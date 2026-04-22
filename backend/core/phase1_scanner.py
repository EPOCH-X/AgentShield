"""
[R2 담당 / R7 연동 반영] Phase 1 — 공격 프롬프트 대량 스캔

세부기획서 섹션 2, 기능별 파이프라인 섹션 1 참조.
공격 프롬프트를 타겟에 비동기 전송하고 Judge로 1차 판정한다.

데이터 소스 우선순위:
    1. 공용 DB attack_patterns
    2. 로컬 attack pattern JSON fallback
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from pathlib import Path
from sqlalchemy import select
from typing import Optional, Callable, Any

import httpx

from backend.config import settings
from backend.database import async_session
from backend.core.judge import rule_based_judge, full_judge
from backend.core.target_adapter import TargetAdapterConfig, send_messages_to_target
from backend.models.attack_pattern import AttackPattern

logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "attack_patterns"


# ── 데이터 로딩 ────────────────────────────────────────────────

def _load_attacks_from_file(category: Optional[str] = None) -> list[dict]:
    """로컬 JSON 파일에서 공격 패턴 로드 (colla_v1 + generated_*.json 병합)

    각 시드에 고유 seed_id(UUID)를 발급하여 Phase 2에서 DPO 쌍 매칭에 활용한다.
    """
    attacks = []
    for json_file in sorted(DATA_DIR.glob("*.json")):
        if json_file.name == "README.md":
            continue
        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        # prompt_text 키가 있는 항목만 (attack pattern 형식)
        valid = [a for a in data if "prompt_text" in a and "category" in a]
        for a in valid:
            a["seed_id"] = str(uuid.uuid4())
        attacks.extend(valid)
    if category:
        attacks = [a for a in attacks if a["category"] == category]
    return attacks


async def _load_attacks_from_db(category: Optional[str] = None) -> list[dict]:
    async with async_session() as session:
        query = select(AttackPattern).where(
            AttackPattern.category.in_(["LLM01", "LLM02", "LLM06", "LLM07"])
        )
        if category:
            query = query.where(AttackPattern.category == category)
        rows = (await session.scalars(query.order_by(AttackPattern.id.asc()))).all()

    attacks = []
    for row in rows:
        attacks.append(
            {
                "attack_pattern_id": row.id,
                "seed_id": f"db-{row.id}",
                "prompt_text": row.prompt_text,
                "category": row.category,
                "subcategory": row.subcategory or "",
                "severity": row.severity,
                "source": row.source,
                "language": row.language,
            }
        )
    return attacks


async def _load_attacks(category: Optional[str] = None) -> list[dict]:
    db_attacks = await _load_attacks_from_db(category)
    if db_attacks:
        return db_attacks
    if settings.PHASE1_ALLOW_FILE_FALLBACK:
        logger.warning("attack_patterns DB가 비어 있어 파일 fallback을 사용합니다.")
        return _load_attacks_from_file(category)
    raise RuntimeError(
        "attack_patterns DB가 비어 있습니다. 현재 설정에서는 파일 fallback을 허용하지 않습니다. "
        "네가 관리하는 공격 데이터만 쓰려면 DB를 먼저 채우세요."
    )


# ── Phase 1 메인 ─────────────────────────────────────────────────

async def run_phase1(
    session_id: str,
    target_url: str,
    category: Optional[str] = None,
    send_fn: Optional[Callable] = None,
    llm: Any = None,
    target_config: Optional[dict[str, Any]] = None,
) -> dict:
    """Phase 1 — 공격 프롬프트 대량 스캔

    1. 공격 패턴 로드 (DB 우선, 파일 fallback)
    2. send_fn(client, prompt_text) 또는 기본 HTTP POST로 타겟 호출
    3. Judge 판정 (llm 있으면 full_judge, 없으면 rule_based_judge)
    4. safe / vulnerable 분류 반환

    Args:
        session_id: 세션 ID
        target_url: 타겟 API URL
        category: 특정 카테고리만 필터 (None이면 전체)
        send_fn: async (client, prompt_text) -> str  커스텀 타겟 호출 함수
                 None이면 기획서 규격 POST {"messages": [...]} 사용
        llm: LLM Judge 인스턴스 (None이면 규칙만 사용)

    Returns:
        {"safe_attacks": [...], "vulnerable_attacks": [...],
         "ambiguous_attacks": [...], "total_scanned": int}
    """
    attacks = await _load_attacks(category)
    safe_attacks: list[dict] = []
    vulnerable_attacks: list[dict] = []
    ambiguous_attacks: list[dict] = []
    error_attacks: list[dict] = []
    total = len(attacks)
    done_count = 0

    sem = asyncio.Semaphore(settings.PHASE1_CONCURRENCY)

    adapter_config = TargetAdapterConfig.from_input(
        target_url=target_url,
        api_key=(target_config or {}).get("api_key"),
        provider=(target_config or {}).get("provider"),
        model=(target_config or {}).get("model"),
    )

    async def scan_one(attack: dict) -> None:
        nonlocal done_count
        async with sem:
            prompt_text = attack["prompt_text"]
            cat = attack["category"]
            try:
                async with httpx.AsyncClient(timeout=settings.PHASE1_TIMEOUT) as client:
                    if send_fn:
                        target_response = await send_fn(client, prompt_text)
                    else:
                        target_response = await send_messages_to_target(
                            client,
                            adapter_config,
                            messages=[{"role": "user", "content": prompt_text}],
                        )
            except (httpx.HTTPError, Exception) as e:
                logger.warning(f"타겟 요청 실패 [{cat}]: {e}")
                target_response = "[ERROR]"

            # 타겟 응답 실패 시 judge 호출 없이 error 분류
            if target_response in ("[ERROR]", ""):
                error_entry = {
                    "attack_pattern_id": attack.get("attack_pattern_id"),
                    "seed_id": attack.get("seed_id", ""),
                    "category": cat,
                    "subcategory": attack.get("subcategory", ""),
                    "attack_prompt": prompt_text,
                    "target_response": target_response,
                    "judgment": "error",
                    "severity": None,
                    "detail": "Target request failed (timeout or network error)",
                }
                error_attacks.append(error_entry)
                done_count += 1
                print(f"  [{done_count}/{total}] {cat}/{attack.get('subcategory', '?')} → ❌ error", flush=True)
                return

            verdict = await full_judge(cat, prompt_text, target_response, llm)

            entry = {
                "attack_pattern_id": attack.get("attack_pattern_id"),
                "seed_id": attack.get("seed_id", ""),
                "category": cat,
                "subcategory": attack.get("subcategory", ""),
                "attack_prompt": prompt_text,
                "target_response": target_response,
                "judgment": verdict["judgment"],
                "severity": verdict.get("severity"),
                "detail": verdict.get("detail", ""),
                "judge_layer": verdict.get("layer", 1),
                "judgment_confidence": verdict.get("confidence"),
                "manual_review_needed": verdict.get("manual_review", False),
            }

            if verdict["judgment"] == "vulnerable":
                vulnerable_attacks.append(entry)
            elif verdict["judgment"] == "safe":
                safe_attacks.append(entry)
            else:
                # ambiguous → Phase 2에서 다시 시도
                safe_attacks.append(entry)
                ambiguous_attacks.append(entry)

            done_count += 1
            icon = "🔴" if verdict["judgment"] == "vulnerable" else "🟢"
            print(f"  [{done_count}/{total}] {cat}/{attack.get('subcategory', '?')} → {icon} {verdict['judgment']}", flush=True)

    # Phase 1 원본 결과는 graph/scan API 계층에서 test_results 적재까지 이어진다.

    tasks = [scan_one(a) for a in attacks]
    await asyncio.gather(*tasks)

    logger.info(
        f"Phase 1 완료: scanned={len(attacks)}, "
        f"vulnerable={len(vulnerable_attacks)}, "
        f"safe={len(safe_attacks)}, "
        f"ambiguous={len(ambiguous_attacks)}, "
        f"error={len(error_attacks)}"
    )

    return {
        "safe_attacks": safe_attacks,
        "vulnerable_attacks": vulnerable_attacks,
        "ambiguous_attacks": ambiguous_attacks,
        "error_attacks": error_attacks,
        "total_scanned": len(attacks),
    }

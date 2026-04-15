"""
Phase 1 — 공격 프롬프트 대량 스캔

세부기획서 섹션 2, 기능별 파이프라인 섹션 1 참조.
공격 프롬프트를 타겟에 비동기 전송 → 규칙(Layer 1) 판정.

데이터 소스:
  - 현재: colla_v1.json 로컬 파일 로드 (DB 미연결 상태)
  - TODO: [R7] DB 연결 후 → _load_attacks_from_db() 전환
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Optional, Callable, Any

import httpx

from backend.config import settings
from backend.core.judge import rule_based_judge

logger = logging.getLogger(__name__)

DATA_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "attack_patterns" / "colla_v1.json"


# ── 데이터 로딩 (나중에 DB 전환 시 이 부분만 교체) ────────────────

def _load_attacks_from_file(category: Optional[str] = None) -> list[dict]:
    """로컬 JSON 파일에서 공격 패턴 로드 (현재 사용)"""
    with open(DATA_PATH, "r", encoding="utf-8") as f:
        attacks = json.load(f)
    if category:
        attacks = [a for a in attacks if a["category"] == category]
    return attacks


# TODO: [R7] DB 연결 후 아래 함수로 교체
# async def _load_attacks_from_db(db, category: str | None = None) -> list[dict]:
#     """PostgreSQL attack_patterns 테이블에서 로드"""
#     from backend.models.attack_pattern import AttackPattern
#     query = db.query(AttackPattern).filter(
#         AttackPattern.category.in_(["LLM01", "LLM02", "LLM06", "LLM07"])
#     )
#     if category:
#         query = query.filter(AttackPattern.category == category)
#     rows = query.all()
#     return [{"prompt_text": r.prompt_text, "category": r.category,
#              "subcategory": r.subcategory} for r in rows]


# ── Phase 1 메인 ─────────────────────────────────────────────────

async def run_phase1(
    session_id: str,
    target_url: str,
    category: Optional[str] = None,
    send_fn: Optional[Callable] = None,
) -> dict:
    """Phase 1 — 공격 프롬프트 대량 스캔

    1. 공격 패턴 로드 (현재: colla_v1.json / TODO: DB)
    2. send_fn(client, prompt_text) 또는 기본 HTTP POST로 타겟 호출
    3. Judge Layer 1 (규칙) 판정
    4. safe / vulnerable 분류 반환

    Args:
        session_id: 세션 ID
        target_url: 타겟 API URL
        category: 특정 카테고리만 필터 (None이면 전체)
        send_fn: async (client, prompt_text) -> str  커스텀 타겟 호출 함수
                 None이면 기획서 규격 POST {"messages": [...]} 사용

    Returns:
        {"safe_attacks": [...], "vulnerable_attacks": [...],
         "ambiguous_attacks": [...], "total_scanned": int}
    """
    attacks = _load_attacks_from_file(category)
    safe_attacks: list[dict] = []
    vulnerable_attacks: list[dict] = []
    ambiguous_attacks: list[dict] = []
    error_attacks: list[dict] = []

    sem = asyncio.Semaphore(settings.PHASE1_CONCURRENCY)

    async def scan_one(attack: dict) -> None:
        async with sem:
            prompt_text = attack["prompt_text"]
            cat = attack["category"]
            try:
                async with httpx.AsyncClient(timeout=settings.PHASE1_TIMEOUT) as client:
                    if send_fn:
                        target_response = await send_fn(client, prompt_text)
                    else:
                        # 기획서 규격: POST {"messages": [{"role":"user","content":...}]}
                        resp = await client.post(
                            target_url,
                            json={"messages": [{"role": "user", "content": prompt_text}]},
                        )
                        target_response = resp.json().get("content", resp.text)
            except (httpx.HTTPError, Exception) as e:
                logger.warning(f"타겟 요청 실패 [{cat}]: {e}")
                target_response = "[ERROR]"

            # 타겟 응답 실패 시 judge 호출 없이 error 분류
            if target_response in ("[ERROR]", ""):
                error_entry = {
                    "category": cat,
                    "subcategory": attack.get("subcategory", ""),
                    "attack_prompt": prompt_text,
                    "target_response": target_response,
                    "judgment": "error",
                    "severity": None,
                    "detail": "Target request failed (timeout or network error)",
                }
                error_attacks.append(error_entry)
                return

            verdict = rule_based_judge(cat, prompt_text, target_response)

            entry = {
                "category": cat,
                "subcategory": attack.get("subcategory", ""),
                "attack_prompt": prompt_text,
                "target_response": target_response,
                "judgment": verdict["judgment"],
                "severity": verdict.get("severity"),
                "detail": verdict.get("detail", ""),
            }

            if verdict["judgment"] == "vulnerable":
                vulnerable_attacks.append(entry)
            elif verdict["judgment"] == "safe":
                safe_attacks.append(entry)
            else:
                # ambiguous → Phase 2에서 다시 시도
                safe_attacks.append(entry)
                ambiguous_attacks.append(entry)

    # TODO: [R7] DB 연결 후 → test_results 테이블에 결과 INSERT
    # 현재는 반환값만 Phase 2에 전달

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

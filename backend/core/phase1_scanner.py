# backend/core/phase1_scanner.py
"""
Phase 1 Scanner — 공격 패턴 실행 및 판정

[수정 사항]
- _load_attack_patterns_from_file():
    파일 경로 data/attack_patterns.json → data/attack_patterns/**/*.json 로 수정
    JSON 키 매핑: prompt_text → attack_prompt, vector_id → id (fallback)
- _load_attack_patterns() DB 경로:
    ORM 필드명 불일치(prompt_text vs attack_prompt) getattr로 양쪽 허용
    빈 결과 시 warning → error 레벨로 상향
- run_phase1() 내부에서 _load_attacks를 _self._load_attacks로 호출:
    smoke 스크립트의 monkey-patch가 반드시 반영되도록 모듈 속성 경유
- asyncio.Semaphore(2): _execute_attack_pattern 내부에서 직접 획득
- send_fn 파라미터: smoke 스크립트가 Ollama 형식 변환 함수를 주입
- _load_attacks 별칭: smoke 스크립트의 monkey-patch 대상
- Exponential Backoff: 실패 attempt 1→2초, 2→4초, 3→8초
- error_source / failure_mode 필드: smoke 스크립트 에러 출력용
"""

import asyncio
import logging
import uuid
from typing import Any, Dict, List, Optional

import httpx

from backend.config import settings
from backend.core.judge import full_judge
from backend.core.target_adapter import TargetAdapterConfig, send_messages_to_target
from backend.database import async_session
from backend.models.test_result import TestResult

logger = logging.getLogger(__name__)

MAX_TARGET_RETRIES = 3


def _backoff(attempt: int) -> float:
    """지수 백오프 대기 시간. attempt 1→2초, 2→4초, 3→8초"""
    return float(2 ** attempt)


# ── 진입점 ───────────────────────────────────────────────────────────────────

async def run_phase1(
    session_id: str,
    target_url: str,
    category: str = "ALL",
    max_attacks: int = None,
    target_config: dict = None,
    send_fn=None,
    llm=None,
    on_result=None,
) -> dict:
    """
    Phase 1 실행 — 공격 패턴 전송 → 타겟 응답 수집 → Judge 판정

    llm_security_graph.py 호출 방식:
        run_phase1(session_id, target_url,
                   target_config=..., on_result=phase1_result_callback)
        → category 생략 시 "ALL" 기본값 사용

    smoke 스크립트 호출 방식:
        wrapped_run_phase1(..., send_fn=ollama_send_fn, on_result=_print_result)
        → send_fn으로 Ollama /api/chat 형식 변환 주입

    Parameters
    ----------
    send_fn : optional
        smoke 스크립트가 주입하는 커스텀 HTTP 전송 함수.
        signature: async def send_fn(client: httpx.AsyncClient, prompt: str) -> str
        None이면 target_adapter.send_messages_to_target 사용.
    on_result : optional
        결과 하나가 완료될 때마다 호출되는 콜백.
        graph의 phase1_result_callback 또는 smoke의 _print_result가 전달됨.
    """
    adapter_config = TargetAdapterConfig.from_input(
        target_url=target_url,
        api_key=None,
        provider=None,
        model=None,
    )

    # ★ 반드시 모듈 속성(_self._load_attacks)으로 호출해야
    #   smoke 스크립트의 monkey-patch(_patched_phase1_loader)가 반영됨.
    #   직접 _load_attack_patterns(...)를 호출하면 patch가 무시됨.
    import backend.core.phase1_scanner as _self
    attack_patterns = await _self._load_attacks(category, max_attacks)

    if not attack_patterns:
        logger.error(
            f"[Phase1] ❌ 공격 패턴 로드 실패 — category={category}, "
            f"max_attacks={max_attacks}. "
            f"data/attack_patterns/ 폴더 또는 DB를 확인하세요."
        )
        return {
            "total_scanned": 0,
            "vulnerable_count": 0,
            "safe_count": 0,
            "ambiguous_count": 0,
            "error_count": 0,
            "results": [],
            "vulnerable_attacks": [],
            "safe_attacks": [],
        }

    logger.info(f"[Phase1] Loaded {len(attack_patterns)} attack patterns")

    # 단일 GPU 직렬화: gather 대신 순차 for 루프로 패턴 1개씩 완전 처리
    results = []
    for i, pattern in enumerate(attack_patterns):
        logger.debug(f"[Phase1] Executing pattern {i + 1}/{len(attack_patterns)}: {pattern.get('category')}/{pattern.get('subcategory')}")
        try:
            result = await _execute_attack_pattern(
                session_id=session_id,
                pattern=pattern,
                adapter_config=adapter_config,
                send_fn=send_fn,
                on_result=on_result,
            )
            results.append(result)
        except Exception as e:
            logger.error(f"[Phase1] Pattern {i + 1} unhandled exception: {e}")

    vulnerable_count = sum(1 for r in results if r.get("judgment") == "vulnerable")
    safe_count       = sum(1 for r in results if r.get("judgment") == "safe")
    ambiguous_count  = sum(1 for r in results if r.get("judgment") == "ambiguous")
    error_count      = sum(1 for r in results if r.get("judgment") == "error")

    logger.info(
        f"[Phase1] Done: total={len(results)}, vulnerable={vulnerable_count}, "
        f"safe={safe_count}, ambiguous={ambiguous_count}, error={error_count}"
    )

    return {
        "total_scanned": len(results),
        "vulnerable_count": vulnerable_count,
        "safe_count": safe_count,
        "ambiguous_count": ambiguous_count,
        "error_count": error_count,
        "results": results,
        # smoke 스크립트 _short_summary 호환 필드
        "vulnerable_attacks": [r for r in results if r.get("judgment") == "vulnerable"],
        "safe_attacks":       [r for r in results if r.get("judgment") == "safe"],
    }


# ── 공격 패턴 로드 ────────────────────────────────────────────────────────────

async def _load_attack_patterns(
    category: str = "ALL", max_attacks: int = None
) -> List[Dict[str, Any]]:
    """공격 패턴 로드 (DB 우선, 파일 fallback)"""
    try:
        from sqlalchemy import select as sa_select
        async with async_session() as db:
            from backend.models.attack_pattern import AttackPattern as AP
            stmt = sa_select(AP)
            if category and category != "ALL":
                stmt = stmt.where(AP.category == category)
            if max_attacks:
                stmt = stmt.limit(max_attacks)
            rows = (await db.execute(stmt)).scalars().all()
            if not rows:
                logger.error(
                    "[Phase1] ❌ DB에 AttackPattern 데이터 없음 → file fallback으로 전환"
                )
                raise ValueError("DB가 비어 있음")
            return [
                {
                    "id": row.id,
                    "category": getattr(row, "category", ""),
                    "subcategory": getattr(row, "subcategory", ""),
                    "attack_prompt": getattr(
                        row, "attack_prompt", getattr(row, "prompt_text", "")
                    ),
                    "target_response": getattr(row, "target_response", ""),
                    "seed_id": str(getattr(row, "seed_id", row.id) or row.id),
                    "severity": getattr(row, "severity", ""),
                }
                for row in rows
            ]
    except Exception as e:
        logger.warning(f"[Phase1] DB load failed → file fallback: {e}")
        return await _load_attack_patterns_from_file(category, max_attacks)


# ★ smoke 스크립트(_patched_phase1_loader)가 monkey-patch하는 함수명.
#   run_phase1()은 _self._load_attacks로 호출하므로 patch가 반영됨.
_load_attacks = _load_attack_patterns


async def _load_attack_patterns_from_file(
    category: str, max_attacks: int = None
) -> List[Dict[str, Any]]:
    """공격 패턴 파일 로드 (fallback)"""
    import json
    from pathlib import Path

    base = Path(__file__).resolve().parents[2] / "data"
    candidates = sorted(base.glob("attack_patterns/**/*.json"))
    if not candidates:
        single = base / "attack_patterns.json"
        candidates = [single] if single.exists() else []
    if not candidates:
        logger.error(
            f"[Phase1] ❌ 공격 패턴 파일을 찾을 수 없음. "
            f"확인 경로: {base}/attack_patterns/ 또는 {base}/attack_patterns.json"
        )
        return []

    patterns = []
    for file_path in candidates:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            raw_list = data if isinstance(data, list) else data.get("patterns", [data])
            for item in raw_list:
                patterns.append({
                    "id": item.get("id", item.get("vector_id", item.get("attack_pattern_id", ""))),
                    "category": item.get("category", ""),
                    "subcategory": item.get("subcategory", ""),
                    "attack_prompt": item.get("attack_prompt", item.get("prompt_text", "")),
                    "target_response": item.get("target_response", ""),
                    "seed_id": item.get("seed_id", str(item.get("id", ""))),
                    "severity": item.get("severity", ""),
                })
        except Exception as e:
            logger.error(f"[Phase1] 파일 로드 실패: {file_path} — {e}")

    before = len(patterns)
    patterns = [p for p in patterns if p.get("attack_prompt")]
    if before != len(patterns):
        logger.warning(f"[Phase1] attack_prompt 없는 항목 {before - len(patterns)}개 제거")

    if category and category != "ALL":
        patterns = [p for p in patterns if p.get("category") == category]
    if max_attacks:
        patterns = patterns[:max_attacks]

    logger.info(
        f"[Phase1] 파일에서 {len(patterns)}개 패턴 로드 완료 "
        f"(경로: {[str(c) for c in candidates]})"
    )
    return patterns


# ── 단일 패턴 실행 ────────────────────────────────────────────────────────────

async def _execute_attack_pattern(
    session_id: str,
    pattern: Dict[str, Any],
    adapter_config: TargetAdapterConfig,
    send_fn=None,
    on_result=None,
) -> Dict[str, Any]:
    """
    단일 공격 패턴 실행.
    흐름: Semaphore 획득 → 타겟 호출(재시도) → Judge 판정 → DB 저장 → 반환
    """
    category          = pattern.get("category", "LLM01")
    subcategory       = pattern.get("subcategory", "")
    attack_prompt     = pattern.get("attack_prompt", "")
    attack_pattern_id = pattern.get("id", "")
    seed_id           = pattern.get("seed_id", "")

    # run_phase1의 for 루프가 직렬화를 보장 — 여기서 별도 Semaphore 불필요
    target_response, error_reason = await _call_target_with_retry(
        adapter_config=adapter_config,
        attack_prompt=attack_prompt,
        send_fn=send_fn,
    )

    if not target_response:
        logger.error(
            f"❌ [Target LLM] category={category}/{subcategory} "
            f"resp_len=0 reason={error_reason}"
        )
        entry = _make_error_entry(
            session_id=session_id,
            category=category,
            subcategory=subcategory,
            attack_pattern_id=attack_pattern_id,
            seed_id=seed_id,
            attack_prompt=attack_prompt,
            source="Target LLM",
            reason=error_reason or "unknown",
        )
        if on_result:
            on_result(entry)
        return entry

    logger.debug(f"[Phase1] Target OK: category={category}, resp_len={len(target_response)}")

    try:
        verdict = await full_judge(category, attack_prompt, target_response)
    except Exception as e:
        logger.error(
            f"❌ [Auditor] category={category}/{subcategory} "
            f"error={e.__class__.__name__}: {e}"
        )
        verdict = {
            "judgment": "error",
            "layer": 2,
            "confidence": 0.0,
            "severity": None,
            "detail": f"Judgment failed: {e.__class__.__name__}",
        }

    entry = {
        "phase": 1,
        "category": category,
        "subcategory": subcategory,
        "attack_pattern_id": attack_pattern_id,
        "seed_id": seed_id,
        "attack_prompt": attack_prompt,
        "target_response": target_response,
        "judgment": verdict["judgment"],
        "judgment_layer": verdict.get("layer"),
        "judgment_confidence": verdict.get("confidence"),
        "severity": verdict.get("severity"),
        "manual_review_needed": verdict.get("manual_review", False),
        "detail": verdict.get("detail", ""),
        "round": 1,
        "session_id": session_id,
        "failure_mode": verdict.get("failure_mode"),
        "root_cause_label": verdict.get("root_cause_label"),
        "error_source": "Auditor" if verdict["judgment"] == "error" else None,
    }

    try:
        await _persist_result(session_id, entry)
    except Exception as e:
        logger.warning(f"[Phase1] DB save failed: {e}")

    if on_result:
        on_result(entry)

    return entry


# ── 타겟 호출 + 재시도 ────────────────────────────────────────────────────────

async def _call_target_with_retry(
    adapter_config: TargetAdapterConfig,
    attack_prompt: str,
    send_fn=None,
) -> tuple:
    """
    타겟 서버 호출을 MAX_TARGET_RETRIES 회 재시도.

    send_fn이 주입된 경우(smoke 스크립트):
        send_fn(client, attack_prompt) → str
    send_fn이 없는 경우(프로덕션):
        target_adapter.send_messages_to_target 사용
        → 어댑터가 외부 챗봇 API 형식을 자동 변환하므로 직접 httpx 호출 금지

    반환: (response_text, None) 성공 | (None, error_reason) 실패
    """
    error_reason: Optional[str] = None

    async with httpx.AsyncClient(timeout=httpx.Timeout(float(settings.PHASE1_TIMEOUT))) as client:
        for attempt in range(1, MAX_TARGET_RETRIES + 1):
            try:
                if send_fn is not None:
                    response = await send_fn(client, attack_prompt)
                else:
                    response = await send_messages_to_target(
                        client,
                        adapter_config,
                        messages=[{"role": "user", "content": attack_prompt}],
                    )

                if response:
                    return response, None

                error_reason = "empty_response"
                logger.warning(
                    f"[Target LLM] empty response "
                    f"(attempt {attempt}/{MAX_TARGET_RETRIES})"
                )

            except httpx.TimeoutException:
                error_reason = "timeout"
                logger.warning(
                    f"[Target LLM] timeout "
                    f"(attempt {attempt}/{MAX_TARGET_RETRIES})"
                )
            except httpx.ConnectError:
                error_reason = "connection_refused"
                logger.warning(
                    f"[Target LLM] connection refused "
                    f"(attempt {attempt}/{MAX_TARGET_RETRIES})"
                )
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 502:
                    try:
                        body = e.response.json()
                        error_reason = body.get("error", "http_502")
                    except Exception:
                        error_reason = "http_502"
                else:
                    error_reason = f"http_{e.response.status_code}"
                logger.warning(
                    f"[Target LLM] HTTP {e.response.status_code} ({error_reason}) "
                    f"(attempt {attempt}/{MAX_TARGET_RETRIES})"
                )
            except Exception as e:
                error_reason = f"unexpected_{e.__class__.__name__}"
                logger.warning(
                    f"[Target LLM] unexpected error {e.__class__.__name__} "
                    f"(attempt {attempt}/{MAX_TARGET_RETRIES}): {e}"
                )

            if attempt < MAX_TARGET_RETRIES:
                wait = _backoff(attempt)
                logger.warning(
                    f"[Target LLM] 재시도 {attempt}/{MAX_TARGET_RETRIES}, "
                    f"{wait:.0f}초 후 재시도..."
                )
                await asyncio.sleep(wait)

    return None, error_reason


# ── 헬퍼 ─────────────────────────────────────────────────────────────────────

def _make_error_entry(
    session_id: str,
    category: str,
    subcategory: str,
    attack_pattern_id: Any,
    seed_id: str,
    attack_prompt: str,
    source: str,
    reason: str,
) -> Dict[str, Any]:
    return {
        "phase": 1,
        "category": category,
        "subcategory": subcategory,
        "attack_pattern_id": attack_pattern_id,
        "seed_id": seed_id,
        "attack_prompt": attack_prompt,
        "target_response": "",
        "judgment": "error",
        "judgment_layer": 0,
        "judgment_confidence": None,
        "severity": None,
        "manual_review_needed": True,
        "detail": f"{source} failed: {reason}",
        "round": 1,
        "session_id": session_id,
        "error_source": source,
        "failure_mode": reason,
        "root_cause_label": None,
    }


async def _persist_result(session_id: str, result_entry: Dict[str, Any]) -> Optional[int]:
    try:
        # attack_pattern_id: DB는 INTEGER, 파일 폴백 ID는 UUID 문자열 → None으로 변환
        raw_id = result_entry.get("attack_pattern_id")
        try:
            attack_pattern_id: Optional[int] = int(raw_id) if raw_id is not None else None
        except (ValueError, TypeError):
            attack_pattern_id = None

        async with async_session() as db:
            db_row = TestResult(
                session_id=uuid.UUID(session_id) if isinstance(session_id, str) else session_id,
                phase=result_entry.get("phase", 1),
                attack_pattern_id=attack_pattern_id,
                seed_id=result_entry.get("seed_id", ""),
                round=result_entry.get("round", 1),
                attack_prompt=result_entry.get("attack_prompt"),
                target_response=result_entry.get("target_response"),
                judgment=result_entry.get("judgment"),
                judgment_layer=result_entry.get("judgment_layer"),
                judgment_confidence=result_entry.get("judgment_confidence"),
                manual_review_needed=result_entry.get("manual_review_needed", False),
                severity=result_entry.get("severity"),
                category=result_entry.get("category"),
                subcategory=result_entry.get("subcategory"),
                detail=result_entry.get("detail", ""),
                mitre_technique_id=result_entry.get("mitre_technique_id", ""),
                # failure_mode, root_cause_label: TestResult 스키마 미포함 → entry dict에만 보존
            )
            db.add(db_row)
            await db.flush()
            row_id = db_row.id
            await db.commit()
            return row_id
    except Exception as e:
        logger.warning(f"[Phase1] DB 저장 실패: {e}")
        return None
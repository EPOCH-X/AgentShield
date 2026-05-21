"""
P4 — LLM 의도 검토.

Judge Agent (AgentShieldLLM role='judge')를 재사용한다. FastAPI route 안에서 sync 흐름으로
호출되므로 nested asyncio.run 회피를 위해 worker thread에서 실행.

JSON 파싱 실패 또는 LLM 호출 실패 시 'ambiguous'로 폴백 — 모니터링 응답 흐름은 끊기지 않게.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import json
import logging
import re
from typing import Optional

from monitoring_proxy.schemas import IntentReviewResult

logger = logging.getLogger(__name__)


_INTENT_PROMPT_TEMPLATE = """\
당신은 기업 보안 모니터링 시스템의 의도 판정 심사관입니다.
직원이 사내 AI 챗봇에 보낸 메시지가 기업 정책을 위반할 의도가 있는지 평가하세요.

[직원 ID] {employee_id}
[규칙 기반 사전 검출]
{rule_reasons}

[직원 메시지]
\"\"\"
{message}
\"\"\"

다음 JSON 형식으로만 답변하세요 (다른 설명·코드블록 금지):
{{
  "judgment": "normal" | "violation" | "ambiguous",
  "confidence": 0.0~1.0,
  "reason": "한 문장으로 판정 근거"
}}
"""


def get_default_intent_review_llm_client():
    """기본 LLM 클라이언트 = AgentShieldLLM 인스턴스. 호출 시점에 lazy 생성."""
    try:
        from backend.agents.llm_client import AgentShieldLLM
        return AgentShieldLLM()
    except Exception:
        logger.exception("[monitoring_proxy] AgentShieldLLM 초기화 실패 — 의도 검토 비활성화")
        return None


def _run_async_in_thread(coro):
    """이미 event loop이 도는 컨텍스트(FastAPI route)에서도 안전하게 async 코루틴 실행."""
    try:
        asyncio.get_running_loop()
        # 실행 중 loop가 있음 → worker thread에서 새 loop으로 실행
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(lambda: asyncio.run(coro)).result()
    except RuntimeError:
        # 실행 중 loop 없음 → 직접 실행
        return asyncio.run(coro)


def _parse_intent_json(raw: str) -> Optional[dict]:
    """LLM 응답에서 JSON 블록 추출."""
    text = (raw or "").strip()
    # ```json ... ``` 블록 제거
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    # 첫 번째 { ... } 추출
    m = re.search(r"\{[\s\S]*\}", text)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except json.JSONDecodeError:
        return None


def review_request_intent(
    *,
    message: str,
    employee_context: dict,
    rule_reasons: list[str],
    llm_client=None,
    role: str = "base",
) -> IntentReviewResult:
    if llm_client is None:
        return IntentReviewResult(
            judgment="ambiguous",
            confidence=0.5,
            reason="LLM client unavailable; defaulting to ambiguous",
        )

    prompt = _INTENT_PROMPT_TEMPLATE.format(
        employee_id=employee_context.get("employee_id", "unknown"),
        rule_reasons="\n".join(f"- {r}" for r in (rule_reasons or [])) or "- (없음)",
        message=message,
    )

    try:
        raw = _run_async_in_thread(llm_client.generate(prompt, role="judge", max_tokens=256))
    except Exception:
        logger.exception("[monitoring_proxy] intent LLM 호출 실패 — ambiguous 폴백")
        return IntentReviewResult(
            judgment="ambiguous",
            confidence=0.5,
            reason="LLM call failed; defaulting to ambiguous",
        )

    parsed = _parse_intent_json(str(raw or ""))
    if not parsed:
        return IntentReviewResult(
            judgment="ambiguous",
            confidence=0.5,
            reason="LLM response not JSON-parseable; defaulting to ambiguous",
        )

    judgment = str(parsed.get("judgment") or "ambiguous").lower()
    if judgment not in {"normal", "violation", "ambiguous"}:
        judgment = "ambiguous"
    try:
        confidence = float(parsed.get("confidence") or 0.5)
    except (TypeError, ValueError):
        confidence = 0.5
    confidence = max(0.0, min(1.0, confidence))
    reason = str(parsed.get("reason") or "no reason provided")[:500]

    return IntentReviewResult(judgment=judgment, confidence=confidence, reason=reason)

"""
[R3] Defense Proxy — MVP

Layer 1: 입력 필터
Layer 2: 시스템 프롬프트 패치 주입
Layer 3: 타겟 호출
Layer 4: 출력 필터
(Layer 5 Execution Guard는 다음 단계)
"""

from __future__ import annotations

import re
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="AgentShield Defense Proxy")


# ------------------------------------------------------------------
# Pydantic 모델
# ------------------------------------------------------------------
class DefenseRules(BaseModel):
    # phase3에서 만든 defense_code(JSON)을 proxy-friendly 형태로 풀어 담는 구조
    # MVP는 regex 기반으로 단순화
    input_filters: list[str] = Field(default_factory=list)
    output_filters: list[str] = Field(default_factory=list)
    system_prompt_patch: str = ""
    # 다음 단계용
    execution_guard: dict[str, Any] | None = None


class ProxyChatRequest(BaseModel):
    target_url: str
    messages: list[dict[str, str]]


# 세션별 방어 규칙 저장소 (MVP: in-memory)
DEFENSE_STORE: dict[str, DefenseRules] = {}


# ------------------------------------------------------------------
# [R3 산출물] 유틸
# ------------------------------------------------------------------
def _apply_input_filters(text: str, patterns: list[str]) -> bool:
    """차단 여부만 반환 (True=blocked)."""
    for p in patterns:
        try:
            if re.search(p, text, re.IGNORECASE):
                return True
        except re.error:
            # 잘못된 regex는 무시 (실서비스에서는 로그 남기기)
            continue
    return False


def _inject_system_patch(messages: list[dict[str, str]], patch: str) -> list[dict[str, str]]:
    if not patch.strip():
        return messages

    copied = [dict(m) for m in messages]
    for msg in copied:
        if msg.get("role") == "system":
            msg["content"] = f'{msg.get("content", "")}\n{patch}'.strip()
            return copied

    # system 메시지가 없으면 맨 앞 삽입
    return [{"role": "system", "content": patch}] + copied


def _apply_output_filters(text: str, patterns: list[str]) -> str:
    result = text
    for p in patterns:
        try:
            result = re.sub(p, "[REDACTED]", result, flags=re.IGNORECASE)
        except re.error:
            continue
    return result


# ------------------------------------------------------------------
# 엔드포인트
# ------------------------------------------------------------------
@app.post("/proxy/{session_id}/register")
async def register_rules(session_id: str, rules: DefenseRules) -> dict[str, Any]:
    DEFENSE_STORE[session_id] = rules
    return {
        "status": "registered",
        "session_id": session_id,
        "input_filters": len(rules.input_filters),
        "output_filters": len(rules.output_filters),
    }


@app.delete("/proxy/{session_id}/rules")
async def clear_rules(session_id: str) -> dict[str, Any]:
    DEFENSE_STORE.pop(session_id, None)
    return {"status": "cleared", "session_id": session_id}


@app.post("/proxy/{session_id}/chat")
async def proxy_chat(session_id: str, req: ProxyChatRequest) -> dict[str, Any]:
    rules = DEFENSE_STORE.get(session_id)
    if not rules:
        raise HTTPException(status_code=404, detail="No defense rules registered for session")

    if not req.messages:
        raise HTTPException(status_code=400, detail="messages is required")

    user_text = req.messages[-1].get("content", "")

    # Layer 1: 입력 필터
    if _apply_input_filters(user_text, rules.input_filters):
        return {"content": "보안 정책에 의해 요청이 차단되었습니다.", "blocked": True}

    # Layer 2: 시스템 프롬프트 패치
    patched_messages = _inject_system_patch(req.messages, rules.system_prompt_patch)

    # Layer 3: 타겟 호출
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(req.target_url, json={"messages": patched_messages})
            resp.raise_for_status()
            response_json = resp.json()
            response_text = response_json.get("content", "")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Target call failed: {e}")

    # Layer 4: 출력 필터
    filtered_text = _apply_output_filters(response_text, rules.output_filters)

    # Layer 5: execution guard (다음 단계)
    return {"content": filtered_text, "blocked": False}

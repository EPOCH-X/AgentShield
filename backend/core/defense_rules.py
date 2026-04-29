"""
Phase4와 Defense Proxy가 함께 쓰는 방어 규칙 공통 유틸.
"""

from __future__ import annotations

import re
from typing import Any


_META_WORDS = {"action", "reason", "block", "pass", "warn"}
_META_PHRASES = {
    "safe input.",
    "safe request.",
    "no policy violation detected.",
    "input passed security checks.",
}
_REDACT_TOKEN = "[REDACTED]"
_GENERIC_LITERALS = {
    # LLM이 자주 생성하는 일반 단어. 그대로 regex에 올리면 과차단을 유발한다.
    "key",
    "keys",
    "policy",
    "policies",
    "rule",
    "rules",
    "role",
    "roles",
    "function",
    "functions",
    "permission",
    "permissions",
    "restriction",
    "restrictions",
    "extract",
    "translate",
    "convert",
    "replace",
    "modify",
}
_HIGH_RISK_LITERALS = {
    # 짧더라도 차단 가치가 높은 토큰은 예외 허용
    "override",
    "ignore",
    "do not discuss",
    "hidden directive",
    "<tool_call>",
    "system.execute_command",
    "sk-live",
}


def _looks_like_replacement_literal(value: str) -> bool:
    """치환 결과 리터럴([TOKEN]) 형태는 정규식 후보에서 제외한다."""
    # 예: [INTERNAL_ESCALATION_CODE], [ADMIN_TOKEN_MASK]
    return bool(re.fullmatch(r"\[[A-Z0-9_]{3,}\]", value))


def _is_low_signal_literal(value: str) -> bool:
    """과차단 가능성이 높은 약한 문자열은 regex 후보에서 제외한다."""
    lowered = value.strip().lower()
    if not lowered:
        return True
    if lowered in _GENERIC_LITERALS:
        return True

    # regex 메타문자가 전혀 없고 단일 단어인데 너무 짧으면 신호가 약하다.
    has_regex_meta = bool(re.search(r"[\\\[\]\(\)\{\}\|\.\*\+\?\^$]", value))
    is_single_word = bool(re.fullmatch(r"[a-zA-Z0-9_-]+", value))
    if is_single_word and not has_regex_meta:
        if lowered in _HIGH_RISK_LITERALS:
            return False
        if len(lowered) < 7:
            return True
    return False


def _looks_like_reason_sentence(value: str) -> bool:
    """사유 문장(reason text)은 regex 후보에서 제외한다."""
    stripped = value.strip()
    if len(stripped) < 20:
        return False
    # 사람이 읽는 설명문은 proxy regex로 쓰면 오탐/저성능만 유발한다.
    if stripped.endswith(".") and " " in stripped:
        return True
    return False


def _alternation_contains_generic_literal(value: str) -> bool:
    """(a|b|c) 형태에서 generic 토큰이 포함되면 과차단 위험이 높다."""
    m = re.fullmatch(r"\(([^)]+)\)", value.strip())
    if not m:
        return False
    parts = [p.strip().lower() for p in m.group(1).split("|")]
    if len(parts) < 2:
        return False
    return any(p in _GENERIC_LITERALS for p in parts)


def extract_regex_patterns(source: str) -> list[str]:
    """생성된 코드에서 정규식 후보 문자열을 느슨하게 추출한다."""
    if not source:
        return []
    patterns: list[str] = []
    for match in re.finditer(r'''(?:r)?(["'])(.+?)\1''', source, re.DOTALL):
        value = match.group(2).strip()
        if len(value) < 3:
            continue
        if value in _META_WORDS:
            continue
        if value.strip().lower() in _META_PHRASES:
            continue
        # 치환 토큰 리터럴을 regex로 취급하면 문자클래스로 해석되어 과매칭/폭증을 유발한다.
        if _looks_like_replacement_literal(value):
            continue
        if _looks_like_reason_sentence(value):
            continue
        if _alternation_contains_generic_literal(value):
            continue
        if _is_low_signal_literal(value):
            continue
        patterns.append(value)
    return list(dict.fromkeys(patterns))[:30]


def build_proxy_rules(payloads: list[dict[str, Any]]) -> dict[str, Any]:
    """Phase3 payload 목록을 proxy 등록용 규칙 형태로 변환한다."""
    input_patterns: list[str] = []
    output_patterns: list[str] = []
    patches: list[str] = []

    for payload in payloads:
        input_patterns.extend(extract_regex_patterns(str(payload.get("input_filter") or "")))
        output_patterns.extend(extract_regex_patterns(str(payload.get("output_filter") or "")))
        patch = str(payload.get("system_prompt_patch") or "").strip()
        if patch:
            patches.append(patch)

    return {
        "input_filters": list(dict.fromkeys(input_patterns))[:100],
        "output_filters": list(dict.fromkeys(output_patterns))[:100],
        "system_prompt_patch": "\n".join(dict.fromkeys(patches)).strip(),
        "execution_guard": None,
    }


def apply_input_filters(text: str, patterns: list[str]) -> bool:
    """입력이 차단 대상이면 True를 반환한다."""
    for pattern in patterns:
        try:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        except re.error:
            continue
    return False


def inject_system_patch(messages: list[dict[str, str]], patch: str) -> list[dict[str, str]]:
    if not patch.strip():
        return messages
    copied = [dict(m) for m in messages]
    for msg in copied:
        if msg.get("role") == "system":
            msg["content"] = f'{msg.get("content", "")}\n{patch}'.strip()
            return copied
    return [{"role": "system", "content": patch}] + copied


def apply_output_filters(text: str, patterns: list[str]) -> str:
    result = text
    for pattern in patterns:
        try:
            # [REDACTED] 토큰 자체를 다시 치환하는 루프를 차단한다.
            if _REDACT_TOKEN in result and re.search(pattern, _REDACT_TOKEN, re.IGNORECASE):
                continue
            result = re.sub(pattern, "[REDACTED]", result, flags=re.IGNORECASE)
        except re.error:
            continue
    return result

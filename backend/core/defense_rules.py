"""
Phase4와 Defense Proxy가 함께 쓰는 방어 규칙 공통 유틸.
"""

from __future__ import annotations

import re
from typing import Any


def extract_regex_patterns(source: str) -> list[str]:
    """생성된 코드에서 정규식 후보 문자열을 느슨하게 추출한다."""
    if not source:
        return []
    patterns: list[str] = []
    for match in re.finditer(r'''(?:r)?(["'])(.+?)\1''', source, re.DOTALL):
        value = match.group(2).strip()
        if len(value) < 3:
            continue
        if value in {"action", "reason", "block", "pass", "warn"}:
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
            result = re.sub(pattern, "[REDACTED]", result, flags=re.IGNORECASE)
        except re.error:
            continue
    return result

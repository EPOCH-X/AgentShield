"""
Sensitive data masking — **외부 공유 전용**.

[정책]
- AgentShield 내부 데이터(DB / RAG / `data/policy_packages/*.json` / `results/review_exports/*.json`)는
  **항상 원문**으로 보존한다. 우리가 다시 읽고 분석하는 자산이기 때문.
- 마스킹은 다음 두 시점에서만 적용한다:
    1. UI 표시 (dashboard) — 공격 프롬프트 페이로드 보호 (AgentShield 카탈로그)
    2. 외부 배포 산출물 (PDF/외부 공유 ZIP) — 고객사 PII / 시크릿 보호
- 그 외 호출은 자산 손상을 일으키므로 금지.
"""

from __future__ import annotations

import re

_MASK_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Email
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "[EMAIL]"),
    # KR mobile/phone-ish formats
    (re.compile(r"\b(?:\+?82[-\s]?)?0?1[0-9][-\s]?\d{3,4}[-\s]?\d{4}\b"), "[PHONE]"),
    # Common API key patterns
    (re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b"), "[API_KEY]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[API_KEY]"),
    # Resident registration style
    (re.compile(r"\b\d{6}-\d{7}\b"), "[SSN]"),
    # Private IP ranges
    (
        re.compile(
            r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b"
        ),
        "[IP]",
    ),
]


def mask_for_external_share(text: str) -> str:
    """외부 공유 산출물(PDF·외부 ZIP)용 마스킹. 내부 DB/JSON에는 절대 적용 금지."""
    out = text or ""
    for pattern, token in _MASK_PATTERNS:
        out = pattern.sub(token, out)
    return out


# 하위 호환 별칭 — 신규 코드는 mask_for_external_share 사용.
mask_sensitive = mask_for_external_share


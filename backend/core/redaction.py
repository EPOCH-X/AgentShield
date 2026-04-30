"""
Sensitive data masking utilities.
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


def mask_sensitive(text: str) -> str:
    """Mask common sensitive tokens in free text."""
    out = text or ""
    for pattern, token in _MASK_PATTERNS:
        out = pattern.sub(token, out)
    return out


"""[R5] Monitoring 응답 마스킹 서비스."""

import re


_EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+-]{1,2})[A-Za-z0-9._%+-]*(@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
_PHONE_RE = re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?(?:\d{2,4}[-.\s]?){2,3}\d{4}\b")
_TOKEN_RE = re.compile(r"\b(?:ADMIN-[A-Za-z0-9-]+|[A-Za-z0-9]{24,}|sk-[A-Za-z0-9]{16,})\b")


def _mask_email(match: re.Match) -> str:
    return f"{match.group(1)}***{match.group(2)}"


def _mask_phone(match: re.Match) -> str:
    digits = re.sub(r"\D", "", match.group(0))
    if len(digits) < 4:
        return "[REDACTED_PHONE]"
    return f"***-****-{digits[-4:]}"


def mask_response_content(response_text: str) -> str:
    """Apply conservative masking for common PII and token-like strings in monitoring responses."""

    masked = _EMAIL_RE.sub(_mask_email, response_text)
    masked = _PHONE_RE.sub(_mask_phone, masked)
    masked = _TOKEN_RE.sub("[REDACTED_TOKEN]", masked)
    return masked

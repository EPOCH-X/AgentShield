import re

from monitoring_proxy.schemas import PolicyResultSchema


class P1DetectionResult(PolicyResultSchema):
    pass


EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
PHONE_PATTERN = re.compile(
    r"(\+82[- ]?\d{1,2}[- ]?\d{3,4}[- ]?\d{4})|(01[016789][- ]?\d{3,4}[- ]?\d{4})"
)
API_KEY_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("OpenAI-style API key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("AWS access key", re.compile(r"\bAKIA[A-Z0-9]{16}\b")),
    (
        "generic secret token",
        re.compile(
            r"\b(?:api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{8,}['\"]?\b",
            re.IGNORECASE,
        ),
    ),
)
DB_KEYWORDS: tuple[str, ...] = (
    "create table",
    "select * from",
    "alter table",
    "drop table",
    "insert into",
    "database_url",
    "postgresql://",
    "mysql://",
)
INTERNAL_PATH_KEYWORDS: tuple[str, ...] = (
    "internal.company",
    "intranet",
    "/etc/passwd",
    "/var/www",
    "c:\\users\\",
    "c:\\inetpub\\",
    "/admin",
    "/internal",
)


def detect_confidential_leak(text: str) -> P1DetectionResult:
    normalized = text.strip()
    lowered = normalized.lower()

    if EMAIL_PATTERN.search(normalized):
        return P1DetectionResult(
            blocked=True,
            needs_llm_review=False,
            stage="p1_confidential_scan",
            severity="high",
            reason="email pattern detected in request content",
        )

    if PHONE_PATTERN.search(normalized):
        return P1DetectionResult(
            blocked=True,
            needs_llm_review=False,
            stage="p1_confidential_scan",
            severity="high",
            reason="phone number pattern detected in request content",
        )

    for label, pattern in API_KEY_PATTERNS:
        if pattern.search(normalized):
            return P1DetectionResult(
                blocked=True,
                needs_llm_review=False,
                stage="p1_confidential_scan",
                severity="high",
                reason=f"{label} detected in request content",
            )

    for keyword in DB_KEYWORDS:
        if keyword in lowered:
            return P1DetectionResult(
                blocked=False,
                needs_llm_review=True,
                stage="p1_confidential_scan",
                severity="medium",
                reason=f"database-sensitive keyword detected: {keyword}",
            )

    for keyword in INTERNAL_PATH_KEYWORDS:
        if keyword in lowered:
            return P1DetectionResult(
                blocked=False,
                needs_llm_review=True,
                stage="p1_confidential_scan",
                severity="medium",
                reason=f"internal url/path keyword detected: {keyword}",
            )

    return P1DetectionResult(
        blocked=False,
        needs_llm_review=False,
        stage="p1_confidential_scan",
        severity=None,
        reason=None,
    )

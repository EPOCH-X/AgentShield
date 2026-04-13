"""
[R5] Monitoring Proxy — 직원 AI 사용 모니터링

기능별 파이프라인 섹션 9, 세부기획서 섹션 7 참조.
P1 기밀유출 → P2 부적절사용 → P3 Rate Limit → Forward → 출력 스캔 → 로그 → 제재
"""

from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
import re
from typing import Literal

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field, HttpUrl


class ChatMessage(BaseModel):
    """OpenAI-style message payload for the monitoring skeleton."""

    role: str = Field(..., min_length=1)
    content: str = Field(..., min_length=1)


class MonitorChatRequest(BaseModel):
    """Minimal request contract for the monitoring proxy skeleton."""

    model_config = ConfigDict(extra="allow")

    messages: list[ChatMessage] = Field(..., min_length=1)
    target_url: HttpUrl | None = None
    employee_id: str | None = None


class MonitorChatResponse(BaseModel):
    """Placeholder response returned by the monitoring proxy skeleton."""

    content: str
    blocked: bool
    stage: Literal[
        "skeleton",
        "p1_confidential_scan",
        "p2_inappropriate_use",
        "p3_rate_limit",
    ]
    severity: Literal["high", "medium", "low"] | None
    reason: str | None
    retry_after_seconds: int | None = None
    limit_type: Literal[
        "hourly",
        "daily",
        "repeated_query",
    ] | None = None
    target_url: str | None = None
    message_count: int


class HealthResponse(BaseModel):
    status: Literal["ok"]
    service: Literal["monitoring_proxy"]
    stage: Literal["skeleton"]


class P1DetectionResult(BaseModel):
    blocked: bool
    severity: Literal["high", "medium", "low"] | None
    reason: str | None


class P2DetectionResult(BaseModel):
    category: Literal[
        "normal",
        "p2_toxic_or_harmful",
        "p2_non_work_related",
        "p2_competitor_related",
    ]
    blocked: bool
    severity: Literal["high", "medium", "low"] | None
    reason: str | None


class P3DetectionResult(BaseModel):
    category: Literal[
        "normal",
        "p3_rate_limit_hourly",
        "p3_rate_limit_daily",
        "p3_repeated_query",
    ]
    blocked: bool
    severity: Literal["high", "medium", "low"] | None
    reason: str | None
    retry_after_seconds: int | None = None
    limit_type: Literal[
        "hourly",
        "daily",
        "repeated_query",
    ] | None = None


@dataclass
class EmployeeRateLimitState:
    hourly_requests: deque[datetime] = field(default_factory=deque)
    daily_requests: deque[datetime] = field(default_factory=deque)
    query_timestamps: dict[str, deque[datetime]] = field(default_factory=dict)


EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
PHONE_PATTERN = re.compile(
    r"(\+82[- ]?\d{1,2}[- ]?\d{3,4}[- ]?\d{4})|(01[016789][- ]?\d{3,4}[- ]?\d{4})"
)
API_KEY_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("OpenAI-style API key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("AWS access key", re.compile(r"\bAKIA[A-Z0-9]{16}\b")),
    ("generic secret token", re.compile(r"\b(?:api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{8,}['\"]?\b", re.IGNORECASE)),
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
WORK_RELATED_ALLOWLIST: tuple[str, ...] = (
    "report",
    "summary",
    "meeting",
    "document",
    "analysis",
    "code",
    "debug",
    "api",
    "database",
    "sql",
    "service",
    "backend",
    "frontend",
    "project",
    "work",
    "client",
    "customer",
    "proposal",
    "회의",
    "요약",
    "문서",
    "보고서",
    "분석",
    "코드",
    "디버그",
    "개발",
    "업무",
    "프로젝트",
    "고객",
    "서비스",
    "데이터",
)
NON_WORK_RELATED_KEYWORDS: tuple[str, ...] = (
    "joke",
    "poem",
    "song lyrics",
    "movie recommendation",
    "tv show recommendation",
    "entertainment recommendation",
    "restaurant recommendation",
    "travel itinerary",
    "dating advice",
    "horoscope",
    "game cheat",
    "weekend plan",
    "농담",
    "시 써줘",
    "노래 가사",
    "영화 추천",
    "예능 추천",
    "드라마 추천",
    "맛집 추천",
    "여행 일정",
    "연애 상담",
    "운세",
    "게임 공략",
    "주말 계획",
)
TOXIC_OR_HARMFUL_KEYWORDS: tuple[str, ...] = (
    "make a bomb",
    "build a bomb",
    "how to kill",
    "kill someone",
    "harm someone",
    "hurt someone",
    "murder",
    "suicide note",
    "self-harm",
    "malware",
    "ransomware",
    "phishing email",
    "ddos attack",
    "hate speech",
    "폭탄 만드는 법",
    "사람 죽이는 법",
    "살인 방법",
    "자살 방법",
    "자해 방법",
    "악성코드",
    "랜섬웨어",
    "피싱 메일",
    "디도스 공격",
    "혐오 발언",
    "해치는 방법",
    "해치는 법",
    "누군가를 해치는 방법",
)
COMPETITOR_KEYWORDS: tuple[str, ...] = (
    "competitor",
    "rival company",
    "competitor product",
    "competitor weakness",
    "other company strategy",
    "steal market share",
    "benchmark competitor pricing",
    "삼성",
    "lg",
    "네이버",
    "카카오",
    "쿠팡",
    "경쟁사",
    "타사",
    "제품 약점",
    "제품 비교",
    "시장 점유율 빼앗기",
    "가격 전략",
)
COMPETITOR_INTENT_KEYWORDS: tuple[str, ...] = (
    "collect",
    "gather",
    "investigate",
    "research",
    "analyze",
    "scrape",
    "find out",
    "compare",
    "comparison table",
    "정리해줘",
    "조사해줘",
    "수집해줘",
    "분석해줘",
    "알아와",
    "크롤링",
    "비교표",
    "비교해줘",
    "만들어줘",
)
DEFAULT_EMPLOYEE_ID = "demo-user"
HOURLY_REQUEST_LIMIT = 3
DAILY_REQUEST_LIMIT = 10
REPEATED_QUERY_THRESHOLD = 3
REPEATED_QUERY_WINDOW_SECONDS = 300
HOURLY_WINDOW = timedelta(hours=1)
DAILY_WINDOW = timedelta(days=1)
REPEATED_QUERY_WINDOW = timedelta(seconds=REPEATED_QUERY_WINDOW_SECONDS)
RATE_LIMIT_STATE: dict[str, EmployeeRateLimitState] = {}


def detect_confidential_leak(text: str) -> P1DetectionResult:
    normalized = text.strip()
    lowered = normalized.lower()

    if EMAIL_PATTERN.search(normalized):
        return P1DetectionResult(
            blocked=True,
            severity="high",
            reason="email pattern detected in request content",
        )

    if PHONE_PATTERN.search(normalized):
        return P1DetectionResult(
            blocked=True,
            severity="high",
            reason="phone number pattern detected in request content",
        )

    for label, pattern in API_KEY_PATTERNS:
        if pattern.search(normalized):
            return P1DetectionResult(
                blocked=True,
                severity="high",
                reason=f"{label} detected in request content",
            )

    for keyword in DB_KEYWORDS:
        if keyword in lowered:
            return P1DetectionResult(
                blocked=False,
                severity="medium",
                reason=f"database-sensitive keyword detected: {keyword}",
            )

    for keyword in INTERNAL_PATH_KEYWORDS:
        if keyword in lowered:
            return P1DetectionResult(
                blocked=False,
                severity="medium",
                reason=f"internal url/path keyword detected: {keyword}",
            )

    return P1DetectionResult(
        blocked=False,
        severity=None,
        reason=None,
    )


def detect_inappropriate_use(text: str) -> P2DetectionResult:
    lowered = text.strip().lower()

    for keyword in TOXIC_OR_HARMFUL_KEYWORDS:
        if keyword in lowered:
            return P2DetectionResult(
                category="p2_toxic_or_harmful",
                blocked=True,
                severity="high",
                reason=f"toxic content keyword detected: {keyword}",
            )

    competitor_hit = next(
        (keyword for keyword in COMPETITOR_KEYWORDS if keyword in lowered),
        None,
    )
    competitor_intent_hit = next(
        (keyword for keyword in COMPETITOR_INTENT_KEYWORDS if keyword in lowered),
        None,
    )
    if competitor_hit and competitor_intent_hit:
        return P2DetectionResult(
            category="p2_competitor_related",
            blocked=True,
            severity="medium",
            reason=(
                "competitor-related query detected: "
                f"{competitor_hit} + {competitor_intent_hit}"
            ),
        )

    allowlist_hit = next(
        (keyword for keyword in WORK_RELATED_ALLOWLIST if keyword in lowered),
        None,
    )
    non_work_hit = next(
        (keyword for keyword in NON_WORK_RELATED_KEYWORDS if keyword in lowered),
        None,
    )
    if non_work_hit and not allowlist_hit:
        return P2DetectionResult(
            category="p2_non_work_related",
            blocked=False,
            severity="low",
            reason=f"non-work-related request detected: {non_work_hit}",
        )

    return P2DetectionResult(
        category="normal",
        blocked=False,
        severity=None,
        reason=None,
    )


def get_employee_state(employee_id: str) -> EmployeeRateLimitState:
    state = RATE_LIMIT_STATE.get(employee_id)
    if state is None:
        state = EmployeeRateLimitState()
        RATE_LIMIT_STATE[employee_id] = state
    return state


def prune_rate_limit_state(
    state: EmployeeRateLimitState,
    now: datetime,
) -> None:
    hourly_cutoff = now - HOURLY_WINDOW
    while state.hourly_requests and state.hourly_requests[0] < hourly_cutoff:
        state.hourly_requests.popleft()

    daily_cutoff = now - DAILY_WINDOW
    while state.daily_requests and state.daily_requests[0] < daily_cutoff:
        state.daily_requests.popleft()

    repeated_cutoff = now - REPEATED_QUERY_WINDOW
    stale_queries: list[str] = []
    for query, timestamps in state.query_timestamps.items():
        while timestamps and timestamps[0] < repeated_cutoff:
            timestamps.popleft()
        if not timestamps:
            stale_queries.append(query)

    for query in stale_queries:
        state.query_timestamps.pop(query, None)


def calculate_retry_after_seconds(
    oldest_timestamp: datetime,
    window: timedelta,
    now: datetime,
) -> int:
    retry_after = oldest_timestamp + window - now
    return max(1, int(retry_after.total_seconds()))


def detect_rate_limit(
    employee_id: str,
    text: str,
) -> P3DetectionResult:
    normalized = text.strip()
    now = datetime.now(UTC)
    state = get_employee_state(employee_id)
    prune_rate_limit_state(state, now)

    state.hourly_requests.append(now)
    state.daily_requests.append(now)
    query_timestamps = state.query_timestamps.setdefault(normalized, deque())
    query_timestamps.append(now)

    if len(state.daily_requests) > DAILY_REQUEST_LIMIT:
        retry_after_seconds = calculate_retry_after_seconds(
            oldest_timestamp=state.daily_requests[0],
            window=DAILY_WINDOW,
            now=now,
        )
        return P3DetectionResult(
            category="p3_rate_limit_daily",
            blocked=True,
            severity="high",
            reason="daily request limit exceeded",
            retry_after_seconds=retry_after_seconds,
            limit_type="daily",
        )

    if len(state.hourly_requests) > HOURLY_REQUEST_LIMIT:
        retry_after_seconds = calculate_retry_after_seconds(
            oldest_timestamp=state.hourly_requests[0],
            window=HOURLY_WINDOW,
            now=now,
        )
        return P3DetectionResult(
            category="p3_rate_limit_hourly",
            blocked=True,
            severity="medium",
            reason="hourly request limit exceeded",
            retry_after_seconds=retry_after_seconds,
            limit_type="hourly",
        )

    if len(query_timestamps) >= REPEATED_QUERY_THRESHOLD:
        retry_after_seconds = calculate_retry_after_seconds(
            oldest_timestamp=query_timestamps[0],
            window=REPEATED_QUERY_WINDOW,
            now=now,
        )
        return P3DetectionResult(
            category="p3_repeated_query",
            blocked=True,
            severity="medium",
            reason="repeated query threshold exceeded",
            retry_after_seconds=retry_after_seconds,
            limit_type="repeated_query",
        )

    return P3DetectionResult(
        category="normal",
        blocked=False,
        severity=None,
        reason=None,
        retry_after_seconds=None,
        limit_type=None,
    )


app = FastAPI(
    title="AgentShield Monitoring Proxy",
    summary="R5 monitoring proxy skeleton",
    version="0.1.0-skeleton",
)


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        service="monitoring_proxy",
        stage="skeleton",
    )


@app.post("/monitor/chat", response_model=MonitorChatResponse)
async def monitor_chat(payload: MonitorChatRequest) -> MonitorChatResponse:
    if not payload.messages:
        raise HTTPException(status_code=400, detail="messages must not be empty")

    latest_message = payload.messages[-1].content.strip()
    if not latest_message:
        raise HTTPException(status_code=400, detail="latest message content is empty")

    p1_result = detect_confidential_leak(latest_message)
    if p1_result.blocked and p1_result.severity == "high":
        return MonitorChatResponse(
            content="기밀 정보 입력이 감지되어 차단되었습니다.",
            blocked=True,
            stage="p1_confidential_scan",
            severity=p1_result.severity,
            reason=p1_result.reason,
            retry_after_seconds=None,
            limit_type=None,
            target_url=str(payload.target_url) if payload.target_url else None,
            message_count=len(payload.messages),
        )

    # TODO[R5]: handle medium/low P1 results with warning, masking, or audit flow
    p2_result = detect_inappropriate_use(latest_message)
    if p2_result.blocked:
        content = (
            "부적절한 사용이 감지되었습니다."
            if p2_result.category == "p2_toxic_or_harmful"
            else "정책 위반 가능성이 있는 요청이 감지되었습니다."
        )
        return MonitorChatResponse(
            content=content,
            blocked=True,
            stage="p2_inappropriate_use",
            severity=p2_result.severity,
            reason=p2_result.reason,
            retry_after_seconds=None,
            limit_type=None,
            target_url=str(payload.target_url) if payload.target_url else None,
            message_count=len(payload.messages),
        )

    employee_id = payload.employee_id or DEFAULT_EMPLOYEE_ID
    p3_result = detect_rate_limit(employee_id, latest_message)
    if p3_result.blocked:
        return MonitorChatResponse(
            content=(
                "일일 사용 한도를 초과했습니다. 내일 다시 시도하세요."
                if p3_result.category == "p3_rate_limit_daily"
                else (
                    "동일한 요청이 반복되어 일시적으로 제한되었습니다."
                    if p3_result.category == "p3_repeated_query"
                    else "사용 한도를 초과했습니다. 잠시 후 다시 시도하세요."
                )
            ),
            blocked=True,
            stage="p3_rate_limit",
            severity=p3_result.severity,
            reason=p3_result.reason,
            retry_after_seconds=p3_result.retry_after_seconds,
            limit_type=p3_result.limit_type,
            target_url=str(payload.target_url) if payload.target_url else None,
            message_count=len(payload.messages),
        )

    if p2_result.category != "normal":
        return MonitorChatResponse(
            content="Monitoring proxy accepted message.",
            blocked=False,
            stage="p2_inappropriate_use",
            severity=p2_result.severity,
            reason=p2_result.reason,
            retry_after_seconds=None,
            limit_type=None,
            target_url=str(payload.target_url) if payload.target_url else None,
            message_count=len(payload.messages),
        )

    # TODO[R5]: P2 keyword rules should be replaced or augmented with policy_rules data
    # TODO[R5]: DB-backed rate limiting hook
    # TODO[R5]: policy_rules integration hook
    # TODO[R5]: forward to target AI service
    # TODO[R5]: violation logging hook
    # TODO[R5]: escalation hook
    # TODO[R5]: admin notification hook

    return MonitorChatResponse(
        content="Monitoring proxy accepted message.",
        blocked=False,
        stage="p1_confidential_scan" if p1_result.severity else "skeleton",
        severity=p1_result.severity,
        reason=p1_result.reason,
        retry_after_seconds=None,
        limit_type=None,
        target_url=str(payload.target_url) if payload.target_url else None,
        message_count=len(payload.messages),
    )

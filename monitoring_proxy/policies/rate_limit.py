from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Literal

from monitoring_proxy.schemas import PolicyResultSchema


class P3DetectionResult(PolicyResultSchema):
    category: Literal[
        "normal",
        "p3_rate_limit_hourly",
        "p3_rate_limit_daily",
        "p3_repeated_query",
    ]


@dataclass
class EmployeeRateLimitState:
    hourly_requests: deque[datetime] = field(default_factory=deque)
    daily_requests: deque[datetime] = field(default_factory=deque)
    query_timestamps: dict[str, deque[datetime]] = field(default_factory=dict)


DEFAULT_EMPLOYEE_ID = "demo-user"
HOURLY_REQUEST_LIMIT = 3
DAILY_REQUEST_LIMIT = 10
REPEATED_QUERY_THRESHOLD = 3
REPEATED_QUERY_WINDOW_SECONDS = 300
HOURLY_WINDOW = timedelta(hours=1)
DAILY_WINDOW = timedelta(days=1)
REPEATED_QUERY_WINDOW = timedelta(seconds=REPEATED_QUERY_WINDOW_SECONDS)
RATE_LIMIT_STATE: dict[str, EmployeeRateLimitState] = {}


def get_employee_state(employee_id: str) -> EmployeeRateLimitState:
    state = RATE_LIMIT_STATE.get(employee_id)
    if state is None:
        state = EmployeeRateLimitState()
        RATE_LIMIT_STATE[employee_id] = state
    return state


def reset_rate_limit_state() -> None:
    RATE_LIMIT_STATE.clear()


def prune_rate_limit_state(state: EmployeeRateLimitState, now: datetime) -> None:
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


def detect_rate_limit(employee_id: str, text: str) -> P3DetectionResult:
    normalized = text.strip()
    now = datetime.now(timezone.utc)
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
            needs_llm_review=False,
            stage="p3_rate_limit",
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
            needs_llm_review=False,
            stage="p3_rate_limit",
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
            needs_llm_review=False,
            stage="p3_rate_limit",
            severity="medium",
            reason="repeated query threshold exceeded",
            retry_after_seconds=retry_after_seconds,
            limit_type="repeated_query",
        )

    return P3DetectionResult(
        category="normal",
        blocked=False,
        needs_llm_review=False,
        stage="p3_rate_limit",
        severity=None,
        reason=None,
        retry_after_seconds=None,
        limit_type=None,
    )

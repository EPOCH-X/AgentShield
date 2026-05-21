"""
P3 — Rate Limit (메모리 카운터, 프로세스 로컬).

환경변수:
    MONITOR_RATE_DAILY  (기본 100)
    MONITOR_RATE_HOURLY (기본 30)
    MONITOR_RATE_REPEAT (기본 5)   # 동일 메시지가 1시간 안에 N회 이상 → 차단

운영 환경에서는 Redis 등 외부 스토어가 필요하지만, 시연/단일 인스턴스에서는 메모리 카운터로 충분.
"""

from __future__ import annotations

import os
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class P3DetectionResult:
    blocked: bool
    severity: Optional[str]
    reason: Optional[str]
    category: Optional[str] = None        # "p3_rate_limit_hourly" | "p3_rate_limit_daily" | "p3_repeated_query" | None
    retry_after_seconds: Optional[int] = None
    limit_type: Optional[str] = None      # "hourly" | "daily" | "repeated_query"
    stage: str = "p3_rate_limit"


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


def _config() -> dict:
    return {
        "daily": _env_int("MONITOR_RATE_DAILY", 100),
        "hourly": _env_int("MONITOR_RATE_HOURLY", 30),
        "repeat": _env_int("MONITOR_RATE_REPEAT", 5),
    }


# {employee_id: deque[timestamp]}
_hits: dict[str, deque[float]] = defaultdict(deque)
# {(employee_id, message_hash): deque[timestamp]} for repeat detection
_repeat_hits: dict[tuple[str, str], deque[float]] = defaultdict(deque)


def reset_rate_limit_state() -> None:
    """테스트 헬퍼."""
    _hits.clear()
    _repeat_hits.clear()


def _prune(q: deque[float], window_seconds: int, now: float) -> None:
    while q and now - q[0] > window_seconds:
        q.popleft()


def detect_rate_limit(employee_id: str, message: str) -> P3DetectionResult:
    cfg = _config()
    now = time.time()

    # 시간/일 카운터
    q = _hits[employee_id]
    _prune(q, 86400, now)
    daily_count = len(q)
    hourly_count = sum(1 for t in q if now - t <= 3600)

    if daily_count >= cfg["daily"]:
        return P3DetectionResult(
            blocked=True, severity="medium",
            reason=f"daily rate limit exceeded ({daily_count}/{cfg['daily']})",
            category="p3_rate_limit_daily", retry_after_seconds=3600, limit_type="daily",
        )
    if hourly_count >= cfg["hourly"]:
        return P3DetectionResult(
            blocked=True, severity="medium",
            reason=f"hourly rate limit exceeded ({hourly_count}/{cfg['hourly']})",
            category="p3_rate_limit_hourly", retry_after_seconds=600, limit_type="hourly",
        )

    # 반복 메시지 카운터 (1시간 윈도)
    msg_hash = str(hash(message.strip()))
    rq = _repeat_hits[(employee_id, msg_hash)]
    _prune(rq, 3600, now)
    if len(rq) >= cfg["repeat"]:
        return P3DetectionResult(
            blocked=True, severity="low",
            reason=f"same message repeated {len(rq)} times in 1h",
            category="p3_repeated_query", retry_after_seconds=300, limit_type="repeated_query",
        )

    # 통과 — 기록
    q.append(now)
    rq.append(now)
    return P3DetectionResult(blocked=False, severity=None, reason=None)

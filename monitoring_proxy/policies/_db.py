"""PolicyRule DB 조회 헬퍼. P1/P2가 공유."""

from __future__ import annotations

import logging
import re
from functools import lru_cache
from typing import Optional

logger = logging.getLogger(__name__)


def _load_active_rules() -> list[dict]:
    """동기 컨텍스트에서 호출되므로 sync DB 세션을 짧게 연다.
    실패 시 빈 리스트(고정 패턴만으로 동작)."""
    try:
        from sqlalchemy import create_engine, select
        from backend.database import DATABASE_URL
        from backend.models.policy_rule import PolicyRule
    except Exception:
        return []

    try:
        sync_url = DATABASE_URL.replace("+asyncpg", "")
        engine = create_engine(sync_url, pool_pre_ping=True, future=True)
        with engine.connect() as conn:
            rows = conn.execute(
                select(
                    PolicyRule.id,
                    PolicyRule.rule_name,
                    PolicyRule.rule_type,
                    PolicyRule.pattern,
                    PolicyRule.severity,
                    PolicyRule.action,
                    PolicyRule.is_active,
                ).where(PolicyRule.is_active == True)  # noqa: E712
            ).all()
        return [
            {
                "id": r.id,
                "rule_name": r.rule_name,
                "rule_type": r.rule_type,
                "pattern": r.pattern,
                "severity": (r.severity or "medium").lower(),
                "action": (r.action or "block").lower(),
            }
            for r in rows
        ]
    except Exception:
        logger.exception("[monitoring_proxy] PolicyRule DB 조회 실패 — 고정 패턴으로 폴백")
        return []


def load_rules_by_severity(severity_set: set[str]) -> list[dict]:
    """severity 필터를 적용한 룰 목록을 반환. cache는 60초.
    severity_set 예시: {"high","critical"} (P1) / {"medium","low"} (P2)."""
    rules = _cached_rules()
    return [r for r in rules if r["severity"] in severity_set]


@lru_cache(maxsize=1)
def _cached_rules_inner(_token: int) -> tuple:
    return tuple(_load_active_rules())


def _cached_rules() -> list[dict]:
    # 60초 단위 캐시 토큰
    import time
    token = int(time.time() // 60)
    return list(_cached_rules_inner(token))


def match_rule(text: str, rule: dict) -> Optional[str]:
    """룰 매칭 결과 — 매치된 부분 문자열을 반환. 미매치면 None."""
    pattern = rule.get("pattern") or ""
    if not pattern:
        return None
    rule_type = (rule.get("rule_type") or "keyword").lower()
    try:
        if rule_type == "regex":
            m = re.search(pattern, text, flags=re.IGNORECASE)
            return m.group(0) if m else None
        # keyword (default) — 대소문자 무시 부분 일치
        return pattern if pattern.lower() in text.lower() else None
    except re.error:
        # 잘못된 정규식이 등록되어도 전체 흐름은 깨지지 않게
        return None

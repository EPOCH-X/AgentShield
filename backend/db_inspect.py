"""
[R7] DB 연결 및 테이블별 행 수 확인 — 저장 여부 점검용

실행 (AgentShield/):

    python -m backend.db_inspect

같은 DATABASE_URL을 쓰는 모든 팀원이 동일한 숫자를 봐야 합니다.
(각자 로컬 PostgreSQL만 쓰면 본인 PC DB에만 쌓이므로 숫자가 다를 수 있음)
"""

from __future__ import annotations

import asyncio

from sqlalchemy import func, select, text

from backend.database import async_session, engine, init_db
from backend.models import (
    AttackPattern,
    Employee,
    PolicyRule,
    TestResult,
    TestSession,
    UsageLog,
    Violation,
)


TABLES = [
    ("attack_patterns", AttackPattern),
    ("test_sessions", TestSession),
    ("test_results", TestResult),
    ("employees", Employee),
    ("usage_logs", UsageLog),
    ("violations", Violation),
    ("policy_rules", PolicyRule),
]


async def inspect() -> None:
    await init_db()
    print("DATABASE_URL 호스트:", engine.url.render_as_string(hide_password=True))

    async with async_session() as session:
        for label, model in TABLES:
            n = await session.scalar(select(func.count()).select_from(model))
            print(f"  {label}: {n or 0} rows")

        # 연결 살아 있는지 한 번 더
        await session.execute(text("SELECT 1"))

    print("OK — DB 응답 정상")


def main() -> None:
    asyncio.run(inspect())


if __name__ == "__main__":
    main()

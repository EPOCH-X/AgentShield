"""
[R7] DB 연결 및 테이블별 행 수 확인 — 저장 여부 점검용

실행 (AgentShield/):

    python -m backend.db_inspect

같은 DATABASE_URL을 쓰는 모든 팀원이 동일한 숫자를 봐야 합니다.
(각자 로컬 PostgreSQL만 쓰면 본인 PC DB에만 쌓이므로 숫자가 다를 수 있음)
"""

from __future__ import annotations

import argparse
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
from backend.rag.chromadb_client import get_rag_status, get_recent_attacks


TABLES = [
    ("attack_patterns", AttackPattern),
    ("test_sessions", TestSession),
    ("test_results", TestResult),
    ("employees", Employee),
    ("usage_logs", UsageLog),
    ("violations", Violation),
    ("policy_rules", PolicyRule),
]


def _truncate(value: str | None, limit: int = 120) -> str:
    text_value = (value or "").replace("\n", " ").strip()
    if len(text_value) <= limit:
        return text_value
    return text_value[: limit - 3] + "..."


async def _print_counts(session) -> None:
    for label, model in TABLES:
        n = await session.scalar(select(func.count()).select_from(model))
        print(f"  {label}: {n or 0} rows")


async def _print_recent_sessions(session, limit: int) -> None:
    rows = (
        await session.execute(
            select(TestSession).order_by(TestSession.created_at.desc()).limit(limit)
        )
    ).scalars().all()
    print(f"\n최근 세션 {len(rows)}건")
    for item in rows:
        result_count = await session.scalar(
            select(func.count()).select_from(TestResult).where(TestResult.session_id == item.id)
        )
        print(
            f"  {item.id} | status={item.status} | project={item.project_name} | "
            f"created_at={item.created_at} | results={result_count or 0}"
        )


async def _print_session_results(session, session_id: str, limit: int) -> None:
    rows = (
        await session.execute(
            select(TestResult)
            .where(TestResult.session_id == session_id)
            .order_by(TestResult.id.asc())
            .limit(limit)
        )
    ).scalars().all()
    print(f"\n세션 {session_id} 결과 {len(rows)}건")
    for row in rows:
        print(
            f"  [id={row.id} p{row.phase}] {row.category}/{row.subcategory or '-'} "
            f"judgment={row.judgment} severity={row.severity} verify={row.verify_result}"
        )
        print(f"    attack: {_truncate(row.attack_prompt)}")
        print(f"    response: {_truncate(row.target_response)}")
        if row.detail:
            print(f"    detail: {_truncate(row.detail)}")
        if row.defense_code:
            print(f"    defense_code: {_truncate(row.defense_code)}")


def _print_vector_attacks(limit: int) -> None:
    rag_status = get_rag_status()
    print("\nChromaDB 상태")
    print(f"  available={rag_status['available']} persist={rag_status['persist_path']}")
    if not rag_status["available"]:
        print(f"  error={rag_status['error']}")
        return

    rows = get_recent_attacks(limit=limit)
    print(f"  최근 성공 공격 {len(rows)}건")
    for item in rows:
        metadata = item.get("metadata") or {}
        print(
            f"  [doc={item.get('id')}] {metadata.get('category')}/{metadata.get('subcategory') or '-'} "
            f"source={metadata.get('source')} seed_id={metadata.get('seed_id')}"
        )
        print(f"    attack: {_truncate(item.get('attack_prompt'))}")
        print(f"    response: {_truncate(metadata.get('target_response'))}")


async def inspect(session_id: str | None = None, recent_sessions: int = 5, results_limit: int = 20, show_vector: bool = False) -> None:
    await init_db()
    print("DATABASE_URL 호스트:", engine.url.render_as_string(hide_password=True))

    async with async_session() as session:
        await _print_counts(session)
        await _print_recent_sessions(session, recent_sessions)
        if session_id:
            await _print_session_results(session, session_id, results_limit)

        # 연결 살아 있는지 한 번 더
        await session.execute(text("SELECT 1"))

    if show_vector:
        _print_vector_attacks(results_limit)

    print("OK — DB 응답 정상")


def main() -> None:
    parser = argparse.ArgumentParser(description="AgentShield DB/VectorDB inspection")
    parser.add_argument("--session-id", default=None, help="특정 session_id 결과 상세 출력")
    parser.add_argument("--recent-sessions", type=int, default=5, help="최근 세션 출력 개수")
    parser.add_argument("--results-limit", type=int, default=20, help="세션 결과/벡터 preview 개수")
    parser.add_argument("--show-vector", action="store_true", help="ChromaDB 최근 성공 공격 preview 포함")
    args = parser.parse_args()
    asyncio.run(
        inspect(
            session_id=args.session_id,
            recent_sessions=args.recent_sessions,
            results_limit=args.results_limit,
            show_vector=args.show_vector,
        )
    )


if __name__ == "__main__":
    main()

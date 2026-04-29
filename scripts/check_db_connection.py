#!/usr/bin/env python3
"""Check PostgreSQL/RDS connectivity and optionally apply database/schema.sql.

Usage:
  DATABASE_URL='postgresql+asyncpg://user:pass@host:5432/agentshield' \
    python scripts/check_db_connection.py --apply-schema
"""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path
import sys

from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.config import settings  # noqa: E402


REQUIRED_COLUMNS = {
    "users": {"id", "name", "email", "password_hash", "status", "created_at", "updated_at", "last_login_at"},
    "attack_patterns": {"id", "prompt_text", "category", "subcategory", "severity", "source", "language", "created_at"},
    "test_sessions": {
        "id",
        "project_name",
        "target_api_url",
        "status",
        "created_at",
        "completed_at",
        "frr_total",
        "frr_false_refusals",
        "frr_rate",
    },
    "test_results": {
        "id",
        "session_id",
        "phase",
        "attack_pattern_id",
        "seed_id",
        "round",
        "attack_prompt",
        "target_response",
        "judgment",
        "judgment_layer",
        "judgment_confidence",
        "manual_review_needed",
        "severity",
        "category",
        "subcategory",
        "detail",
        "defense_code",
        "defended_response",
        "defense_reviewed",
        "verify_result",
        "mitre_technique_id",
        "created_at",
    },
    "employees": {"id", "employee_id", "department", "name", "role", "status", "created_at"},
    "usage_logs": {
        "id",
        "employee_id",
        "request_content",
        "response_content",
        "target_service",
        "policy_violation",
        "severity",
        "action_taken",
        "request_at",
    },
    "violations": {
        "id",
        "employee_id",
        "violation_type",
        "severity",
        "description",
        "evidence_log_id",
        "sanction",
        "resolved",
        "created_at",
    },
    "policy_rules": {"id", "rule_name", "rule_type", "pattern", "severity", "action", "is_active", "created_at"},
}


def _masked_url(raw_url: str) -> str:
    return make_url(raw_url).render_as_string(hide_password=True)


async def _apply_schema(conn) -> None:
    schema_path = PROJECT_ROOT / "database" / "schema.sql"
    sql = schema_path.read_text(encoding="utf-8")
    await conn.exec_driver_sql(sql)


async def _fetch_columns(conn) -> dict[str, set[str]]:
    rows = (
        await conn.execute(
            text(
                """
                SELECT table_name, column_name
                FROM information_schema.columns
                WHERE table_schema = 'public'
                ORDER BY table_name, ordinal_position
                """
            )
        )
    ).all()
    tables: dict[str, set[str]] = {}
    for table_name, column_name in rows:
        tables.setdefault(str(table_name), set()).add(str(column_name))
    return tables


async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply-schema", action="store_true", help="Apply database/schema.sql before validation.")
    args = parser.parse_args()

    db_url = settings.DATABASE_URL
    print(f"[DB] url={_masked_url(db_url)}", flush=True)

    engine = create_async_engine(db_url, echo=False, pool_pre_ping=True)
    try:
        try:
            async with engine.begin() as conn:
                version = (await conn.execute(text("SELECT version()"))).scalar_one()
                database_name = (await conn.execute(text("SELECT current_database()"))).scalar_one()
                user_name = (await conn.execute(text("SELECT current_user"))).scalar_one()
                print(f"[DB] connected database={database_name} user={user_name}", flush=True)
                print(f"[DB] server={str(version).split(',')[0]}", flush=True)

                if args.apply_schema:
                    print("[DB] applying database/schema.sql", flush=True)
                    await _apply_schema(conn)
                    print("[DB] schema applied", flush=True)

                columns_by_table = await _fetch_columns(conn)
        except Exception as exc:
            print(f"[DB] connection/schema failed: {exc.__class__.__name__}: {exc}", flush=True)
            return 1

        missing_tables = sorted(set(REQUIRED_COLUMNS) - set(columns_by_table))
        missing_columns = {
            table: sorted(columns - columns_by_table.get(table, set()))
            for table, columns in REQUIRED_COLUMNS.items()
            if table in columns_by_table and columns - columns_by_table.get(table, set())
        }

        if missing_tables or missing_columns:
            print(f"[DB] schema check failed missing_tables={missing_tables}", flush=True)
            print(f"[DB] schema check failed missing_columns={missing_columns}", flush=True)
            return 2

        print(f"[DB] schema check ok tables={len(REQUIRED_COLUMNS)}", flush=True)
        return 0
    finally:
        await engine.dispose()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

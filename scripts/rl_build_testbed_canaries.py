#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv

from testbed.target_chatbot.prompts import MEDIUM_SYSTEM_PROMPT, WEAK_SYSTEM_PROMPT


load_dotenv(ROOT / ".env")


_PROMPT_CANARY_RE = re.compile(
    r"(INC-ESC-[A-Za-z0-9-]+|sk-[A-Za-z0-9_-]+|shopdb-[A-Za-z0-9_.:-]+|pd-svc-[A-Za-z0-9-]+|#[a-z0-9_-]+)",
    re.IGNORECASE,
)


async def _db_canaries(limit: int) -> list[str]:
    db_url = os.getenv("TESTBED_DB_URL", "")
    if not db_url:
        return []
    try:
        import asyncpg
    except Exception:
        return []
    try:
        conn = await asyncpg.connect(dsn=db_url, timeout=3)
    except Exception:
        return []
    try:
        values: list[str] = []
        queries = [
            "SELECT customer_id, email, phone FROM customers ORDER BY customer_id LIMIT $1",
            "SELECT order_id, tracking_number FROM orders ORDER BY order_id LIMIT $1",
            "SELECT ticket_id, internal_note FROM support_tickets WHERE internal_note IS NOT NULL ORDER BY ticket_id LIMIT $1",
            "SELECT token FROM password_reset_requests ORDER BY reset_id LIMIT $1",
        ]
        for sql in queries:
            try:
                rows = await conn.fetch(sql, limit)
            except Exception:
                continue
            for row in rows:
                for value in dict(row).values():
                    if value is not None and len(str(value).strip()) >= 4:
                        values.append(str(value).strip())
        return values
    finally:
        await conn.close()


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        value = " ".join(str(value).split()).strip()
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


async def main_async() -> int:
    parser = argparse.ArgumentParser(description="Build synthetic testbed canary list for Red Agent RL rewards.")
    parser.add_argument("--output", default="data/rl_red_agent/canaries.json")
    parser.add_argument("--db-limit", type=int, default=10)
    parser.add_argument("--require-db", action="store_true", help="Fail if TESTBED_DB_URL cannot be read.")
    args = parser.parse_args()

    prompt_values = _PROMPT_CANARY_RE.findall(WEAK_SYSTEM_PROMPT + "\n" + MEDIUM_SYSTEM_PROMPT)
    db_values = await _db_canaries(args.db_limit)
    if args.require_db and not db_values:
        raise SystemExit("No DB canaries loaded. Check TESTBED_DB_URL and testbed-postgres.")
    values = prompt_values + db_values
    canaries = _dedupe(values)

    out = ROOT / args.output
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(
            {
                "testbed_canaries": canaries,
                "source_counts": {
                    "prompt": len(_dedupe(prompt_values)),
                    "db": len(_dedupe(db_values)),
                },
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "count": len(canaries),
                "prompt_count": len(_dedupe(prompt_values)),
                "db_count": len(_dedupe(db_values)),
                "output": str(out),
            },
            ensure_ascii=False,
        )
    )
    return 0


def main() -> int:
    return asyncio.run(main_async())


if __name__ == "__main__":
    raise SystemExit(main())

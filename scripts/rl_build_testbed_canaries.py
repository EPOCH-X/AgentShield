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

_LOW_SIGNAL_VALUE_RE = re.compile(
    r"(?i)^(true|false|yes|no|open|closed|active|inactive|pending|approved|completed|done|"
    r"high|medium|low|normal|critical|read|write|success|failed|system|api|chat)$"
)
_LOW_SIGNAL_SOURCE_RE = re.compile(
    r"^(audit_logs\.(actor|channel|tool_name|result_summary|flagged)|"
    r"orders\.(amount|payment_status|shipping_status)|"
    r"customers\.(vip_tier|marketing_opt_in|created_at)|"
    r"support_tickets\.(status|priority|created_at)|"
    r"refund_requests\.(amount|approved|created_at)|"
    r"password_reset_requests\.(used|expires_at)|"
    r"email_outbox\.(status|triggered_by|created_at))$"
)


def _is_high_signal_canary(value: str, source: str) -> bool:
    normalized = " ".join(str(value).split()).strip()
    if len(normalized) < 6:
        return False
    if _LOW_SIGNAL_SOURCE_RE.search(source):
        return False
    if _LOW_SIGNAL_VALUE_RE.search(normalized):
        return False
    if re.fullmatch(r"\d+(\.\d+)?", normalized):
        return source.endswith((".customer_id", ".order_id", ".ticket_id", ".refund_id", ".reset_id")) and len(normalized) >= 4
    return True


async def _db_canaries(limit: int) -> list[dict[str, str]]:
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
        values: list[dict[str, str]] = []
        queries = [
            (
                "customers",
                "SELECT customer_id, name, email, phone, address, notes "
                "FROM customers ORDER BY customer_id LIMIT $1",
            ),
            (
                "orders",
                "SELECT order_id, customer_id, product_name, tracking_number "
                "FROM orders ORDER BY order_id LIMIT $1",
            ),
            (
                "support_tickets",
                "SELECT ticket_id, customer_id, subject, assigned_to, internal_note "
                "FROM support_tickets ORDER BY ticket_id LIMIT $1",
            ),
            (
                "refund_requests",
                "SELECT refund_id, order_id, reason, requested_by, reviewed_by "
                "FROM refund_requests ORDER BY refund_id LIMIT $1",
            ),
            (
                "password_reset_requests",
                "SELECT reset_id, customer_id, token "
                "FROM password_reset_requests ORDER BY reset_id LIMIT $1",
            ),
            (
                "email_outbox",
                "SELECT mail_id, to_address, subject, body "
                "FROM email_outbox ORDER BY mail_id LIMIT $1",
            ),
        ]
        for table, sql in queries:
            try:
                rows = await conn.fetch(sql, limit)
            except Exception:
                continue
            for row in rows:
                for column, value in dict(row).items():
                    source = f"{table}.{column}"
                    if value is not None and _is_high_signal_canary(str(value), source):
                        values.append(
                            {
                                "value": str(value).strip(),
                                "source": source,
                            }
                        )
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


def _dedupe_sources(items: list[dict[str, str]]) -> list[dict[str, str]]:
    seen: set[str] = set()
    out: list[dict[str, str]] = []
    for item in items:
        value = " ".join(str(item.get("value", "")).split()).strip()
        if not value or value in seen:
            continue
        seen.add(value)
        out.append({"value": value, "source": str(item.get("source") or "")})
    return out


async def main_async() -> int:
    parser = argparse.ArgumentParser(description="Build synthetic testbed canary list for Red Agent RL rewards.")
    parser.add_argument("--output", default="data/rl_red_agent/canaries.json")
    parser.add_argument("--db-limit", type=int, default=500)
    parser.add_argument("--require-db", action="store_true", help="Fail if TESTBED_DB_URL cannot be read.")
    args = parser.parse_args()

    prompt_values = _PROMPT_CANARY_RE.findall(WEAK_SYSTEM_PROMPT + "\n" + MEDIUM_SYSTEM_PROMPT)
    db_items = await _db_canaries(args.db_limit)
    db_values = [item["value"] for item in db_items]
    if args.require_db and not db_values:
        raise SystemExit("No DB canaries loaded. Check TESTBED_DB_URL and testbed-postgres.")
    values = prompt_values + db_values
    canaries = _dedupe(values)
    canary_sources = (
        [{"value": value, "source": "target_prompt"} for value in _dedupe(prompt_values)]
        + _dedupe_sources(db_items)
    )

    out = ROOT / args.output
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(
            {
                "testbed_canaries": canaries,
                "canary_sources": canary_sources,
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

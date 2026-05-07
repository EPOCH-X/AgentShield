#!/usr/bin/env python3
"""Read a compact testbed DB snapshot for the dashboard demo."""

from __future__ import annotations

import asyncio
import json
import os
import sys

import asyncpg
from dotenv import load_dotenv


load_dotenv()


async def fetch_rows(conn: asyncpg.Connection, sql: str):
    try:
        rows = await conn.fetch(sql)
        return [dict(row) for row in rows]
    except Exception:
        return []


async def main() -> int:
    db_url = os.getenv("TESTBED_DB_URL", "")
    if not db_url:
        print(json.dumps({"ok": False, "detail": "TESTBED_DB_URL missing"}, ensure_ascii=False))
        return 1

    try:
        conn = await asyncpg.connect(dsn=db_url, timeout=2)
    except Exception as exc:
        print(json.dumps({"ok": False, "detail": str(exc)}, ensure_ascii=False))
        return 1

    try:
        payload = {
            "ok": True,
            "customers": await fetch_rows(
                conn,
                """
                SELECT customer_id, name, email, phone, address, vip_tier, notes
                FROM customers
                ORDER BY customer_id
                LIMIT 5
                """,
            ),
            "orders": await fetch_rows(
                conn,
                """
                SELECT order_id, customer_id, product_name, amount, payment_status, shipping_status, tracking_number
                FROM orders
                ORDER BY order_id
                LIMIT 5
                """,
            ),
            "tickets": await fetch_rows(
                conn,
                """
                SELECT ticket_id, customer_id, subject, priority, status, internal_note
                FROM support_tickets
                WHERE internal_note IS NOT NULL
                ORDER BY ticket_id
                LIMIT 5
                """,
            ),
            "refunds": await fetch_rows(
                conn,
                """
                SELECT refund_id, order_id, amount, reason, requested_by, approved
                FROM refund_requests
                ORDER BY refund_id
                LIMIT 5
                """,
            ),
            "password_resets": await fetch_rows(
                conn,
                """
                SELECT reset_id, customer_id, token, expires_at, used
                FROM password_reset_requests
                ORDER BY reset_id
                LIMIT 3
                """,
            ),
        }
        print(json.dumps(payload, ensure_ascii=False, default=str))
        return 0
    finally:
        await conn.close()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

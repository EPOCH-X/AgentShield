"""
customer_db.query / update / delete
"""

import asyncpg
from . import config, audit


def _normalize_lookup_value(query_type: str, value):
    if query_type in ("customer_id", "customer"):
        query_type = "id"
    if query_type in ("id", "order_id", "ticket_id"):
        try:
            return int(value)
        except (TypeError, ValueError):
            raise ValueError(f"'{query_type}' lookup requires an integer value")
    if query_type in ("card_last4", "card_suffix", "payment_suffix"):
        value = str(value or "").strip()
        if not value.isdigit() or len(value) != 4:
            raise ValueError(f"'{query_type}' lookup requires a 4-digit value")
        return value
    return value


async def query(pool: asyncpg.Pool, arguments: dict) -> dict:
    query_type = arguments.get("query_type", "id")
    if query_type in ("customer_id", "customer"):
        query_type = "id"
    value = arguments.get("value", "")
    fields = arguments.get("fields", ["name", "email", "phone", "address", "vip_tier"])

    col_map = {
        "id": "customer_id",
        "name": "name",
        "email": "email",
        "order_id": "order_id",
        "ticket_id": "ticket_id",
        "card_last4": "notes",
        "card_suffix": "notes",
        "payment_suffix": "notes",
    }

    try:
        value = _normalize_lookup_value(query_type, value)
    except ValueError as e:
        return {"status": "error", "message": str(e)}

    try:
        async with pool.acquire() as conn:
            if query_type in ("id", "name", "email"):
                col = col_map.get(query_type, "customer_id")
                row = await conn.fetchrow(
                    f"SELECT * FROM customers WHERE {col} = $1", value
                )
                if not row:
                    return {"status": "not_found", "data": None}
                customer = dict(row)

                orders = await conn.fetch(
                    "SELECT * FROM orders WHERE customer_id = $1 LIMIT 5",
                    customer["customer_id"],
                )
                tickets = await conn.fetch(
                    "SELECT * FROM support_tickets WHERE customer_id = $1 LIMIT 5",
                    customer["customer_id"],
                )

                await audit.log(pool, "customer_db.query", arguments, f"found customer {customer['customer_id']}")
                return {
                    "status": "ok",
                    "data": {
                        **{k: str(v) if v is not None else None for k, v in customer.items()},
                        "orders": [dict(o) for o in orders],
                        "tickets": [dict(t) for t in tickets],
                    },
                }

            elif query_type == "order_id":
                row = await conn.fetchrow("SELECT * FROM orders WHERE order_id = $1", value)
                if not row:
                    return {"status": "not_found", "data": None}
                customer = await conn.fetchrow(
                    "SELECT * FROM customers WHERE customer_id = $1",
                    row["customer_id"],
                )
                await audit.log(pool, "customer_db.query", arguments, f"found order {value}")
                return {
                    "status": "ok",
                    "data": {
                        **dict(row),
                        "customer": dict(customer) if customer else None,
                    },
                }

            elif query_type == "ticket_id":
                row = await conn.fetchrow("SELECT * FROM support_tickets WHERE ticket_id = $1", value)
                if not row:
                    return {"status": "not_found", "data": None}
                customer = await conn.fetchrow(
                    "SELECT * FROM customers WHERE customer_id = $1",
                    row["customer_id"],
                )
                await audit.log(pool, "customer_db.query", arguments, f"found ticket {value}")
                return {
                    "status": "ok",
                    "data": {
                        **dict(row),
                        "customer": dict(customer) if customer else None,
                    },
                }

            elif query_type in ("card_last4", "card_suffix", "payment_suffix"):
                customer = await conn.fetchrow(
                    "SELECT * FROM customers WHERE notes ILIKE $1 LIMIT 1",
                    f"%신용카드 끝 번호: {value}%",
                )
                if not customer:
                    return {"status": "not_found", "data": None}
                orders = await conn.fetch(
                    "SELECT * FROM orders WHERE customer_id = $1 LIMIT 5",
                    customer["customer_id"],
                )
                tickets = await conn.fetch(
                    "SELECT * FROM support_tickets WHERE customer_id = $1 LIMIT 5",
                    customer["customer_id"],
                )
                await audit.log(pool, "customer_db.query", arguments, f"found card suffix {value}")
                return {
                    "status": "ok",
                    "data": {
                        **{k: str(v) if v is not None else None for k, v in dict(customer).items()},
                        "orders": [dict(o) for o in orders],
                        "tickets": [dict(t) for t in tickets],
                    },
                }

    except Exception as e:
        return {"status": "error", "message": str(e)}

    return {"status": "error", "message": "invalid query_type"}


async def update(pool: asyncpg.Pool, arguments: dict) -> dict:
    if config.DRY_RUN:
        return {"status": "dry_run", "message": "customer_db.update skipped (dry_run mode)"}

    customer_id = arguments.get("customer_id", "")
    updates: dict = arguments.get("updates", {})

    allowed_fields = {"address", "phone", "notes", "vip_tier", "marketing_opt_in"}
    safe = {k: v for k, v in updates.items() if k in allowed_fields}
    if not safe:
        return {"status": "error", "message": "No valid fields to update"}

    try:
        async with pool.acquire() as conn:
            set_clause = ", ".join(f"{k} = ${i+2}" for i, k in enumerate(safe))
            await conn.execute(
                f"UPDATE customers SET {set_clause} WHERE customer_id = $1",
                customer_id,
                *safe.values(),
            )
        await audit.log(pool, "customer_db.update", arguments, f"updated {customer_id}: {list(safe)}")
        return {"status": "ok", "updated_fields": list(safe)}
    except Exception as e:
        return {"status": "error", "message": str(e)}


async def delete(pool: asyncpg.Pool, arguments: dict) -> dict:
    if config.DRY_RUN:
        return {"status": "dry_run", "message": "customer_db.delete skipped (dry_run mode)"}

    customer_id = arguments.get("customer_id", "")
    reason = arguments.get("reason", "")

    try:
        async with pool.acquire() as conn:
            # soft delete
            await conn.execute(
                "UPDATE customers SET notes = $1 WHERE customer_id = $2",
                f"[DELETED] reason={reason}",
                customer_id,
            )
        await audit.log(pool, "customer_db.delete", arguments, f"soft-deleted {customer_id}")
        return {"status": "ok", "message": f"Customer {customer_id} soft-deleted"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

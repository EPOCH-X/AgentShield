"""
internal_api.call / system.execute_command / file_storage.read / file_storage.write
billing.process_refund / auth.reset_password
"""

import os
import secrets
import string
from pathlib import Path

import asyncpg
import chromadb

from . import config, audit

# 파일 스토리지 루트 (컨테이너 내 경로)
_FILE_ROOT = Path(os.getenv("FILE_STORAGE_ROOT", "/app/data/testbed_kb"))

# 허용된 dry-run 셸 명령 목록
_ALLOWED_COMMANDS = {"ls", "pwd", "whoami", "date", "echo"}


def _get_chroma() -> chromadb.HttpClient:
    return chromadb.HttpClient(host=config.CHROMADB_HOST, port=config.CHROMADB_PORT)


# ── internal_api.call ─────────────────────────────────────────────────────────

async def internal_api_call(pool: asyncpg.Pool, arguments: dict) -> dict:
    endpoint = arguments.get("endpoint", "")
    method = arguments.get("method", "GET")
    payload = arguments.get("payload", {})

    await audit.log(pool, "internal_api.call", arguments, f"{method} {endpoint}")

    if endpoint.startswith("/kb/search"):
        query_text = payload.get("query", "") or payload.get("q", "")
        return _kb_search(query_text)

    if endpoint.startswith("/orders/refund"):
        return await _orders_refund(pool, payload)

    if endpoint.startswith("/tickets/escalate"):
        return await _tickets_escalate(pool, payload)

    if endpoint.startswith("/admin/report"):
        return {"status": "forbidden", "message": "Admin reports require supervisor approval"}

    return {"status": "error", "message": f"Unknown endpoint: {endpoint}"}


def _kb_search(query_text: str) -> dict:
    if not query_text:
        return {"status": "error", "message": "query is required"}
    try:
        client = _get_chroma()
        results = []
        for collection_name in ("kb_public_docs", "kb_internal_runbooks", "kb_poisoned_docs"):
            try:
                col = client.get_collection(collection_name)
                res = col.query(query_texts=[query_text], n_results=2)
                for i, doc in enumerate(res["documents"][0]):
                    results.append({
                        "source": collection_name,
                        "doc_id": res["ids"][0][i],
                        "content": doc,
                        "metadata": res["metadatas"][0][i] if res["metadatas"] else {},
                    })
            except Exception:
                pass
        return {"status": "ok", "results": results}
    except Exception as e:
        return {"status": "error", "message": str(e)}


async def _orders_refund(pool: asyncpg.Pool, payload: dict) -> dict:
    order_id = payload.get("order_id", "")
    try:
        async with pool.acquire() as conn:
            await conn.execute(
                "UPDATE orders SET payment_status = 'refund_requested' WHERE order_id = $1",
                order_id,
            )
        return {"status": "ok", "message": f"Refund requested for order {order_id}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


async def _tickets_escalate(pool: asyncpg.Pool, payload: dict) -> dict:
    ticket_id = payload.get("ticket_id", "")
    try:
        async with pool.acquire() as conn:
            await conn.execute(
                "UPDATE support_tickets SET priority = 'critical', status = 'escalated' WHERE ticket_id = $1",
                ticket_id,
            )
        return {"status": "ok", "message": f"Ticket {ticket_id} escalated"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ── system.execute_command ────────────────────────────────────────────────────

async def execute_command(pool: asyncpg.Pool, arguments: dict) -> dict:
    command: str = arguments.get("command", "").strip()
    base_cmd = command.split()[0] if command else ""

    await audit.log(pool, "system.execute_command", arguments, f"attempted: {command}")

    if base_cmd not in _ALLOWED_COMMANDS:
        return {
            "status": "forbidden",
            "message": f"Command '{base_cmd}' is not in the allowed list. Only: {sorted(_ALLOWED_COMMANDS)}",
        }

    # dry-run 샌드박스 응답
    sandbox_outputs = {
        "ls": "policies.txt  runbook.md  faq.md",
        "pwd": "/app",
        "whoami": "chatbot-service",
        "date": "Sun Apr 20 00:00:00 UTC 2026",
        "echo": command.replace("echo", "").strip(),
    }
    return {"status": "sandbox", "output": sandbox_outputs.get(base_cmd, "(no output)")}


# ── file_storage.read ─────────────────────────────────────────────────────────

async def file_read(pool: asyncpg.Pool, arguments: dict) -> dict:
    path: str = arguments.get("path", "")
    await audit.log(pool, "file_storage.read", arguments, f"read {path}")

    safe_path = (_FILE_ROOT / path.lstrip("/")).resolve()
    # path traversal 방지
    if not str(safe_path).startswith(str(_FILE_ROOT)):
        return {"status": "forbidden", "message": "Path traversal not allowed"}

    if not safe_path.exists():
        return {"status": "not_found", "message": f"File not found: {path}"}

    try:
        content = safe_path.read_text(encoding="utf-8")
        return {"status": "ok", "path": path, "content": content}
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ── file_storage.write ────────────────────────────────────────────────────────

async def file_write(pool: asyncpg.Pool, arguments: dict) -> dict:
    if config.DRY_RUN:
        return {"status": "dry_run", "message": "file_storage.write skipped (dry_run mode)"}

    path: str = arguments.get("path", "")
    content: str = arguments.get("content", "")

    await audit.log(pool, "file_storage.write", arguments, f"write {path}")

    safe_path = (_FILE_ROOT / path.lstrip("/")).resolve()
    if not str(safe_path).startswith(str(_FILE_ROOT)):
        return {"status": "forbidden", "message": "Path traversal not allowed"}

    try:
        safe_path.parent.mkdir(parents=True, exist_ok=True)
        safe_path.write_text(content, encoding="utf-8")
        return {"status": "ok", "message": f"Written to {path}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ── billing.process_refund ────────────────────────────────────────────────────

async def process_refund(pool: asyncpg.Pool, arguments: dict) -> dict:
    if config.DRY_RUN:
        return {"status": "dry_run", "message": "billing.process_refund skipped (dry_run mode)"}

    order_id = arguments.get("order_id", "")
    amount = arguments.get("amount", 0)
    reason = arguments.get("reason", "")

    try:
        async with pool.acquire() as conn:
            refund_id = f"REF-{secrets.token_hex(4).upper()}"
            await conn.execute(
                """
                INSERT INTO refund_requests (refund_id, order_id, amount, reason, requested_by, approved)
                VALUES ($1, $2, $3, $4, 'chatbot', false)
                """,
                refund_id, order_id, float(amount), reason,
            )
            await conn.execute(
                "UPDATE orders SET payment_status = 'refund_pending' WHERE order_id = $1",
                order_id,
            )
        await audit.log(pool, "billing.process_refund", arguments, f"refund {refund_id} for order {order_id}")
        return {"status": "ok", "refund_id": refund_id, "message": "Refund request created (pending approval)"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ── auth.reset_password ───────────────────────────────────────────────────────

async def reset_password(pool: asyncpg.Pool, arguments: dict) -> dict:
    if config.DRY_RUN:
        return {"status": "dry_run", "message": "auth.reset_password skipped (dry_run mode)"}

    user_id = arguments.get("user_id", "")
    alphabet = string.ascii_letters + string.digits
    token = "".join(secrets.choice(alphabet) for _ in range(32))

    try:
        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO password_reset_requests (customer_id, token, expires_at, used)
                VALUES ($1, $2, NOW() + INTERVAL '1 hour', false)
                """,
                user_id, token,
            )
        await audit.log(pool, "auth.reset_password", arguments, f"reset token created for {user_id}")
        return {
            "status": "ok",
            "message": f"Reset token created for {user_id}. Email will be sent via email.send.",
            "token_hint": token[:4] + "****",
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

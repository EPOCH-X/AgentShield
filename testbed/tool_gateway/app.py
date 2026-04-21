"""
Tool Gateway API — 챗봇의 tool call을 실제 시스템에 연결한다.
POST /tools/{tool}/{action}  {"arguments": {...}}
"""

import asyncpg
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from . import config
from . import db_tools, email_tools, internal_api


# ── DB pool ───────────────────────────────────────────────────────────────────

_pool: asyncpg.Pool | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _pool
    try:
        _pool = await asyncpg.create_pool(
            dsn=config.TESTBED_DB_URL,
            min_size=2,
            max_size=10,
        )
    except Exception as e:
        print(f"[tool_gateway] DB 연결 실패 (stub 모드로 동작): {e}")
        _pool = None
    yield
    if _pool:
        await _pool.close()


app = FastAPI(title="AgentShield Tool Gateway", lifespan=lifespan)


class ToolRequest(BaseModel):
    arguments: dict = {}


def pool_or_raise() -> asyncpg.Pool:
    if _pool is None:
        raise HTTPException(status_code=503, detail="DB not connected")
    return _pool


# ── customer_db ───────────────────────────────────────────────────────────────

@app.post("/tools/customer_db/query")
async def tool_customer_db_query(req: ToolRequest):
    return await db_tools.query(pool_or_raise(), req.arguments)


@app.post("/tools/customer_db/update")
async def tool_customer_db_update(req: ToolRequest):
    return await db_tools.update(pool_or_raise(), req.arguments)


@app.post("/tools/customer_db/delete")
async def tool_customer_db_delete(req: ToolRequest):
    return await db_tools.delete(pool_or_raise(), req.arguments)


# ── email ─────────────────────────────────────────────────────────────────────

@app.post("/tools/email/send")
async def tool_email_send(req: ToolRequest):
    return await email_tools.send(pool_or_raise(), req.arguments)


# ── internal_api ──────────────────────────────────────────────────────────────

@app.post("/tools/internal_api/call")
async def tool_internal_api_call(req: ToolRequest):
    return await internal_api.internal_api_call(pool_or_raise(), req.arguments)


# ── system ────────────────────────────────────────────────────────────────────

@app.post("/tools/system/execute_command")
async def tool_system_execute_command(req: ToolRequest):
    return await internal_api.execute_command(pool_or_raise(), req.arguments)


# ── file_storage ──────────────────────────────────────────────────────────────

@app.post("/tools/file_storage/read")
async def tool_file_storage_read(req: ToolRequest):
    return await internal_api.file_read(pool_or_raise(), req.arguments)


@app.post("/tools/file_storage/write")
async def tool_file_storage_write(req: ToolRequest):
    return await internal_api.file_write(pool_or_raise(), req.arguments)


# ── billing ───────────────────────────────────────────────────────────────────

@app.post("/tools/billing/process_refund")
async def tool_billing_process_refund(req: ToolRequest):
    return await internal_api.process_refund(pool_or_raise(), req.arguments)


# ── auth ──────────────────────────────────────────────────────────────────────

@app.post("/tools/auth/reset_password")
async def tool_auth_reset_password(req: ToolRequest):
    return await internal_api.reset_password(pool_or_raise(), req.arguments)


# ── health ────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "db_connected": _pool is not None,
        "dry_run": config.DRY_RUN,
    }

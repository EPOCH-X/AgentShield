import json
import asyncpg
from . import config


async def log(
    pool: asyncpg.Pool,
    tool_name: str,
    arguments: dict,
    result_summary: str,
    actor: str = "chatbot",
    channel: str = "api",
) -> None:
    """audit_logs 테이블에 tool 호출 기록. 테이블 없으면 조용히 스킵."""
    try:
        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO audit_logs (actor, channel, tool_name, arguments_json, result_summary)
                VALUES ($1, $2, $3, $4, $5)
                """,
                actor,
                channel,
                tool_name,
                json.dumps(arguments, ensure_ascii=False),
                result_summary,
            )
    except Exception:
        pass

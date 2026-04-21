"""
email.send — Mailpit SMTP 샌드박스로 발송
"""

import asyncio
import smtplib
from email.mime.text import MIMEText

import asyncpg
from . import config, audit


async def send(pool: asyncpg.Pool, arguments: dict) -> dict:
    to_addr = arguments.get("to", "")
    subject = arguments.get("subject", "")
    body = arguments.get("body", "")

    if not to_addr:
        return {"status": "error", "message": "missing 'to' field"}

    # DB outbox 기록
    try:
        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO email_outbox (to_address, subject, body, status)
                VALUES ($1, $2, $3, 'sent')
                """,
                to_addr, subject, body,
            )
    except Exception:
        pass

    # Mailpit SMTP 발송
    try:
        await asyncio.get_event_loop().run_in_executor(
            None, _smtp_send, to_addr, subject, body
        )
        await audit.log(pool, "email.send", arguments, f"sent to {to_addr}")
        return {"status": "ok", "message": f"Email sent to {to_addr}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def _smtp_send(to_addr: str, subject: str, body: str) -> None:
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = config.MAIL_FROM
    msg["To"] = to_addr

    with smtplib.SMTP(config.MAILPIT_HOST, config.MAILPIT_SMTP_PORT, timeout=10) as s:
        s.sendmail(config.MAIL_FROM, [to_addr], msg.as_string())

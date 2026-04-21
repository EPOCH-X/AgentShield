"""[R5/R7 공통] Monitoring usage log 저장 서비스."""

from typing import Optional

import asyncio
from threading import Thread

from sqlalchemy import select

from monitoring_proxy.schemas import ActionTakenType, SeverityType, UsageLogEntry


def _run_async(coro):
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    result_box: dict[str, object] = {}

    def _runner() -> None:
        try:
            result_box["value"] = asyncio.run(coro)
        except Exception as exc:
            result_box["error"] = exc

    thread = Thread(target=_runner, daemon=True)
    thread.start()
    thread.join()

    if "error" in result_box:
        raise result_box["error"]  # type: ignore[misc]
    return result_box.get("value")


async def _ensure_employee(employee_code: str):
    from backend.database import async_session
    from backend.models import Employee

    async with async_session() as db:
        employee = await db.scalar(
            select(Employee).where(Employee.employee_id == employee_code)
        )
        if employee:
            return employee.id

        employee = Employee(
            employee_id=employee_code,
            name=employee_code,
            department="monitoring",
            role="user",
            status="active",
        )
        db.add(employee)
        await db.flush()
        employee_id = employee.id
        await db.commit()
        return employee_id


async def _persist_usage_log(entry: UsageLogEntry) -> UsageLogEntry:
    from backend.database import async_session
    from backend.models import UsageLog

    employee_id = await _ensure_employee(entry.employee_id)

    async with async_session() as db:
        row = UsageLog(
            employee_id=employee_id,
            request_content=entry.request_content,
            response_content=entry.response_content,
            target_service=(entry.target_service or "")[:50] or None,
            policy_violation=entry.policy_violation,
            severity=entry.severity,
            action_taken=entry.action_taken,
        )
        db.add(row)
        await db.flush()
        persisted = entry.model_copy(update={"id": int(row.id)})
        await db.commit()
        return persisted


def build_usage_log_entry(
    *,
    employee_id: str,
    request_content: str,
    response_content: str,
    policy_violation: Optional[str],
    severity: Optional[SeverityType],
    action_taken: ActionTakenType,
    target_service: Optional[str],
) -> UsageLogEntry:
    return UsageLogEntry(
        employee_id=employee_id,
        request_content=request_content,
        response_content=response_content,
        policy_violation=policy_violation,
        severity=severity,
        action_taken=action_taken,
        target_service=target_service,
    )


def save_usage_log(entry: UsageLogEntry) -> UsageLogEntry:
    """Persist usage log to the shared DB when available; fall back to contract-only return on failure."""

    try:
        return _run_async(_persist_usage_log(entry))
    except Exception:
        return entry

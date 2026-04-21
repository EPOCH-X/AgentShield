"""[R5/R7 공통] Monitoring violation 저장 서비스."""

from typing import Optional

import asyncio
from threading import Thread

from sqlalchemy import select

from monitoring_proxy.schemas import SeverityType, ViolationRecordInput


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


async def _ensure_employee(employee_code: Optional[str]):
    if not employee_code:
        return None

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


async def _persist_violation(record: ViolationRecordInput) -> ViolationRecordInput:
    from backend.database import async_session
    from backend.models import Violation

    employee_id = await _ensure_employee(record.employee_id)

    async with async_session() as db:
        row = Violation(
            employee_id=employee_id,
            violation_type=record.violation_type,
            severity=record.severity or "medium",
            description=record.description,
            evidence_log_id=record.evidence_log_id,
            sanction=record.sanction or "blocked",
            resolved=record.resolved,
        )
        db.add(row)
        await db.flush()
        persisted = record.model_copy(update={"id": int(row.id)})
        await db.commit()
        return persisted


def build_violation_record_input(
    *,
    employee_id: Optional[str] = None,
    violation_type: str,
    severity: Optional[SeverityType],
    description: str,
    evidence: Optional[str] = None,
    evidence_log_id: Optional[int] = None,
    reference: Optional[str] = None,
    sanction: Optional[str] = None,
) -> ViolationRecordInput:
    return ViolationRecordInput(
        employee_id=employee_id,
        violation_type=violation_type,
        severity=severity,
        description=description,
        evidence=evidence,
        evidence_log_id=evidence_log_id,
        reference=reference,
        sanction=sanction,
    )


def create_violation_record(record: ViolationRecordInput) -> ViolationRecordInput:
    """Persist violation record to the shared DB when available; fall back to contract-only return on failure."""

    try:
        return _run_async(_persist_violation(record))
    except Exception:
        return record

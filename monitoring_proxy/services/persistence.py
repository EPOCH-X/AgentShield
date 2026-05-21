"""
UsageLog + Violation DB 저장.

monitor_server.process_monitor_request 는 FastAPI route 안에서 동기 호출되므로
async 세션을 nested로 못 쓴다. 짧은 수명의 sync engine으로 격리해서 INSERT.
employee_id 문자열은 Employee 테이블 lookup → UUID로 매핑하고 없으면 자동 INSERT.
"""

from __future__ import annotations

import logging
from functools import lru_cache
from typing import Optional
from uuid import UUID

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from backend.db_urls import make_sync_database_url
from monitoring_proxy.schemas import UsageLogEntry, ViolationRecordInput

logger = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def _sync_engine():
    from backend.config import settings
    sync_url = make_sync_database_url(settings.DATABASE_URL)
    return create_engine(sync_url, pool_pre_ping=True, future=True)


def _resolve_employee_uuid(db: Session, employee_id_str: str) -> Optional[UUID]:
    """문자열 employee_id → Employee.id (UUID). 없으면 자동 생성."""
    from backend.models.employee import Employee

    emp = db.scalar(select(Employee).where(Employee.employee_id == employee_id_str))
    if emp:
        return emp.id
    new_emp = Employee(
        employee_id=employee_id_str,
        name=employee_id_str,
        department="unknown",
        role="user",
        status="active",
    )
    db.add(new_emp)
    db.flush()
    return new_emp.id


def save_usage_log(entry: UsageLogEntry) -> UsageLogEntry:
    """UsageLog INSERT. 반환된 entry.id 는 evidence_log_id 로 사용된다."""
    from backend.models.usage_log import UsageLog

    try:
        with Session(_sync_engine()) as db:
            emp_uuid = _resolve_employee_uuid(db, entry.employee_id)
            log = UsageLog(
                employee_id=emp_uuid,
                request_content=entry.request_content,
                response_content=entry.response_content,
                target_service=entry.target_service,
                policy_violation=entry.policy_violation,
                severity=entry.severity,
                action_taken=entry.action_taken,
            )
            db.add(log)
            db.commit()
            db.refresh(log)
            return entry.model_copy(update={"id": log.id})
    except Exception:
        logger.exception("[monitoring_proxy] UsageLog 저장 실패 (모니터링 응답에는 영향 없음)")
        return entry


def create_violation_record(record: ViolationRecordInput) -> ViolationRecordInput:
    """Violation INSERT. employee_id 가 비면 자동 등록 후 FK 사용."""
    from backend.models.violation import Violation

    try:
        with Session(_sync_engine()) as db:
            emp_uuid = (
                _resolve_employee_uuid(db, record.employee_id)
                if record.employee_id
                else None
            )
            v = Violation(
                employee_id=emp_uuid,
                violation_type=record.violation_type,
                severity=record.severity or "medium",
                description=record.description,
                evidence_log_id=record.evidence_log_id,
                sanction=record.sanction,
                resolved=record.resolved,
            )
            db.add(v)
            db.commit()
            db.refresh(v)
            return record.model_copy(update={"id": v.id})
    except Exception:
        logger.exception("[monitoring_proxy] Violation 저장 실패 (모니터링 응답에는 영향 없음)")
        return record

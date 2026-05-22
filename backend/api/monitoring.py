"""
[R5] 모니터링 API — 직원 AI 사용 모니터링
"""

from datetime import date
import logging
import os
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from backend.config import settings
from backend.database import get_db
from backend.api.auth import get_current_user, UserInfo
from backend.models import Employee, Violation, PolicyRule, UsageLog
from monitoring_proxy.monitor_server import (
    MonitorChatRequest as ProxyMonitorChatRequest,
    MonitorChatResponse as ProxyMonitorChatResponse,
    process_monitor_request_with_dependencies,
)
from monitoring_proxy.schemas import UsageLogEntry, ViolationRecordInput
from monitoring_proxy.services import get_default_intent_review_llm_client

logger = logging.getLogger(__name__)
router = APIRouter()


DEFAULT_MONITORING_TARGET_URL = os.getenv(
    "MONITORING_TARGET_URL",
    os.getenv("TESTBED_CHAT_URL", "http://127.0.0.1:8010/chat"),
)


class MonitoringAuditBuffer:
    """Collect audit records emitted by the pure monitoring proxy pipeline."""

    def __init__(self) -> None:
        self.usage_logs: list[UsageLogEntry] = []
        self.violations: list[ViolationRecordInput] = []

    def save_usage_log(self, entry: UsageLogEntry) -> UsageLogEntry:
        local_id = entry.id if entry.id is not None else -(len(self.usage_logs) + 1)
        captured = entry.model_copy(update={"id": local_id})
        self.usage_logs.append(captured)
        return captured

    def create_violation_record(self, record: ViolationRecordInput) -> ViolationRecordInput:
        self.violations.append(record)
        return record


def _normalize_employee_id(employee_id: str) -> str:
    value = (employee_id or "").strip()
    if not value or len(value) > 50 or any(ord(ch) < 32 for ch in value):
        raise ValueError("invalid employee_id")
    return value


async def _resolve_employee_uuid(db: AsyncSession, employee_id: str):
    normalized = _normalize_employee_id(employee_id)
    emp = await db.scalar(select(Employee).where(Employee.employee_id == normalized))
    if emp:
        return emp.id

    emp = Employee(
        employee_id=normalized,
        name=normalized,
        department="unknown",
        role="user",
        status="active",
    )
    db.add(emp)
    await db.flush()
    return emp.id


async def _persist_monitoring_audit_records(
    db: AsyncSession,
    audit: MonitoringAuditBuffer,
) -> None:
    """Persist monitoring audit records through the same DB session as reads."""
    if not audit.usage_logs and not audit.violations:
        return

    local_log_ids: dict[int, int] = {}
    last_log_id: int | None = None

    for entry in audit.usage_logs:
        emp_uuid = await _resolve_employee_uuid(db, entry.employee_id)
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
        await db.flush()
        if entry.id is not None:
            local_log_ids[entry.id] = log.id
        last_log_id = log.id

    for record in audit.violations:
        emp_uuid = (
            await _resolve_employee_uuid(db, record.employee_id)
            if record.employee_id
            else None
        )
        evidence_log_id = record.evidence_log_id
        if evidence_log_id is not None and evidence_log_id in local_log_ids:
            evidence_log_id = local_log_ids[evidence_log_id]
        elif evidence_log_id is None:
            evidence_log_id = last_log_id

        violation = Violation(
            employee_id=emp_uuid,
            violation_type=record.violation_type,
            severity=record.severity or "medium",
            description=record.description,
            evidence_log_id=evidence_log_id,
            sanction=record.sanction,
            resolved=record.resolved,
        )
        db.add(violation)

    await db.commit()


# ── 대시보드 ──────────────────────────────────────────────────────────────────

@router.get("/dashboard")
async def monitoring_dashboard(
    db: AsyncSession = Depends(get_db),
    user: UserInfo = Depends(get_current_user),
):
    today = date.today()

    daily = await db.scalar(
        select(func.count()).select_from(UsageLog)
        .where(func.date(UsageLog.request_at) == today)
    ) or 0

    vcount   = await db.scalar(select(func.count()).select_from(Violation)) or 0
    blocked  = await db.scalar(
        select(func.count()).select_from(Violation).where(Violation.sanction == "blocked")
    ) or 0
    active   = await db.scalar(
        select(func.count()).select_from(Employee).where(Employee.status == "active")
    ) or 0
    total    = await db.scalar(select(func.count()).select_from(Employee)) or 0

    return {
        "daily_requests":   daily,
        "violations_count": vcount,
        "blocked_count":    blocked,
        "active_employees": active,
        "total_employees":  total,
    }


# ── 위반 목록 ─────────────────────────────────────────────────────────────────

@router.get("/violations")
async def list_violations(
    department:     Optional[str] = None,
    violation_type: Optional[str] = None,
    db:   AsyncSession = Depends(get_db),
    user: UserInfo     = Depends(get_current_user),
):
    q = (
        select(Violation, Employee)
        .outerjoin(Employee, Violation.employee_id == Employee.id)
        .order_by(Violation.created_at.desc())
    )
    if department:
        q = q.where(Employee.department == department)
    if violation_type:
        q = q.where(Violation.violation_type == violation_type)

    rows = (await db.execute(q)).all()
    return [
        {
            "id":             v.id,
            "employee_id":    e.employee_id if e else None,
            "employee_name":  e.name        if e else None,
            "department":     e.department  if e else None,
            "violation_type": v.violation_type,
            "severity":       v.severity,
            "description":    v.description,
            "sanction":       v.sanction,
            "resolved":       v.resolved,
            "created_at":     v.created_at.isoformat() if v.created_at else None,
        }
        for v, e in rows
    ]


@router.get("/violations/{violation_id}/context")
async def violation_context(
    violation_id: int,
    db: AsyncSession = Depends(get_db),
    user: UserInfo = Depends(get_current_user),
):
    """위반 1건의 채팅 기록(요청/응답 원문)과 메타. 상세 드로어에서 사용."""
    v = await db.get(Violation, violation_id)
    if not v:
        raise HTTPException(status_code=404, detail="위반 내역을 찾을 수 없습니다.")

    emp = await db.get(Employee, v.employee_id) if v.employee_id else None
    log = await db.get(UsageLog, v.evidence_log_id) if v.evidence_log_id else None

    return {
        "violation": {
            "id":             v.id,
            "violation_type": v.violation_type,
            "severity":       v.severity,
            "description":    v.description,
            "sanction":       v.sanction,
            "resolved":       v.resolved,
            "created_at":     v.created_at.isoformat() if v.created_at else None,
        },
        "employee": {
            "employee_id": emp.employee_id if emp else None,
            "name":        emp.name        if emp else None,
            "department":  emp.department  if emp else None,
            "role":        emp.role        if emp else None,
        } if emp else None,
        "chat": {
            "request_content":  log.request_content  if log else None,
            "response_content": log.response_content if log else None,
            "action_taken":     log.action_taken     if log else None,
            "target_service":   log.target_service   if log else None,
            "request_at":       log.request_at.isoformat() if log and log.request_at else None,
        } if log else None,
    }


@router.patch("/violations/{violation_id}/resolve")
async def resolve_violation(
    violation_id: int,
    db: AsyncSession = Depends(get_db),
    user: UserInfo = Depends(get_current_user),
):
    """검토 완료 처리 — 상세 드로어에서 호출."""
    v = await db.get(Violation, violation_id)
    if not v:
        raise HTTPException(status_code=404, detail="위반 내역을 찾을 수 없습니다.")
    v.resolved = True
    await db.commit()
    return {"id": v.id, "resolved": v.resolved}


# ── 직원 목록 ─────────────────────────────────────────────────────────────────

@router.get("/employees")
async def list_employees(
    db:   AsyncSession = Depends(get_db),
    user: UserInfo     = Depends(get_current_user),
):
    rows = (await db.scalars(select(Employee).order_by(Employee.created_at))).all()
    return [
        {
            "id":          str(e.id),
            "employee_id": e.employee_id,
            "name":        e.name,
            "department":  e.department,
            "role":        e.role,
            "status":      e.status,
        }
        for e in rows
    ]


@router.get("/employee/{employee_id}")
async def employee_detail(
    employee_id: str,
    db:   AsyncSession = Depends(get_db),
    user: UserInfo     = Depends(get_current_user),
):
    emp = await db.scalar(select(Employee).where(Employee.employee_id == employee_id))
    if not emp:
        raise HTTPException(status_code=404, detail="직원을 찾을 수 없습니다")

    violations = (
        await db.scalars(
            select(Violation)
            .where(Violation.employee_id == emp.id)
            .order_by(Violation.created_at.desc())
        )
    ).all()

    logs = (
        await db.scalars(
            select(UsageLog)
            .where(UsageLog.employee_id == emp.id)
            .order_by(UsageLog.request_at.desc())
            .limit(50)
        )
    ).all()

    return {
        "employee": {
            "id":          str(emp.id),
            "employee_id": emp.employee_id,
            "name":        emp.name,
            "department":  emp.department,
            "role":        emp.role,
            "status":      emp.status,
        },
        "violations": [
            {
                "id":             v.id,
                "violation_type": v.violation_type,
                "severity":       v.severity,
                "description":    v.description,
                "sanction":       v.sanction,
                "resolved":       v.resolved,
                "created_at":     v.created_at.isoformat() if v.created_at else None,
            }
            for v in violations
        ],
        "recent_logs": [
            {
                "id":              l.id,
                "request_content": l.request_content,
                "policy_violation":l.policy_violation,
                "action_taken":    l.action_taken,
                "request_at":      l.request_at.isoformat() if l.request_at else None,
            }
            for l in logs
        ],
    }


# ── 정책 ──────────────────────────────────────────────────────────────────────

class PolicyCreate(BaseModel):
    rule_name: str
    rule_type: str = "keyword"
    pattern:   str = ""
    severity:  str = "medium"
    action:    str = "warn"


class PolicyUpdate(BaseModel):
    """부분 업데이트 — None이 아닌 필드만 갱신. is_active 토글 + 메타 수정 모두 지원."""
    rule_name: Optional[str] = None
    rule_type: Optional[str] = None
    pattern:   Optional[str] = None
    severity:  Optional[str] = None
    action:    Optional[str] = None
    is_active: Optional[bool] = None


def _policy_dict(p: PolicyRule) -> dict:
    return {
        "id":         p.id,
        "rule_name":  p.rule_name,
        "rule_type":  p.rule_type,
        "pattern":    p.pattern,
        "severity":   p.severity,
        "action":     p.action,
        "is_active":  p.is_active,
        "created_at": p.created_at.isoformat() if p.created_at else None,
    }


@router.get("/policies")
async def list_policies(
    db:   AsyncSession = Depends(get_db),
    user: UserInfo     = Depends(get_current_user),
):
    rows = (await db.scalars(select(PolicyRule).order_by(PolicyRule.created_at))).all()
    return [_policy_dict(p) for p in rows]


async def _audit_policy_action(
    db: AsyncSession,
    *,
    actor: str,
    action: str,
    request: Optional[Request],
    rule: PolicyRule,
    detail: Optional[str] = None,
) -> None:
    """정책 CRUD 액션을 audit_logs에 기록 — 보안팀이 누가 언제 어떤 룰을 만들었는지 추적."""
    from backend.models.audit_log import AuditLog
    try:
        ip = request.client.host if request and request.client else None
        ua = request.headers.get("user-agent") if request else None
        async with db.begin_nested():
            db.add(AuditLog(
                actor=actor[:100],
                action=action[:50],
                resource=f"policy_rule:{rule.id}",
                ip_address=ip,
                user_agent=ua[:255] if ua else None,
                detail=detail or f"name={rule.rule_name} severity={rule.severity} action={rule.action} active={rule.is_active}",
            ))
    except Exception:
        logger.exception("[monitoring] policy audit log insert failed (non-fatal)")


def _invalidate_policy_cache_safe() -> None:
    """모니터링 프록시 룰 캐시를 즉시 비워서 다음 요청부터 새 룰 반영."""
    try:
        from monitoring_proxy.policies._db import invalidate_policy_cache
        invalidate_policy_cache()
    except Exception:
        logger.exception("[monitoring] policy cache invalidate failed (non-fatal)")


@router.post("/policies", status_code=201)
async def create_policy(
    body: PolicyCreate,
    request: Request,
    db:   AsyncSession = Depends(get_db),
    user: UserInfo     = Depends(get_current_user),
):
    if not body.rule_name.strip():
        raise HTTPException(status_code=422, detail="rule_name이 필요합니다.")

    rule = PolicyRule(
        rule_name=body.rule_name,
        rule_type=body.rule_type,
        pattern=body.pattern,
        severity=body.severity,
        action=body.action,
        is_active=True,
    )
    db.add(rule)
    await db.flush()
    await _audit_policy_action(db, actor=user.username, action="policy_create", request=request, rule=rule)
    await db.commit()
    await db.refresh(rule)
    _invalidate_policy_cache_safe()
    return _policy_dict(rule)


@router.patch("/policies/{policy_id}")
async def update_policy(
    policy_id: int,
    body: PolicyUpdate,
    request: Request,
    db:   AsyncSession = Depends(get_db),
    user: UserInfo     = Depends(get_current_user),
):
    """is_active 토글 + 룰 메타 수정. None이 아닌 필드만 갱신."""
    rule = await db.get(PolicyRule, policy_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="해당 정책을 찾을 수 없습니다.")

    changes: list[str] = []
    if body.rule_name is not None:
        if not body.rule_name.strip():
            raise HTTPException(status_code=422, detail="rule_name이 비어 있을 수 없습니다.")
        changes.append(f"rule_name:{rule.rule_name}→{body.rule_name}")
        rule.rule_name = body.rule_name
    if body.rule_type is not None:
        changes.append(f"rule_type:{rule.rule_type}→{body.rule_type}")
        rule.rule_type = body.rule_type
    if body.pattern is not None:
        changes.append("pattern_updated")
        rule.pattern = body.pattern
    if body.severity is not None:
        changes.append(f"severity:{rule.severity}→{body.severity}")
        rule.severity = body.severity
    if body.action is not None:
        changes.append(f"action:{rule.action}→{body.action}")
        rule.action = body.action
    if body.is_active is not None:
        changes.append(f"is_active:{rule.is_active}→{body.is_active}")
        rule.is_active = body.is_active

    if not changes:
        return _policy_dict(rule)

    await _audit_policy_action(
        db,
        actor=user.username,
        action="policy_update",
        request=request,
        rule=rule,
        detail="; ".join(changes),
    )
    await db.commit()
    await db.refresh(rule)
    _invalidate_policy_cache_safe()
    return _policy_dict(rule)


@router.delete("/policies/{policy_id}", status_code=204)
async def delete_policy(
    policy_id: int,
    request: Request,
    db:   AsyncSession = Depends(get_db),
    user: UserInfo     = Depends(get_current_user),
):
    rule = await db.get(PolicyRule, policy_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="해당 정책을 찾을 수 없습니다.")

    await _audit_policy_action(
        db,
        actor=user.username,
        action="policy_delete",
        request=request,
        rule=rule,
        detail=f"deleted name={rule.rule_name} severity={rule.severity} action={rule.action}",
    )
    await db.delete(rule)
    await db.commit()
    _invalidate_policy_cache_safe()
    return None


# ── 모니터링 프록시 채팅 ──────────────────────────────────────────────────────

@router.post("/chat", response_model=ProxyMonitorChatResponse)
async def monitored_chat(
    body: ProxyMonitorChatRequest,
    db: AsyncSession = Depends(get_db),
    user: UserInfo = Depends(get_current_user),
):
    """
    Dashboard 1:1 chatbot traffic through the monitoring proxy.

    The proxy checks input policy, forwards allowed traffic to the configured
    target LLM, masks the output, and emits usage/violation records. The API
    route owns persistence so dashboard reads and writes always use the same
    AgentShield application database.
    """

    updates = {"employee_id": user.username}
    if settings.MONITORING_ALLOW_CLIENT_TARGET_URLS:
        if not body.target_url:
            updates["target_url"] = DEFAULT_MONITORING_TARGET_URL
    else:
        updates["target_url"] = DEFAULT_MONITORING_TARGET_URL
        updates["target_api_key"] = None
        updates["target_provider"] = None
        updates["target_model"] = None
    body = body.model_copy(update=updates)

    audit = MonitoringAuditBuffer()
    response = process_monitor_request_with_dependencies(
        body,
        llm_client_factory=get_default_intent_review_llm_client,
        save_usage_log_fn=audit.save_usage_log,
        create_violation_record_fn=audit.create_violation_record,
    )

    try:
        await _persist_monitoring_audit_records(db, audit)
    except (SQLAlchemyError, ValueError):
        await db.rollback()
        logger.exception("[monitoring] audit persistence failed")
        raise HTTPException(status_code=500, detail="모니터링 감사 로그 저장에 실패했습니다.")

    return response

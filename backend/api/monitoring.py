"""
[R5] 모니터링 API — 직원 AI 사용 모니터링
"""

from datetime import date
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.api.auth import get_current_user, UserInfo
from backend.models import Employee, Violation, PolicyRule, UsageLog

router = APIRouter()


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


@router.post("/policies", status_code=201)
async def create_policy(
    body: PolicyCreate,
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
    await db.commit()
    await db.refresh(rule)
    return _policy_dict(rule)

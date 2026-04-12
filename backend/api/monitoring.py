"""
[R5] 모니터링 API — 직원 AI 사용 모니터링
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.api.auth import get_current_user, get_current_admin, UserInfo

router = APIRouter()


@router.get("/dashboard")
async def monitoring_dashboard(
    user: UserInfo = Depends(get_current_user),
):
    """모니터링 요약 통계"""
    # TODO: [R5] 오늘 총 요청 수, 위반 수, 차단 수
    raise NotImplementedError("대시보드 미구현")


@router.get("/violations")
async def list_violations(
    department: str | None = None,
    violation_type: str | None = None,
    db: AsyncSession = Depends(get_db),
    user: UserInfo = Depends(get_current_user),
):
    """위반 목록 조회"""
    # TODO: [R5] violations 테이블 필터 조회
    raise NotImplementedError("위반 목록 미구현")


@router.get("/employees")
async def list_employees(
    db: AsyncSession = Depends(get_db),
    user: UserInfo = Depends(get_current_admin),
):
    """직원 목록 조회 (관리자 전용)"""
    # TODO: [R5] employees 테이블 조회
    raise NotImplementedError("직원 목록 미구현")


@router.get("/employee/{employee_id}")
async def employee_detail(
    employee_id: str,
    db: AsyncSession = Depends(get_db),
    user: UserInfo = Depends(get_current_admin),
):
    """직원 상세 — 사용 이력 + 위반 이력"""
    # TODO: [R5] usage_logs + violations 조회
    raise NotImplementedError("직원 상세 미구현")


@router.get("/policies")
async def list_policies(
    db: AsyncSession = Depends(get_db),
    user: UserInfo = Depends(get_current_admin),
):
    """정책 규칙 목록"""
    # TODO: [R5] policy_rules 조회
    raise NotImplementedError("정책 목록 미구현")


@router.post("/policies")
async def create_policy(
    db: AsyncSession = Depends(get_db),
    user: UserInfo = Depends(get_current_admin),
):
    """정책 규칙 생성"""
    # TODO: [R5] policy_rules INSERT
    raise NotImplementedError("정책 생성 미구현")

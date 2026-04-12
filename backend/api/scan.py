"""
[R7] 스캔 API — Phase 1~4 실행 엔드포인트
"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.api.auth import get_current_user, UserInfo

router = APIRouter()


class ScanRequest(BaseModel):
    target_url: str
    project_name: str = ""


class ScanResponse(BaseModel):
    session_id: str
    status: str


@router.post("/llm-security", response_model=ScanResponse)
async def start_scan(
    req: ScanRequest,
    db: AsyncSession = Depends(get_db),
    user: UserInfo = Depends(get_current_user),
):
    """보안 스캔 시작 — Phase 1→2→3→4 파이프라인 실행"""
    # TODO: [R2] Phase 1 + [R1] Phase 2 + [R3] Phase 3/4 구현 후 연결
    raise NotImplementedError("스캔 파이프라인 미구현")


@router.get("/{session_id}/status")
async def scan_status(
    session_id: str,
    db: AsyncSession = Depends(get_db),
    user: UserInfo = Depends(get_current_user),
):
    """현재 스캔 상태 + 통계 조회"""
    # TODO: [R7] test_sessions에서 상태 조회
    raise NotImplementedError("스캔 상태 조회 미구현")


@router.get("/{session_id}/results")
async def scan_results(
    session_id: str,
    category: str | None = None,
    severity: str | None = None,
    phase: int | None = None,
    db: AsyncSession = Depends(get_db),
    user: UserInfo = Depends(get_current_user),
):
    """취약점 목록 조회 (필터: category, severity, phase)"""
    # TODO: [R7] test_results 필터 조회
    raise NotImplementedError("결과 조회 미구현")


@router.get("/{session_id}/results/{result_id}")
async def scan_result_detail(
    session_id: str,
    result_id: int,
    db: AsyncSession = Depends(get_db),
    user: UserInfo = Depends(get_current_user),
):
    """취약점 상세 + 방어 코드 조회"""
    # TODO: [R7] test_result 단건 조회
    raise NotImplementedError("결과 상세 미구현")

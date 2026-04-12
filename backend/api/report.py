"""
[R7] 보고서 API — PDF 생성/다운로드
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.api.auth import get_current_user, UserInfo

router = APIRouter()


@router.get("/{session_id}/pdf")
async def download_report(
    session_id: str,
    db: AsyncSession = Depends(get_db),
    user: UserInfo = Depends(get_current_user),
):
    """보고서 PDF 다운로드"""
    # TODO: [R7] report/generator.py 연동
    raise NotImplementedError("보고서 생성 미구현")

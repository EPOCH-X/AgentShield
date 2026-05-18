"""
Phase 5 policy package export API.
"""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.auth import UserInfo, get_current_user
from backend.core.phase5_policy_export import PROJECT_ROOT, export_policy_package
from backend.database import get_db


router = APIRouter()


@router.post("/{session_id}")
async def create_policy_package(
    session_id: str,
    db: AsyncSession = Depends(get_db),
    user: UserInfo = Depends(get_current_user),
):
    try:
        UUID(session_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다")

    try:
        result = await export_policy_package(db, session_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다")

    return result.model_dump(mode="json")


@router.get("/{session_id}/download")
async def download_policy_package(
    session_id: str,
    user: UserInfo = Depends(get_current_user),
):
    try:
        UUID(session_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다")

    zip_path = PROJECT_ROOT / "data" / "policy_packages" / f"{session_id}.zip"
    if not zip_path.exists():
        raise HTTPException(status_code=404, detail="정책 패키지를 먼저 생성해야 합니다")

    return FileResponse(
        path=zip_path,
        media_type="application/zip",
        filename=f"agentshield-policy-package-{session_id[:8]}.zip",
    )


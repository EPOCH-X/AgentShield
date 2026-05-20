"""
Phase 5 policy package export API.
"""

from __future__ import annotations

import json
from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.auth import UserInfo, get_current_user
from backend.core.phase5_policy_export import PROJECT_ROOT, export_policy_package
from backend.core import owasp_guidance
from backend.database import get_db


router = APIRouter()


@router.get("/guidance")
async def get_owasp_guidance(user: UserInfo = Depends(get_current_user)):
    """OWASP LLM Top 10 권고 (data/owasp_guidance.yaml). 대시보드 ACTION_GUIDE의 단일 소스."""
    return {
        "source": owasp_guidance.get_source(),
        "categories": owasp_guidance.all_categories(),
    }


def _package_dir(session_id: str) -> Path:
    return PROJECT_ROOT / "data" / "policy_packages" / session_id


def _read_json(path: Path):
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


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


@router.get("/{session_id}")
async def get_policy_package(
    session_id: str,
    user: UserInfo = Depends(get_current_user),
):
    """이미 export 된 정책 패키지 메타데이터를 반환. 없으면 404."""
    try:
        UUID(session_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다")

    pkg = _package_dir(session_id)
    manifest = _read_json(pkg / "manifest.json")
    if manifest is None:
        raise HTTPException(status_code=404, detail="정책 패키지가 아직 생성되지 않았습니다")

    zip_path = pkg.parent / f"{session_id}.zip"
    reports_manifest = _read_json(pkg / "reports_manifest.json") or {}
    base = f"/api/v1/policy-export/{session_id}"
    reports_links = {}
    for key, filename in reports_manifest.items():
        if filename:
            reports_links[key] = f"{base}/report/{filename}"
    return {
        "session_id": session_id,
        "manifest": manifest,
        "middleware_policy": _read_json(pkg / "middleware_policy.json"),
        "masking_rules": _read_json(pkg / "masking_rules.json"),
        "refusal_templates": _read_json(pkg / "refusal_templates.json"),
        "regression_tests": _read_json(pkg / "regression_tests.json"),
        "validation": _read_json(pkg / "validation_result.json"),
        "zip_available": zip_path.exists(),
        "download_url": f"{base}/download" if zip_path.exists() else None,
        "reports": reports_links,
    }


@router.get("/{session_id}/report/{filename}")
async def download_policy_report(
    session_id: str,
    filename: str,
    user: UserInfo = Depends(get_current_user),
):
    """외부 공유용 PDF/HTML 다운로드 (마스킹 적용 사본)."""
    try:
        UUID(session_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다")
    # 경로 탈주 방지 — basename만 허용
    safe_name = Path(filename).name
    if safe_name != filename or not safe_name.endswith((".pdf", ".html")):
        raise HTTPException(status_code=400, detail="유효하지 않은 파일명")
    file_path = _package_dir(session_id) / "reports" / safe_name
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="해당 보고서 파일이 없습니다")
    media = "application/pdf" if safe_name.endswith(".pdf") else "text/html"
    return FileResponse(path=file_path, media_type=media, filename=f"agentshield-{session_id[:8]}-{safe_name}")


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


"""
[R7] 보고서 API — PDF 생성/다운로드
"""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.api.auth import get_current_user, UserInfo
from backend.models import TestSession, TestResult

router = APIRouter()


def _build_mock_pdf(session_id: str, results: list) -> bytes:
    """최소 유효 PDF — 스캔 결과 요약 텍스트 포함"""
    vulnerable = [r for r in results if r.judgment == "vulnerable"]
    safe       = [r for r in results if r.judgment == "safe"]

    lines = [
        f"AgentShield Security Report",
        f"Session: {session_id}",
        f"Total Tests: {len(results)}  Vulnerable: {len(vulnerable)}  Safe: {len(safe)}",
        "",
    ]
    for r in results:
        lines.append(f"[Phase {r.phase}] {r.category} | {r.severity} | {r.judgment}")
        lines.append(f"  Prompt: {(r.attack_prompt or '')[:80]}")
        lines.append("")

    body_text = " ".join(
        f"({l.replace('(', '').replace(')', '').replace('[', '').replace(']', '')})"
        for l in lines
    )

    stream = f"BT /F1 10 Tf 40 750 Td 12 TL {body_text} ET"
    pdf = (
        "%PDF-1.4\n"
        "1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        "2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        f"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]"
        f"/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>endobj\n"
        f"4 0 obj<</Length {len(stream)}>>stream\n{stream}\nendstream\nendobj\n"
        "5 0 obj<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>endobj\n"
        "xref\n0 6\n"
        "0000000000 65535 f \n"
        "0000000009 00000 n \n"
        "0000000058 00000 n \n"
        "0000000115 00000 n \n"
        "0000000300 00000 n \n"
        "0000000420 00000 n \n"
        f"trailer<</Size 6/Root 1 0 R>>\nstartxref\n500\n%%EOF\n"
    )
    return pdf.encode("latin-1", errors="replace")


@router.get("/{session_id}/pdf")
async def download_report(
    session_id: str,
    db:   AsyncSession = Depends(get_db),
    user: UserInfo     = Depends(get_current_user),
):
    try:
        sid = UUID(session_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다")

    sess = await db.scalar(select(TestSession).where(TestSession.id == sid))
    if not sess:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다")

    results = (
        await db.scalars(
            select(TestResult)
            .where(TestResult.session_id == sid)
            .order_by(TestResult.id)
        )
    ).all()

    pdf_bytes = _build_mock_pdf(session_id, list(results))
    filename  = f"agentshield-report-{session_id[:8]}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

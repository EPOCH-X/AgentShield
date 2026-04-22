"""
[R7 담당 / 실연결 보강: Copilot] 스캔 API — Phase 1~4 실행 엔드포인트
"""

from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.graph.llm_security_graph import run_scan
from backend.api.auth import get_current_user, UserInfo
from backend.models import TestSession, TestResult

router = APIRouter()


class ScanRequest(BaseModel):
    target_url:   str
    project_name: str = ""
    target_api_key: Optional[str] = None
    target_provider: Optional[str] = None
    target_model: Optional[str] = None


class ScanResponse(BaseModel):
    session_id: str
    status:     str


def _result_dict(r: TestResult, session_id: str) -> dict:
    return {
        "id":            r.id,
        "session_id":    session_id,
        "phase":         r.phase,
        "attack_prompt": r.attack_prompt,
        "target_response": r.target_response,
        "judgment":      r.judgment,
        "manual_review_needed": r.manual_review_needed,
        "severity":      r.severity,
        "category":      r.category,
        "defense_code":  r.defense_code,
        "verify_result": r.verify_result,
        "created_at":    r.created_at.isoformat() if r.created_at else None,
    }


def _build_target_config(req: ScanRequest) -> dict[str, Any]:
    return {
        "api_key": req.target_api_key,
        "provider": req.target_provider,
        "model": req.target_model,
    }


async def _persist_phase1_results(
    db: AsyncSession,
    *,
    session_id: Any,
    phase1_result: dict[str, Any],
) -> None:
    rows: list[TestResult] = []
    seen_keys: set[tuple[Any, ...]] = set()

    for bucket_name in ("safe_attacks", "vulnerable_attacks", "ambiguous_attacks", "error_attacks"):
        for result in phase1_result.get(bucket_name, []):
            row_key = (
                result.get("attack_pattern_id"),
                result.get("seed_id"),
                result.get("attack_prompt"),
                result.get("judgment"),
            )
            if row_key in seen_keys:
                continue
            seen_keys.add(row_key)

            rows.append(
                TestResult(
                    session_id=session_id,
                    phase=1,
                    attack_pattern_id=result.get("attack_pattern_id"),
                    seed_id=result.get("seed_id"),
                    attack_prompt=result.get("attack_prompt"),
                    target_response=result.get("target_response"),
                    judgment=result.get("judgment"),
                    judgment_layer=result.get("judgment_layer") or result.get("judge_layer"),
                    judgment_confidence=result.get("judgment_confidence"),
                    manual_review_needed=result.get("manual_review_needed", result.get("manual_review", False)),
                    severity=result.get("severity"),
                    category=result.get("category"),
                    subcategory=result.get("subcategory"),
                    detail=result.get("detail"),
                )
            )
    db.add_all(rows)
    await db.flush()


async def _persist_phase4_summary(
    db: AsyncSession,
    *,
    session_id: Any,
    phase4_result: dict[str, Any],
) -> None:
    rows: list[TestResult] = []
    for item in phase4_result.get("details", []):
        rows.append(
            TestResult(
                session_id=session_id,
                phase=4,
                seed_id=str(item.get("defense_id") or ""),
                attack_prompt=str(item.get("defense_id") or "phase4-check"),
                target_response=str(item.get("input_action") or ""),
                judgment="safe" if item.get("verdict") in {"blocked", "mitigated"} else "vulnerable",
                severity="medium",
                category=item.get("category"),
                detail=str(item.get("source_file") or ""),
                verify_result=item.get("verdict"),
            )
        )
    db.add_all(rows)
    await db.flush()


@router.post("/llm-security", response_model=ScanResponse)
async def start_scan(
    req:  ScanRequest,
    db:   AsyncSession = Depends(get_db),
    user: UserInfo     = Depends(get_current_user),
):
    """보안 스캔 시작 — 실제 Phase 1~4 그래프를 실행하고 결과를 저장한다."""
    now = datetime.utcnow()

    session = TestSession(
        target_api_url=req.target_url,
        project_name=req.project_name or "LLM Security Scan",
        status="running",
    )
    db.add(session)
    await db.flush()  # session.id 확정
    await db.commit()

    try:
        final_state = await run_scan(
            session_id=str(session.id),
            target_url=req.target_url,
            target_config=_build_target_config(req),
        )

        await db.refresh(session)
        await _persist_phase1_results(
            db,
            session_id=session.id,
            phase1_result=final_state.get("phase1_result") or {},
        )
        await _persist_phase4_summary(
            db,
            session_id=session.id,
            phase4_result=final_state.get("phase4_result") or {},
        )

        session.status = "completed"
        session.completed_at = datetime.utcnow()
        await db.commit()
        return ScanResponse(session_id=str(session.id), status="completed")
    except Exception as exc:
        await db.refresh(session)
        session.status = "failed"
        session.completed_at = datetime.utcnow()
        await db.commit()
        raise HTTPException(status_code=500, detail=f"scan execution failed: {exc}")


@router.get("/{session_id}/status")
async def scan_status(
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

    total      = await db.scalar(
        select(func.count()).select_from(TestResult).where(TestResult.session_id == sid)
    ) or 0
    vulnerable = await db.scalar(
        select(func.count()).select_from(TestResult)
        .where(TestResult.session_id == sid, TestResult.judgment == "vulnerable")
    ) or 0
    max_phase  = await db.scalar(
        select(func.max(TestResult.phase)).where(TestResult.session_id == sid)
    ) or 1
    verify_count = await db.scalar(
        select(func.count()).select_from(TestResult)
        .where(TestResult.session_id == sid, TestResult.verify_result.is_not(None))
    ) or 0
    defense_count = await db.scalar(
        select(func.count()).select_from(TestResult)
        .where(TestResult.session_id == sid, TestResult.defense_code.is_not(None))
    ) or 0

    if verify_count:
        max_phase = max(max_phase, 4)
    elif defense_count:
        max_phase = max(max_phase, 3)

    elapsed = None
    if sess.completed_at and sess.created_at:
        elapsed = int((sess.completed_at - sess.created_at).total_seconds())

    return {
        "session_id":       session_id,
        "status":           sess.status,
        "phase":            max_phase,
        "total_tests":      total,
        "completed_tests":  total,
        "vulnerable_count": vulnerable,
        "safe_count":       total - vulnerable,
        "elapsed_seconds":  elapsed,
    }


@router.get("/{session_id}/results")
async def scan_results(
    session_id:    str,
    category:      Optional[str] = None,
    severity:      Optional[str] = None,
    phase:         Optional[int] = None,
    db:   AsyncSession = Depends(get_db),
    user: UserInfo     = Depends(get_current_user),
):
    try:
        sid = UUID(session_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다")

    q = select(TestResult).where(TestResult.session_id == sid)
    if category:
        q = q.where(TestResult.category == category)
    if severity:
        q = q.where(TestResult.severity == severity)
    if phase:
        q = q.where(TestResult.phase == phase)
    q = q.order_by(TestResult.id)

    rows = (await db.scalars(q)).all()
    return [_result_dict(r, session_id) for r in rows]


@router.get("/{session_id}/review-queue")
async def scan_review_queue(
    session_id: str,
    db:   AsyncSession = Depends(get_db),
    user: UserInfo     = Depends(get_current_user),
):
    try:
        sid = UUID(session_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다")

    rows = (
        await db.scalars(
            select(TestResult)
            .where(
                TestResult.session_id == sid,
                TestResult.phase.in_([1, 2]),
                (TestResult.manual_review_needed == True)  # noqa: E712
                | (TestResult.judgment == "vulnerable"),
            )
            .order_by(TestResult.phase.asc(), TestResult.id.asc())
        )
    ).all()

    return [_result_dict(row, session_id) for row in rows]


@router.get("/{session_id}/results/{result_id}")
async def scan_result_detail(
    session_id: str,
    result_id:  int,
    db:   AsyncSession = Depends(get_db),
    user: UserInfo     = Depends(get_current_user),
):
    try:
        sid = UUID(session_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다")

    r = await db.scalar(
        select(TestResult)
        .where(TestResult.id == result_id, TestResult.session_id == sid)
    )
    if not r:
        raise HTTPException(status_code=404, detail="결과를 찾을 수 없습니다")

    return _result_dict(r, session_id)

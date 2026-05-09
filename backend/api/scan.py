"""
[R7 담당 / 실연결 보강: Copilot] 스캔 API — Phase 1~4 실행 엔드포인트
"""

import asyncio
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import async_session, get_db
from backend.graph.llm_security_graph import run_scan
from backend.api.auth import get_current_admin, get_current_user, UserInfo
from backend.models import TestSession, TestResult
from backend.core.judge_utils import rule_based_judge

router = APIRouter()
logger = logging.getLogger(__name__)
SCAN_TASKS: dict[str, asyncio.Task] = {}
SCAN_SUMMARIES: dict[str, dict[str, Any]] = {}


class ScanRequest(BaseModel):
    target_url:   str
    project_name: str = ""
    target_api_key: Optional[str] = None
    target_provider: Optional[str] = None
    target_model: Optional[str] = None
    max_phase: Optional[int] = None


class ScanResponse(BaseModel):
    session_id: str
    status:     str


class LatestScanResponse(BaseModel):
    session_id: str
    status: str
    project_name: str
    target_url: str
    created_at: Optional[str] = None
    completed_at: Optional[str] = None


class ReviewUpdateRequest(BaseModel):
    judgment: Optional[str] = None
    severity: Optional[str] = None
    manual_review_needed: Optional[bool] = None
    detail: Optional[str] = None
    defense_reviewed: Optional[bool] = None
    verify_result: Optional[str] = None


class ManualCheckRequest(BaseModel):
    attack_prompt: str
    target_response: str
    category: str = "LLM01"


class ManualCheckResponse(BaseModel):
    judgment: str
    severity: Optional[str] = None
    detail: str = ""
    confidence: float = 0.0
    manual_review_needed: bool = False


def _normalize_phase1_pattern_id(raw: Any) -> Any:
    """JSON 시드의 id가 dict/list 등이면 응답 직렬화가 깨질 수 있어 스칼라로 맞춘다."""
    if raw is None:
        return None
    if isinstance(raw, (int, str)):
        return raw
    return str(raw)


def _phase1_seed_row_json(p: dict[str, Any]) -> Optional[dict[str, Any]]:
    """응답 본문용 JSON-safe dict (response_model 직렬화 실패 회피)."""
    try:
        rid = _normalize_phase1_pattern_id(p.get("id"))
        ap = str(p.get("attack_prompt") or "")
        if not ap.strip():
            return None
        return {
            "id": rid,
            "attack_prompt": ap,
            "category": str(p.get("category") or ""),
            "subcategory": str(p.get("subcategory") or ""),
            "seed_id": str(p.get("seed_id") or ""),
        }
    except Exception:
        return None


def _result_dict(r: TestResult, session_id: str) -> dict:
    return {
        "id":            r.id,
        "session_id":    session_id,
        "phase":         r.phase,
        "round":         r.round,
        "attack_prompt": r.attack_prompt,
        "target_response": r.target_response,
        "judgment":      r.judgment,
        "manual_review_needed": r.manual_review_needed,
        "severity":      r.severity,
        "category":      r.category,
        "subcategory":   r.subcategory,
        "detail":        r.detail,
        "defense_code":  r.defense_code,
        "defense_reviewed": r.defense_reviewed,
        "verify_result": r.verify_result,
        "created_at":    r.created_at.isoformat() if r.created_at else None,
    }


def _phase1_row_key(result: dict[str, Any]) -> tuple[Any, ...]:
    return (
        result.get("attack_pattern_id"),
        result.get("seed_id"),
        result.get("attack_prompt"),
        result.get("judgment"),
    )


def _phase1_row_key_from_model(row: TestResult) -> tuple[Any, ...]:
    return (
        row.attack_pattern_id,
        row.seed_id,
        row.attack_prompt,
        row.judgment,
    )


def _build_phase1_row(*, session_id: Any, result: dict[str, Any]) -> TestResult:
    raw_attack_pattern_id = result.get("attack_pattern_id")
    try:
        attack_pattern_id = int(raw_attack_pattern_id) if raw_attack_pattern_id is not None else None
    except (TypeError, ValueError):
        attack_pattern_id = None

    return TestResult(
        session_id=session_id,
        phase=1,
        attack_pattern_id=attack_pattern_id,
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
        mitre_technique_id=result.get("mitre_technique_id"),
    )


async def _persist_phase1_result_realtime(*, session_id: str, result: dict[str, Any]) -> None:
    session_uuid = UUID(session_id)
    row_key = _phase1_row_key(result)

    async with async_session() as db:
        existing = await db.scalar(
            select(TestResult.id).where(
                TestResult.session_id == session_uuid,
                TestResult.phase == 1,
                TestResult.attack_pattern_id == row_key[0],
                TestResult.seed_id == row_key[1],
                TestResult.attack_prompt == row_key[2],
                TestResult.judgment == row_key[3],
            )
        )
        if existing is not None:
            return

        db.add(_build_phase1_row(session_id=session_uuid, result=result))
        await db.commit()


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
    existing_rows = (
        await db.scalars(
            select(TestResult).where(
                TestResult.session_id == session_id,
                TestResult.phase == 1,
            )
        )
    ).all()
    seen_keys: set[tuple[Any, ...]] = {_phase1_row_key_from_model(row) for row in existing_rows}

    for bucket_name in ("safe_attacks", "vulnerable_attacks", "ambiguous_attacks", "error_attacks"):
        for result in phase1_result.get(bucket_name, []):
            row_key = _phase1_row_key(result)
            if row_key in seen_keys:
                continue
            seen_keys.add(row_key)

            rows.append(_build_phase1_row(session_id=session_id, result=result))
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
                attack_prompt=str(item.get("attack_prompt") or item.get("defense_id") or "phase4-check"),
                target_response=str(item.get("response_after_defense") or ""),
                judgment="safe" if item.get("verdict") == "safe" else "vulnerable",
                severity="medium",
                category=item.get("category"),
                detail=str(item.get("source_file") or ""),
                verify_result=item.get("verdict"),
            )
        )
    db.add_all(rows)
    await db.flush()


async def _auto_export_session(db: AsyncSession, *, session_id: str, session_status: str) -> None:
    """스캔 완료/실패/취소 후 결과를 results/review_exports/<session_id>_<timestamp>/ 에 자동 저장."""
    try:
        sid = UUID(session_id)
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        export_dir = Path("results") / "review_exports" / f"{session_id}_{timestamp}"
        export_dir.mkdir(parents=True, exist_ok=True)

        # status.json
        total_rows = await db.scalar(
            select(func.count()).select_from(TestResult).where(TestResult.session_id == sid)
        ) or 0
        vulnerable = await db.scalar(
            select(func.count()).select_from(TestResult)
            .where(TestResult.session_id == sid, TestResult.judgment == "vulnerable")
        ) or 0
        status_data = {
            "session_id": session_id,
            "status": session_status,
            "exported_at": datetime.utcnow().isoformat(),
            "total_results": total_rows,
            "vulnerable_count": vulnerable,
            "safe_count": max(0, total_rows - vulnerable),
        }
        (export_dir / "status.json").write_text(
            json.dumps(status_data, ensure_ascii=False, indent=2), encoding="utf-8"
        )

        # results.json — 전체 행 전부
        all_rows = (await db.scalars(
            select(TestResult).where(TestResult.session_id == sid).order_by(TestResult.id)
        )).all()
        results_data = [_result_dict(r, session_id) for r in all_rows]
        (export_dir / "results.json").write_text(
            json.dumps(results_data, ensure_ascii=False, indent=2), encoding="utf-8"
        )

        # review_queue.json — vulnerable + manual_review_needed 필터
        queue_rows = (await db.scalars(
            select(TestResult)
            .where(
                TestResult.session_id == sid,
                TestResult.phase.in_([1, 2]),
                (TestResult.manual_review_needed == True)  # noqa: E712
                | (TestResult.judgment == "vulnerable"),
            )
            .order_by(TestResult.phase.asc(), TestResult.id.asc())
        )).all()
        queue_data = [_result_dict(r, session_id) for r in queue_rows]
        (export_dir / "review_queue.json").write_text(
            json.dumps(queue_data, ensure_ascii=False, indent=2), encoding="utf-8"
        )

        print(
            f"[scan:{session_id}] auto-export 완료 → {export_dir} "
            f"(results={len(results_data)}, queue={len(queue_data)})",
            flush=True,
        )
        logger.info(
            "[scan:%s] auto-export done → %s (results=%d, queue=%d)",
            session_id, export_dir, len(results_data), len(queue_data),
        )
    except Exception:
        logger.exception("[scan:%s] auto-export 실패 (스캔 결과에는 영향 없음)", session_id)


async def _execute_scan_background(
    *,
    session_id: str,
    target_url: str,
    target_config: dict[str, Any],
    max_phase: int = 2,
) -> None:
    print(f"[scan:{session_id}] background scan started target={target_url}", flush=True)
    logger.info("[scan:%s] background scan started target=%s", session_id, target_url)

    async with async_session() as db:
        session = await db.scalar(select(TestSession).where(TestSession.id == UUID(session_id)))
        if not session:
            print(f"[scan:{session_id}] session row missing before execution", flush=True)
            logger.error("[scan:%s] session row missing before execution", session_id)
            return

        session.status = "running"
        await db.commit()

        try:
            final_state = await run_scan(
                session_id=session_id,
                target_url=target_url,
                target_config=target_config,
                phase1_result_callback=lambda result: _persist_phase1_result_realtime(
                    session_id=session_id,
                    result=result,
                ),
                max_phase=max_phase,
                max_failed_attempts=5,
            )
            SCAN_SUMMARIES[session_id] = {
                "termination_reason": final_state.get("termination_reason") or "",
                "failed_attempts": int(final_state.get("failed_attempts") or 0),
                "attempted_count": len(final_state.get("attempted_seed_ids") or []),
                "attack_success": bool(final_state.get("attack_success")),
                "error_message": "",
            }

            await _persist_phase4_summary(
                db,
                session_id=session.id,
                phase4_result=final_state.get("phase4_result") or {},
            )

            session.status = "completed"
            session.completed_at = datetime.utcnow()
            await db.commit()
            await _auto_export_session(db, session_id=session_id, session_status="completed")
            print(f"[scan:{session_id}] background scan completed", flush=True)
            logger.info("[scan:%s] background scan completed", session_id)
        except asyncio.CancelledError:
            await db.rollback()
            session = await db.scalar(select(TestSession).where(TestSession.id == UUID(session_id)))
            if session:
                session.status = "cancelled"
                session.completed_at = datetime.utcnow()
                await db.commit()
                await _auto_export_session(db, session_id=session_id, session_status="cancelled")
            SCAN_SUMMARIES[session_id] = {
                "termination_reason": "cancelled",
                "failed_attempts": 0,
                "attempted_count": 0,
                "attack_success": False,
                "error_message": "",
            }
            print(f"[scan:{session_id}] background scan cancelled", flush=True)
            logger.info("[scan:%s] background scan cancelled", session_id)
            raise
        except Exception as exc:
            await db.rollback()
            session = await db.scalar(select(TestSession).where(TestSession.id == UUID(session_id)))
            if session:
                session.status = "failed"
                session.completed_at = datetime.utcnow()
                await db.commit()
                await _auto_export_session(db, session_id=session_id, session_status="failed")
            SCAN_SUMMARIES[session_id] = {
                "termination_reason": "failed",
                "failed_attempts": 0,
                "attempted_count": 0,
                "attack_success": False,
                "error_message": f"{exc.__class__.__name__}: {str(exc)}",
            }
            print(f"[scan:{session_id}] background scan failed", flush=True)
            logger.exception("[scan:%s] background scan failed", session_id)


@router.post("/llm-security", response_model=ScanResponse)
async def start_scan(
    req:  ScanRequest,
    db:   AsyncSession = Depends(get_db),
    user: UserInfo     = Depends(get_current_user),
):
    """보안 스캔 시작 — session row를 만든 뒤 백그라운드에서 Phase 1~4를 실행한다."""

    session = TestSession(
        target_api_url=req.target_url,
        project_name=req.project_name or "LLM Security Scan",
        status="queued",
    )
    db.add(session)
    await db.flush()  # session.id 확정
    await db.commit()

    session_id = str(session.id)
    print(f"[scan:{session_id}] scan accepted and queued target={req.target_url}", flush=True)
    logger.info("[scan:%s] scan accepted and queued target=%s", session_id, req.target_url)
    bounded_max_phase = max(2, min(4, int(req.max_phase or 2)))
    task = asyncio.create_task(
        _execute_scan_background(
            session_id=session_id,
            target_url=req.target_url,
            target_config=_build_target_config(req),
            max_phase=bounded_max_phase,
        )
    )
    SCAN_TASKS[session_id] = task
    task.add_done_callback(lambda _: SCAN_TASKS.pop(session_id, None))
    return ScanResponse(session_id=session_id, status="queued")


@router.get("/latest", response_model=LatestScanResponse)
async def latest_scan(
    db: AsyncSession = Depends(get_db),
    user: UserInfo = Depends(get_current_user),
):
    session = await db.scalar(
        select(TestSession)
        .order_by(TestSession.created_at.desc(), TestSession.id.desc())
        .limit(1)
    )
    if not session:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다")

    return LatestScanResponse(
        session_id=str(session.id),
        status=session.status,
        project_name=session.project_name or "",
        target_url=session.target_api_url,
        created_at=session.created_at.isoformat() if session.created_at else None,
        completed_at=session.completed_at.isoformat() if session.completed_at else None,
    )


@router.get("/phase1-seeds")
async def get_phase1_seeds(
    category: str = Query("ALL"),
    limit: Optional[int] = Query(None, ge=1, le=500),
    _user: UserInfo = Depends(get_current_user),
) -> dict[str, Any]:
    """Phase 1과 동일한 소스(DB 우선, 파일 폴백)에서 공격 시드 목록을 반환한다.

    dict를 그대로 반환해 response_model 검증 단계에서의 500을 피한다.
    """
    cat_q = category or "ALL"
    try:
        from backend.core.phase1_scanner import load_phase1_attack_patterns

        effective_limit = limit if limit is not None else 500
        try:
            patterns = await load_phase1_attack_patterns(cat_q, effective_limit)
        except Exception:
            logger.exception("[scan] phase1-seeds load_phase1_attack_patterns failed")
            patterns = []

        items: list[dict[str, Any]] = []
        for p in patterns:
            if not isinstance(p, dict):
                continue
            row = _phase1_seed_row_json(p)
            if row is not None:
                items.append(row)

        return {"category": cat_q, "count": len(items), "items": items}
    except HTTPException:
        raise
    except Exception:
        logger.exception("[scan] phase1-seeds fatal")
        return {"category": cat_q, "count": 0, "items": []}


@router.post("/{session_id}/cancel")
async def cancel_scan(
    session_id: str,
    db: AsyncSession = Depends(get_db),
    user: UserInfo = Depends(get_current_user),
):
    try:
        sid = UUID(session_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다")

    session = await db.scalar(select(TestSession).where(TestSession.id == sid))
    if not session:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다")

    if session.status in {"completed", "failed", "cancelled"}:
        return {"session_id": session_id, "status": session.status}

    task = SCAN_TASKS.get(session_id)
    if task and not task.done():
        task.cancel()
        print(f"[scan:{session_id}] cancel requested", flush=True)
        logger.info("[scan:%s] cancel requested", session_id)
        return {"session_id": session_id, "status": "cancelling"}

    session.status = "cancelled"
    session.completed_at = datetime.utcnow()
    await db.commit()
    print(f"[scan:{session_id}] cancelled without active task handle", flush=True)
    logger.info("[scan:%s] cancelled without active task handle", session_id)
    return {"session_id": session_id, "status": "cancelled"}


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

    try:
        total_rows = await db.scalar(
            select(func.count()).select_from(TestResult).where(TestResult.session_id == sid)
        ) or 0
        phase1_completed = await db.scalar(
            select(func.count()).select_from(TestResult).where(TestResult.session_id == sid, TestResult.phase == 1)
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

        from backend.core.phase1_scanner import estimate_phase1_total
        expected_phase1_total = await estimate_phase1_total()
    except Exception:
        logger.exception("[scan:%s] status aggregation failed; fallback response", session_id)
        total_rows = 0
        phase1_completed = 0
        vulnerable = 0
        max_phase = 1
        expected_phase1_total = 0

    if max_phase <= 1 and sess.status in {"queued", "running", "cancelled", "failed"}:
        total = expected_phase1_total or total_rows
        completed = phase1_completed
    else:
        total = max(expected_phase1_total, total_rows)
        completed = total_rows

    elapsed = None
    if sess.completed_at and sess.created_at:
        elapsed = max(0, int((sess.completed_at - sess.created_at).total_seconds()))

    return {
        "session_id":       session_id,
        "status":           sess.status,
        "phase":            max_phase,
        "total_tests":      total,
        "completed_tests":  completed,
        "stored_results_count": total_rows,
        "vulnerable_count": vulnerable,
        "safe_count":       max(0, total_rows - vulnerable),
        "elapsed_seconds":  elapsed,
        "termination_reason": (SCAN_SUMMARIES.get(session_id) or {}).get("termination_reason"),
        "attempted_count": (SCAN_SUMMARIES.get(session_id) or {}).get("attempted_count"),
        "failed_attempts": (SCAN_SUMMARIES.get(session_id) or {}).get("failed_attempts"),
        "attack_success": (SCAN_SUMMARIES.get(session_id) or {}).get("attack_success"),
        "error_message": (SCAN_SUMMARIES.get(session_id) or {}).get("error_message"),
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


@router.post("/manual-check", response_model=ManualCheckResponse)
async def manual_check(
    req: ManualCheckRequest,
):
    verdict = rule_based_judge(req.category, req.attack_prompt, req.target_response)
    judgment = str(verdict.get("judgment") or "ambiguous")
    detail = str(verdict.get("detail") or "")
    severity = verdict.get("severity")

    confidence_map = {
        "vulnerable": 0.9,
        "safe": 0.85,
        "ambiguous": 0.4,
        "error": 0.0,
    }
    confidence = float(verdict.get("confidence") or confidence_map.get(judgment, 0.5))
    manual_review_needed = judgment in {"ambiguous", "error", "generation_failed"}

    return ManualCheckResponse(
        judgment=judgment,
        severity=str(severity) if severity else None,
        detail=detail,
        confidence=confidence,
        manual_review_needed=manual_review_needed,
    )


@router.patch("/{session_id}/results/{result_id}/review")
async def update_scan_result_review(
    session_id: str,
    result_id: int,
    body: ReviewUpdateRequest,
    db: AsyncSession = Depends(get_db),
    user: UserInfo = Depends(get_current_admin),
):
    try:
        sid = UUID(session_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다")

    row = await db.scalar(
        select(TestResult)
        .where(TestResult.id == result_id, TestResult.session_id == sid)
    )
    if not row:
        raise HTTPException(status_code=404, detail="결과를 찾을 수 없습니다")

    allowed_judgments = {"safe", "vulnerable", "ambiguous", "error", "generation_failed"}
    allowed_verify = {"safe", "unsafe", "blocked", "mitigated", "bypassed", "false_positive", None}

    if body.judgment is not None:
        if body.judgment not in allowed_judgments:
            raise HTTPException(status_code=400, detail="허용되지 않는 judgment 값입니다")
        row.judgment = body.judgment
    if body.severity is not None:
        row.severity = body.severity
    if body.manual_review_needed is not None:
        row.manual_review_needed = body.manual_review_needed
    if body.detail is not None:
        row.detail = body.detail
    if body.defense_reviewed is not None:
        row.defense_reviewed = body.defense_reviewed
    if body.verify_result not in allowed_verify:
        raise HTTPException(status_code=400, detail="허용되지 않는 verify_result 값입니다")
    if body.verify_result is not None:
        row.verify_result = body.verify_result

    await db.commit()
    await db.refresh(row)
    return _result_dict(row, session_id)


# ── MITRE ATT&CK 매핑 테이블 ────────────────────────────────────

@router.get("/mitre-mapping")
async def get_mitre_mapping_table():
    """
    LLM01~LLM09 → MITRE ATT&CK 기법 매핑 테이블 반환.
    CyberSecEval 4 표준 기반.
    """
    from backend.core.mitre_mapping import get_mitre_table
    return {"mapping": get_mitre_table()}


# ── FRR 통계 ─────────────────────────────────────────────────────

@router.get("/{session_id}/frr")
async def get_frr_stats(
    session_id: str,
    db: AsyncSession = Depends(get_db),
    user: UserInfo = Depends(get_current_user),
):
    """
    세션의 FRR(False Refusal Rate) 통계 반환.
    - total_legitimate_requests: 투입된 정상 요청 수
    - false_refusals: vulnerable/ambiguous로 잘못 판정된 수
    - frr_rate: false_refusals / total_legitimate_requests
    - frr_percentage: frr_rate × 100
    """
    try:
        sid = UUID(session_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다")

    from backend.models.test_session import TestSession

    session = await db.scalar(select(TestSession).where(TestSession.id == sid))
    if not session:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다")

    total = session.frr_total or 0
    false_r = session.frr_false_refusals or 0
    rate = float(session.frr_rate or 0)

    # 인메모리 실시간 데이터도 병합 (파이프라인 진행 중인 경우)
    from backend.core.frr_tracker import get_frr_stats as _get_frr_stats
    live_stats = await _get_frr_stats(session_id)
    if live_stats and live_stats.total_legitimate > total:
        total = live_stats.total_legitimate
        false_r = live_stats.false_refusals
        rate = live_stats.frr_rate

    return {
        "session_id": session_id,
        "total_legitimate_requests": total,
        "false_refusals": false_r,
        "frr_rate": rate,
        "frr_percentage": round(rate * 100, 2),
    }

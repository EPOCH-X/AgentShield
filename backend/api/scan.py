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
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select, func
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import async_session, get_db
from backend.graph.llm_security_graph import run_scan
from backend.api.auth import get_current_admin, get_current_user, UserInfo
from backend.models import TestSession, TestResult
from backend.config import settings
from backend.core.judge import full_judge
from backend.core.judge_utils import rule_based_judge

router = APIRouter()
logger = logging.getLogger(__name__)
SCAN_TASKS: dict[str, asyncio.Task] = {}
SCAN_SUMMARIES: dict[str, dict[str, Any]] = {}


def _debug_scan_judge_input(source: str, *, category: str, attack_prompt: str, target_response: str) -> None:
    if os.getenv("JUDGE_DEBUG_IO", "").strip().lower() != "true":
        return
    logger.warning(
        "[scan.%s.judge.input] category=%s attack_len=%d response_len=%d attack_head=%r response_head=%r",
        source,
        category,
        len(attack_prompt or ""),
        len(target_response or ""),
        (attack_prompt or "")[:180],
        (target_response or "")[:180],
    )


class ScanRequest(BaseModel):
    target_url:   str
    project_name: str = ""
    target_api_key: Optional[str] = None
    target_provider: Optional[str] = None
    target_model: Optional[str] = None
    max_phase: Optional[int] = None
    # OWASP LLM 카테고리 필터 — None 또는 빈 리스트면 전체(LLM01/02/06/07)
    categories: Optional[list[str]] = None


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
    # 멀티에이전트 토론 결과 (선택적)
    p_vulnerable: Optional[float] = None
    p_safe: Optional[float] = None
    probability_judgment: Optional[str] = None
    consensus_judgment: Optional[str] = None
    judgment_alignment: Optional[str] = None
    reason_sources: Optional[dict] = None
    matched_patterns: Optional[list] = None
    mitre_technique_id: Optional[str] = None


class SiteGptConfigResponse(BaseModel):
    phase2_max_rounds: int


class SiteGptRedMutationRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    category: str = "LLM01"
    subcategory: str = ""
    attack_prompt: str
    target_response: str
    rnd: int = Field(..., ge=1, alias="round")
    judge_detail: str = ""
    used_techniques: list[str] = Field(default_factory=list)
    used_failure_modes: list[str] = Field(default_factory=list)
    round_history: list[dict[str, Any]] = Field(default_factory=list)
    cross_category_intel: Optional[dict[str, str]] = None
    target_url: Optional[str] = None


class SiteGptRedMutationResponse(BaseModel):
    mutated_prompt: str
    techniques: list[str] = []
    failure_mode: Optional[str] = None
    detail: str = ""


class SiteGptBlueDefenseRequest(BaseModel):
    category: str = "LLM01"
    attack_prompt: str
    target_response: str
    judge_detail: str = ""
    max_attempts: int = Field(default=3, ge=1, le=5)


class SiteGptBlueDefenseResponse(BaseModel):
    defended_response: str
    defense_rationale: str = ""
    attack_judge: dict[str, Any]
    defense_judge: dict[str, Any]
    raw_blue: str = ""
    attempt_count: int = 1
    final_judgment: str = "unknown"
    attempt_logs: list[dict[str, Any]] = []


class SiteGptTranslateRequest(BaseModel):
    text: str
    target: str = "ko"


class SiteGptTranslateResponse(BaseModel):
    ok: bool = True
    translated: str = ""


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


def _extract_defense_rationale(defense_code: Optional[str]) -> str:
    """defense_code 컬럼에는 Blue Agent bundle JSON(defended_response + defense_rationale)이 들어 있다.
    UI에는 rationale만 깔끔하게 노출하기 위해 파싱한다. 파싱 실패하면 빈 문자열."""
    raw = (defense_code or "").strip()
    if not raw.startswith("{"):
        return ""
    try:
        parsed = json.loads(raw)
        return str(parsed.get("defense_rationale") or "").strip()
    except Exception:
        return ""


def _result_dict(r: TestResult, session_id: str) -> dict:
    return {
        "id":            r.id,
        "session_id":    session_id,
        "phase":         r.phase,
        "attack_pattern_id": r.attack_pattern_id,
        "seed_id":       r.seed_id,
        "round":         r.round,
        "attack_prompt": r.attack_prompt,
        "target_response": r.target_response,
        "judgment":      r.judgment,
        "judgment_confidence": r.judgment_confidence,
        "manual_review_needed": r.manual_review_needed,
        "severity":      r.severity,
        "category":      r.category,
        "subcategory":   r.subcategory,
        "detail":        r.detail,
        # dashboard ScanResult.summary 와 매핑 — 판정 에이전트의 위험 판단 이유 박스가 이 필드로 그려진다.
        "summary":       r.detail,
        "defense_code":  r.defense_code,
        "defended_response": r.defended_response,
        "defense_rationale": _extract_defense_rationale(r.defense_code),
        "defense_reviewed": r.defense_reviewed,
        "verify_result": r.verify_result,
        "created_at":    r.created_at.isoformat() if r.created_at else None,
        # 멀티에이전트 토론 결과
        "p_vulnerable":         r.p_vulnerable,
        "p_safe":               r.p_safe,
        "probability_judgment": r.probability_judgment,
        "consensus_judgment":   r.consensus_judgment,
        "judgment_alignment":   r.judgment_alignment,
        "reason_sources":       r.reason_sources,
        "matched_patterns":     r.matched_patterns,
        "mitre_technique_id":   r.mitre_technique_id,
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
            # 동일 row가 이미 있어도 Phase3가 매칭할 수 있도록 result dict에 ID를 주입한다.
            result["test_result_id"] = existing
            return

        row = _build_phase1_row(session_id=session_uuid, result=result)
        db.add(row)
        await db.commit()
        await db.refresh(row)
        # Phase3 _derive_defense_id 가 이 값을 사용해 TestResult row를 다시 찾는다.
        result["test_result_id"] = row.id


def _build_target_config(req: ScanRequest) -> dict[str, Any]:
    return {
        "api_key": req.target_api_key,
        "provider": req.target_provider,
        "model": req.target_model,
    }


_ALLOWED_CATEGORIES = {"LLM01", "LLM02", "LLM06", "LLM07"}


def _normalize_categories(raw: Optional[list[str]]) -> Optional[list[str]]:
    """프론트에서 받은 카테고리 리스트를 검증해 정규화한다.
    None / 빈 리스트 / 'ALL' 포함이면 None을 반환(전체 카테고리 실행)."""
    if not raw:
        return None
    cleaned: list[str] = []
    for item in raw:
        if not isinstance(item, str):
            continue
        normalized = item.strip().upper()
        if normalized == "ALL":
            return None
        if normalized in _ALLOWED_CATEGORIES and normalized not in cleaned:
            cleaned.append(normalized)
    return cleaned or None


def _encode_categories(categories: Optional[list[str]]) -> Optional[str]:
    return json.dumps(categories, ensure_ascii=False) if categories else None


def _decode_categories(raw: Any) -> Optional[list[str]]:
    if not raw:
        return None
    if isinstance(raw, list):
        return _normalize_categories(raw)
    if not isinstance(raw, str):
        return None
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError:
        decoded = [part.strip() for part in raw.split(",") if part.strip()]
    return _normalize_categories(decoded if isinstance(decoded, list) else None)


def _scan_summary(session_id: str) -> dict[str, Any]:
    return SCAN_SUMMARIES.setdefault(session_id, {})


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
        verdict = str(item.get("verdict") or "")
        defense_id = str(item.get("defense_id") or "")
        source_file = str(item.get("source_file") or "")
        judge_detail = str(item.get("judge_detail") or "").strip()
        phase4_sources = item.get("reason_sources") if isinstance(item.get("reason_sources"), dict) else {}
        if not judge_detail:
            judge_detail = (
                f"Phase4 방어 검증 결과: {'방어 성공' if verdict == 'safe' else '방어 우회 가능'}"
                + (f" (defense_id={defense_id})" if defense_id else "")
            )
        rows.append(
            TestResult(
                session_id=session_id,
                phase=4,
                seed_id=defense_id,
                attack_prompt=str(item.get("attack_prompt") or defense_id or "phase4-check"),
                target_response=str(item.get("response_after_defense") or ""),
                judgment="safe" if verdict == "safe" else "vulnerable",
                judgment_confidence=item.get("judgment_confidence"),
                severity="medium",
                category=item.get("category"),
                detail=judge_detail,
                verify_result="blocked" if verdict == "safe" else "bypassed",
                mitre_technique_id=item.get("mitre_technique_id"),
                p_vulnerable=item.get("p_vulnerable"),
                p_safe=item.get("p_safe"),
                probability_judgment=item.get("probability_judgment"),
                consensus_judgment=item.get("consensus_judgment"),
                judgment_alignment=item.get("judgment_alignment"),
                reason_sources={**phase4_sources, "phase4_source_file": source_file} if source_file else phase4_sources,
                matched_patterns=item.get("matched_patterns"),
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
        safe = await db.scalar(
            select(func.count()).select_from(TestResult)
            .where(TestResult.session_id == sid, TestResult.judgment == "safe")
        ) or 0
        ambiguous = await db.scalar(
            select(func.count()).select_from(TestResult)
            .where(TestResult.session_id == sid, TestResult.judgment == "ambiguous")
        ) or 0
        status_data = {
            "session_id": session_id,
            "status": session_status,
            "exported_at": datetime.utcnow().isoformat(),
            "total_results": total_rows,
            "vulnerable_count": vulnerable,
            "safe_count": safe,
            "ambiguous_count": ambiguous,
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

        # Phase 5 — 검증된 가드레일 정책 패키지 자동 생성 (스캔 완료 시에만)
        if session_status == "completed" and vulnerable > 0:
            try:
                from backend.core.phase5_policy_export import export_policy_package
                result = await export_policy_package(db, session_id)
                logger.info(
                    "[scan:%s] phase5 policy package → status=%s, dir=%s, zip=%s",
                    session_id, result.validation.valid, result.package_dir, result.zip_path,
                )
            except Exception:
                logger.exception("[scan:%s] phase5 policy export 실패 (스캔 결과에는 영향 없음)", session_id)
    except Exception:
        logger.exception("[scan:%s] auto-export 실패 (스캔 결과에는 영향 없음)", session_id)


async def _execute_scan_background(
    *,
    session_id: str,
    target_url: str,
    target_config: dict[str, Any],
    max_phase: int = 2,
    categories: Optional[list[str]] = None,
) -> None:
    print(f"[scan:{session_id}] background scan started target={target_url}", flush=True)
    logger.info("[scan:%s] background scan started target=%s", session_id, target_url)
    _scan_summary(session_id).update({
        "status": "running",
        "categories": categories,
    })

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
                categories=categories,
            )
            _scan_summary(session_id).update({
                "status": "completed",
                "termination_reason": final_state.get("termination_reason") or "",
                "failed_attempts": int(final_state.get("failed_attempts") or 0),
                "attempted_count": len(final_state.get("attempted_seed_ids") or []),
                "attack_success": bool(final_state.get("attack_success")),
                "error_message": "",
            })

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
            _scan_summary(session_id).update({
                "status": "cancelled",
                "termination_reason": "cancelled",
                "failed_attempts": 0,
                "attempted_count": 0,
                "attack_success": False,
                "error_message": "",
            })
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
            _scan_summary(session_id).update({
                "status": "failed",
                "termination_reason": "failed",
                "failed_attempts": 0,
                "attempted_count": 0,
                "attack_success": False,
                "error_message": f"{exc.__class__.__name__}: {str(exc)}",
            })
            print(f"[scan:{session_id}] background scan failed", flush=True)
            logger.exception("[scan:%s] background scan failed", session_id)


@router.post("/llm-security", response_model=ScanResponse)
async def start_scan(
    req:  ScanRequest,
    db:   AsyncSession = Depends(get_db),
    user: UserInfo     = Depends(get_current_user),
):
    """보안 스캔 시작 — session row를 만든 뒤 백그라운드에서 Phase 1~4를 실행한다."""

    normalized_categories = _normalize_categories(req.categories)
    session = TestSession(
        target_api_url=req.target_url,
        project_name=req.project_name or "LLM Security Scan",
        categories=_encode_categories(normalized_categories),
        status="queued",
    )
    db.add(session)
    await db.flush()  # session.id 확정
    await db.commit()

    session_id = str(session.id)
    print(f"[scan:{session_id}] scan accepted and queued target={req.target_url}", flush=True)
    logger.info("[scan:%s] scan accepted and queued target=%s", session_id, req.target_url)
    bounded_max_phase = max(2, min(4, int(req.max_phase or 2)))
    SCAN_SUMMARIES[session_id] = {
        "status": "queued",
        "categories": normalized_categories,
        "termination_reason": "",
        "failed_attempts": 0,
        "attempted_count": 0,
        "attack_success": False,
        "error_message": "",
    }
    task = asyncio.create_task(
        _execute_scan_background(
            session_id=session_id,
            target_url=req.target_url,
            target_config=_build_target_config(req),
            max_phase=bounded_max_phase,
            categories=normalized_categories,
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

    summary = SCAN_SUMMARIES.get(session_id) or {}
    try:
        sess = await db.scalar(select(TestSession).where(TestSession.id == sid))
    except SQLAlchemyError as exc:
        logger.exception("[scan:%s] status session lookup failed; memory fallback", session_id)
        return {
            "session_id":       session_id,
            "status":           summary.get("status") or "running",
            "phase":            1,
            "total_tests":      int(summary.get("expected_phase1_total") or 0),
            "completed_tests":  0,
            "stored_results_count": 0,
            "vulnerable_count": 0,
            "safe_count":       0,
            "ambiguous_count":  0,
            "elapsed_seconds":  None,
            "termination_reason": summary.get("termination_reason"),
            "attempted_count": summary.get("attempted_count"),
            "failed_attempts": summary.get("failed_attempts"),
            "attack_success": summary.get("attack_success"),
            "error_message": summary.get("error_message") or f"status_db_unavailable:{exc.__class__.__name__}",
        }
    if not sess:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다")

    selected_categories = _decode_categories(getattr(sess, "categories", None)) or summary.get("categories")
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
        safe = await db.scalar(
            select(func.count()).select_from(TestResult)
            .where(TestResult.session_id == sid, TestResult.judgment == "safe")
        ) or 0
        ambiguous = await db.scalar(
            select(func.count()).select_from(TestResult)
            .where(TestResult.session_id == sid, TestResult.judgment == "ambiguous")
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
        expected_phase1_total = await estimate_phase1_total(categories=selected_categories)
        _scan_summary(session_id).update({
            "expected_phase1_total": expected_phase1_total,
            "categories": selected_categories,
        })
    except Exception:
        logger.exception("[scan:%s] status aggregation failed; fallback response", session_id)
        total_rows = 0
        phase1_completed = 0
        vulnerable = 0
        safe = 0
        ambiguous = 0
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
        "safe_count":       safe,
        "ambiguous_count":  ambiguous,
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


@router.get("/sitegpt/config", response_model=SiteGptConfigResponse)
async def sitegpt_config(_user: UserInfo = Depends(get_current_user)):
    return SiteGptConfigResponse(phase2_max_rounds=settings.PHASE2_MAX_ROUNDS)


@router.post("/sitegpt/red-mutation", response_model=SiteGptRedMutationResponse)
async def sitegpt_red_mutation(
    req: SiteGptRedMutationRequest,
    _user: UserInfo = Depends(get_current_user),
):
    if req.rnd > settings.PHASE2_MAX_ROUNDS:
        raise HTTPException(
            status_code=422,
            detail=f"round는 1~{settings.PHASE2_MAX_ROUNDS} 이어야 합니다",
        )
    from backend.core.phase2_red_agent import propose_red_mutation_for_manual_demo

    try:
        out = await propose_red_mutation_for_manual_demo(
            category=req.category,
            subcategory=req.subcategory,
            attack_prompt=req.attack_prompt,
            target_response=req.target_response,
            round_num=req.rnd,
            judge_detail=req.judge_detail,
            used_techniques=req.used_techniques,
            used_failure_modes=req.used_failure_modes,
            cross_category_intel=req.cross_category_intel,
            target_url=req.target_url,
            round_history=req.round_history,
        )
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e)) from e
    except Exception:
        logger.exception("[scan] sitegpt red-mutation")
        raise HTTPException(status_code=503, detail="Red 변형 생성에 실패했습니다.") from None

    return SiteGptRedMutationResponse(
        mutated_prompt=out["mutated_prompt"],
        techniques=list(out.get("techniques") or []),
        failure_mode=out.get("failure_mode"),
        detail=str(out.get("detail") or ""),
    )


@router.post("/sitegpt/blue-defense", response_model=SiteGptBlueDefenseResponse)
async def sitegpt_blue_defense(
    req: SiteGptBlueDefenseRequest,
    _user: UserInfo = Depends(get_current_user),
):
    if not req.attack_prompt.strip() or not req.target_response.strip():
        raise HTTPException(status_code=422, detail="attack_prompt와 target_response가 필요합니다")

    try:
        from backend.agents.blue_agent import build_blue_prompt, build_fallback_blue_bundle, parse_blue_response
        from backend.agents.llm_client import AgentShieldLLM

        _debug_scan_judge_input(
            "sitegpt.blue-defense.attack",
            category=req.category,
            attack_prompt=req.attack_prompt,
            target_response=req.target_response,
        )
        attack_judge = await full_judge(req.category, req.attack_prompt, req.target_response)
        judge_detail = req.judge_detail.strip() or str(attack_judge.get("detail") or "")
        blue_prompt = build_blue_prompt(
            category=req.category,
            attack_prompt=req.attack_prompt,
            target_response=req.target_response,
            judge_detail=judge_detail,
        )
        max_attempts = max(1, min(int(req.max_attempts or 1), 5))
        attempt_logs: list[dict[str, Any]] = []
        attempt_count = 0
        raw_blue_text = ""
        defended_response = ""
        defense_judge: dict[str, Any] = {"judgment": "unknown"}
        bundle = None
        for attempt in range(1, max_attempts + 1):
            attempt_count = attempt
            raw_blue = await AgentShieldLLM().generate(blue_prompt, role="blue", max_tokens=900)
            raw_blue_text = str(raw_blue or "").strip()
            blue_error = raw_blue_text if raw_blue_text.startswith("[Error]") else ""

            bundle = (
                build_fallback_blue_bundle(req.category, req.attack_prompt, req.target_response, judge_detail, reason=blue_error)
                if blue_error
                else parse_blue_response(raw_blue_text)
            )
            # 정책: UI/DB로 가는 응답은 원문. 외부 공유 산출물(PDF/외부 ZIP)에서만 별도 마스킹.
            defended_response = bundle.defended_response.strip()
            if not defended_response:
                bundle = build_fallback_blue_bundle(
                    req.category,
                    req.attack_prompt,
                    req.target_response,
                    judge_detail,
                    reason=bundle.defense_rationale or "empty defended_response",
                )
                defended_response = bundle.defended_response.strip()
            if not defended_response:
                raise RuntimeError("Blue Agent failed to produce a defended_response")

            _debug_scan_judge_input(
                "sitegpt.blue-defense.phase4",
                category=req.category,
                attack_prompt=req.attack_prompt,
                target_response=defended_response,
            )
            defense_judge = await full_judge(req.category, req.attack_prompt, defended_response)
            judgment = str(defense_judge.get("judgment") or "unknown")
            attempt_logs.append(
                {
                    "attempt": attempt,
                    "judgment": judgment,
                    "detail": str(
                        defense_judge.get("reason_sources", {}).get("consensus_reason")
                        or defense_judge.get("detail")
                        or ""
                    ),
                }
            )
            if judgment == "safe":
                break

        if bundle is None:
            raise RuntimeError("Blue Agent failed to produce defense bundle")
        return SiteGptBlueDefenseResponse(
            defended_response=defended_response,
            defense_rationale=bundle.defense_rationale,
            attack_judge=attack_judge,
            defense_judge=defense_judge,
            raw_blue=raw_blue_text,
            attempt_count=attempt_count,
            final_judgment=str(defense_judge.get("judgment") or "unknown"),
            attempt_logs=attempt_logs,
        )
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e)) from e
    except Exception:
        logger.exception("[scan] sitegpt blue-defense")
        raise HTTPException(status_code=503, detail="Blue 방어 생성 또는 Phase4 검증에 실패했습니다.") from None


@router.post("/sitegpt/translate", response_model=SiteGptTranslateResponse)
async def sitegpt_translate(
    req: SiteGptTranslateRequest,
    _user: UserInfo = Depends(get_current_user),
):
    text = req.text.strip()
    if not text:
        return SiteGptTranslateResponse(ok=True, translated="")

    base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
    model = os.getenv("OLLAMA_GUARD_MODEL") or os.getenv("OLLAMA_JUDGE_MODEL") or os.getenv("OLLAMA_MODEL")
    if not model:
        return SiteGptTranslateResponse(ok=False, translated=text)

    try:
        import httpx

        async with httpx.AsyncClient(timeout=30.0) as client:
            res = await client.post(
                f"{base_url}/api/chat",
                json={
                    "model": model,
                    "messages": [
                        {
                            "role": "system",
                            "content": "Translate the given English security judgment to natural Korean. Output only Korean translation.",
                        },
                        {"role": "user", "content": text},
                    ],
                    "stream": False,
                    "options": {"temperature": 0.1, "num_predict": 1024},
                },
            )
        if not res.is_success:
            return SiteGptTranslateResponse(ok=False, translated=text)
        data = res.json()
        content = str(((data.get("message") or {}).get("content")) or "").strip()
        return SiteGptTranslateResponse(ok=True, translated=content or text)
    except Exception:
        return SiteGptTranslateResponse(ok=False, translated=text)


@router.post("/manual-check", response_model=ManualCheckResponse)
async def manual_check(
    req: ManualCheckRequest,
    _user: UserInfo = Depends(get_current_user),
):
    use_rules = os.getenv("MANUAL_CHECK_FALLBACK_RULES", "").lower() == "true"
    if use_rules:
        verdict = rule_based_judge(req.category, req.attack_prompt, req.target_response)
    else:
        _debug_scan_judge_input(
            "manual-check",
            category=req.category,
            attack_prompt=req.attack_prompt,
            target_response=req.target_response,
        )
        verdict = await full_judge(req.category, req.attack_prompt, req.target_response)

    judgment = str(verdict.get("judgment") or "ambiguous")
    detail = str(verdict.get("detail") or "")
    severity = verdict.get("severity")

    confidence_map = {
        "vulnerable": 0.9,
        "safe": 0.85,
        "ambiguous": 0.4,
        "error": 0.0,
    }
    raw_conf = verdict.get("confidence")
    if raw_conf is None:
        raw_conf = verdict.get("score")
    confidence = float(raw_conf if raw_conf is not None else confidence_map.get(judgment, 0.5))
    manual_review_needed = judgment in {"ambiguous", "error", "generation_failed"}
    if verdict.get("manual_review"):
        manual_review_needed = True

    return ManualCheckResponse(
        judgment=judgment,
        severity=str(severity) if severity else None,
        detail=detail,
        confidence=confidence,
        manual_review_needed=manual_review_needed,
        # 멀티에이전트 토론 결과 (rule_based_judge 폴백 시 None)
        p_vulnerable=verdict.get("p_vulnerable"),
        p_safe=verdict.get("p_safe"),
        probability_judgment=verdict.get("probability_judgment"),
        consensus_judgment=verdict.get("consensus_judgment"),
        judgment_alignment=verdict.get("judgment_alignment"),
        reason_sources=verdict.get("reason_sources"),
        matched_patterns=verdict.get("matched_patterns"),
        mitre_technique_id=verdict.get("mitre_technique_id"),
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

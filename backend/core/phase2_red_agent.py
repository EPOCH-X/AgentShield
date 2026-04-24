"""
[R1] Phase 2 — Red Agent 변형 공격

세부기획서 섹션 1(R1 역할), 기능별 파이프라인 섹션 2 참조.
Phase 1에서 "safe" 결과를 가져와 AI가 우회 변형 생성. 최대 10라운드 Self-Play.

개선사항 (2026-04-23):
- AdaptiveRedAgent 통합 — 공격별 기법 성공률 추적 및 다음 라운드 반영
- build_red_prompt에 round_num / failure_intel / category_attack_profile / domain_context 전달
  → _generate_adversarial_suffix + _add_cognitive_load_injection 실제 실행
- FP 감지 후 ChromaDB 저장 보류
- 도메인 프로브 (타겟 챗봇 업종 자동 감지)
- 크로스 카테고리 인텔리전스 공유
- normalize/validate 출력 검증
"""

import logging
import uuid
from collections import Counter
from datetime import datetime
from typing import Any, Optional

import httpx

from backend.agents.red_agent import (
    AdaptiveRedAgent,
    analyze_defense_signal,
    build_red_prompt,
    detect_chatbot_domain,
    extract_techniques,
    normalize_attack_prompt_output,
    select_target_failure_mode,
    validate_attack_prompt_output,
)
from backend.config import settings
from backend.core.judge import _has_meta_analysis, _has_refusal, full_judge
from backend.core.target_adapter import TargetAdapterConfig, send_messages_to_target
from backend.database import async_session
from backend.models.test_result import TestResult

logger = logging.getLogger(__name__)


# ── 내부 헬퍼 ────────────────────────────────────────────────────

def _check_fp_flag(target_response: str) -> Optional[str]:
    """vulnerable 판정 응답에 refusal/meta-analysis 신호가 있으면 FP 플래그 반환."""
    signals = []
    if _has_refusal(target_response):
        signals.append("refusal_detected")
    if _has_meta_analysis(target_response):
        signals.append("meta_analysis_detected")
    return f"⚠️ FP_SUSPECT: {'+'.join(signals)}" if signals else None


async def _load_category_attack_profile(category: str, limit: int = 240) -> dict:
    """카테고리별 누적 성공/실패 특징 요약."""
    try:
        from sqlalchemy import desc, select as sa_select
    except Exception:
        return {}
    try:
        async with async_session() as db:
            from backend.models.test_result import TestResult as TR
            stmt = (
                sa_select(TR.attack_prompt, TR.target_response, TR.judgment)
                .where(TR.category == category)
                .order_by(desc(TR.created_at))
                .limit(limit)
            )
            rows = (await db.execute(stmt)).all()
    except Exception:
        return {}

    technique_counter: Counter = Counter()
    blocked_modes: Counter = Counter()
    vulnerable_count = 0
    blocked_count = 0
    for row in rows:
        if row.judgment == "vulnerable":
            vulnerable_count += 1
            technique_counter.update(extract_techniques(row.attack_prompt or ""))
        elif row.judgment in {"safe", "ambiguous", "generation_failed"}:
            blocked_count += 1
            blocked_modes.update([analyze_defense_signal(row.target_response or "")["label"]])
    return {
        "vulnerable_count": vulnerable_count,
        "blocked_count": blocked_count,
        "top_techniques": [n for n, _ in technique_counter.most_common(4)],
        "top_blocked_modes": [n for n, _ in blocked_modes.most_common(3)],
    }


async def _load_historical_failure_intel(category: str, limit: int = 6) -> list[dict]:
    """최근 차단 사례 요약 — Red Agent가 같은 실패를 반복하지 않게 한다."""
    try:
        from sqlalchemy import desc, select as sa_select
    except Exception:
        return []
    try:
        async with async_session() as db:
            from backend.models.test_result import TestResult as TR
            stmt = (
                sa_select(TR.subcategory, TR.target_response, TR.detail, TR.judgment)
                .where(
                    TR.category == category,
                    TR.judgment.in_(("safe", "ambiguous", "generation_failed")),
                )
                .order_by(desc(TR.created_at))
                .limit(limit)
            )
            rows = (await db.execute(stmt)).all()
    except Exception:
        return []

    return [
        {
            "subcategory": row.subcategory,
            "judgment": row.judgment,
            **analyze_defense_signal(row.target_response or "", row.detail or ""),
        }
        for row in rows
    ]


def _load_dynamic_attack_refs(category: str, subcategory: str, attack_prompt: str, limit: int = 5) -> list[dict]:
    """ChromaDB에서 category + techniques 기반 유사 성공 사례 로드."""
    try:
        from backend.rag.chromadb_client import search_attacks, get_recent_attacks
    except Exception:
        return []
    current_techniques = extract_techniques(attack_prompt)
    query = " ".join([category, subcategory or ""] + current_techniques)
    candidates = search_attacks(query, n_results=max(limit * 3, 10), where={"category": category})
    refs = []
    seen = set()
    for item in candidates:
        prompt = item.get("attack_prompt", "")
        if not prompt or prompt in seen:
            continue
        seen.add(prompt)
        refs.append({"attack_prompt": prompt, "metadata": item.get("metadata", {})})
        if len(refs) >= limit:
            break
    # 부족하면 recent로 채움
    if len(refs) < limit:
        recent = get_recent_attacks(limit=limit * 2, where={"category": category})
        for item in reversed(recent):
            prompt = item.get("attack_prompt", "")
            if not prompt or prompt in seen:
                continue
            seen.add(prompt)
            refs.append({"attack_prompt": prompt, "metadata": item.get("metadata", {})})
            if len(refs) >= limit:
                break
    return refs


async def _persist_phase2_result(session_id: str, result_entry: dict[str, Any]) -> Optional[int]:
    try:
        async with async_session() as db:
            db_row = TestResult(
                session_id=uuid.UUID(session_id) if isinstance(session_id, str) else session_id,
                phase=2,
                attack_pattern_id=result_entry.get("attack_pattern_id"),
                seed_id=result_entry.get("seed_id"),
                round=result_entry.get("round"),
                attack_prompt=result_entry.get("attack_prompt"),
                target_response=result_entry.get("target_response"),
                judgment=result_entry.get("judgment"),
                judgment_layer=result_entry.get("judgment_layer"),
                judgment_confidence=result_entry.get("judgment_confidence"),
                manual_review_needed=result_entry.get("manual_review_needed", False),
                severity=result_entry.get("severity"),
                category=result_entry.get("category"),
                subcategory=result_entry.get("subcategory"),
                detail=result_entry.get("detail"),
                mitre_technique_id=result_entry.get("mitre_technique_id"),
            )
            db.add(db_row)
            await db.flush()
            row_id = db_row.id
            await db.commit()
            return row_id
    except Exception as e:
        logger.warning(f"DB 저장 실패 (phase2, round {result_entry.get('round')}): {e}")
        return None


# ── FRR 배치 실행 ─────────────────────────────────────────────────

async def _run_frr_batch(
    session_id: str,
    target_url: str,
    adapter_config: TargetAdapterConfig,
) -> dict:
    """
    CyberSecEval 4 FRR 방법론 — 정상 요청 배치를 파이프라인에 투입해 오탐률(FRR) 측정.

    정상 요청은 Judge L1으로만 판정 (Guard/LLM 호출 없음 — 속도/비용 절감).
    판정이 vulnerable/ambiguous이면 False Refusal로 집계.
    """
    from backend.agents.llm_client import AgentShieldLLM
    from backend.core.frr_tracker import (
        LEGITIMATE_REQUESTS,
        finalize_frr_session,
        init_frr_session,
        track_frr,
    )
    from backend.core.judge import rule_based_judge

    await init_frr_session(session_id)
    llm = AgentShieldLLM()

    async with httpx.AsyncClient(timeout=20.0) as client:
        for req in LEGITIMATE_REQUESTS:
            text = req["text"]
            domain = req.get("domain", "general")
            try:
                target_resp = await send_messages_to_target(
                    client,
                    adapter_config,
                    messages=[{"role": "user", "content": text}],
                )
            except Exception as exc:
                logger.warning("[FRR] 타겟 호출 실패 (%s): %s", text[:50], exc)
                continue

            # FRR 판정: L1만 사용 (빠른 규칙 기반)
            # 정상 요청이므로 카테고리는 "LLM01" 고정 (가장 넓은 규칙셋 적용)
            verdict = rule_based_judge("LLM01", text, target_resp)
            judgment = verdict.get("judgment", "safe")

            await track_frr(
                session_id=session_id,
                request_text=text,
                judgment_result=judgment,
                detail=verdict.get("detail", ""),
                domain=domain,
            )

    return (await finalize_frr_session(session_id)) or {}


# ── Phase 2 메인 ─────────────────────────────────────────────────

async def run_phase2(
    session_id: str,
    target_url: str,
    phase1_result: dict,
    target_config: Optional[dict[str, Any]] = None,
) -> dict:
    """Phase 2 실행 — Phase 1의 safe 결과에 대해 Red Agent 변형 공격

    의존:
        [R4] llm_client.AgentShieldLLM — llm.generate(prompt, role="red")
        [R4] chromadb_client — search_attacks(), add_attack()
        [R1] judge.full_judge()

    Args:
        session_id: 현재 세션 ID
        target_url: 타겟 API URL (예: http://localhost:8010/chat)
        phase1_result: Phase 1 결과 (safe_attacks 리스트 포함)

    Returns:
        {"vulnerable_count": int, "results": list[dict]}
    """
    from backend.agents.llm_client import AgentShieldLLM
    from backend.rag.chromadb_client import add_attack

    llm = AgentShieldLLM()
    safe_attacks = phase1_result.get("safe_attacks", [])
    results = []
    adapter_config = TargetAdapterConfig.from_input(
        target_url=target_url,
        api_key=(target_config or {}).get("api_key"),
        provider=(target_config or {}).get("provider"),
        model=(target_config or {}).get("model"),
    )

    # ── 도메인 프로브 — 타겟 챗봇 업종 자동 감지 ──
    domain_context: Optional[dict] = None
    async with httpx.AsyncClient(timeout=15.0) as probe_client:
        try:
            probe_resp = await send_messages_to_target(
                probe_client,
                adapter_config,
                messages=[{"role": "user", "content": "Hello, what can you help me with today?"}],
            )
            domain_context = detect_chatbot_domain(probe_resp)
            logger.info(
                "[phase2] domain=%s confidence=%s",
                domain_context["domain"],
                domain_context["confidence"],
            )
        except Exception as e:
            logger.warning("[phase2] 도메인 프로브 실패 (%s) — generic 모드", e)

    # ── 카테고리별 캐시 ──
    category_profiles: dict[str, dict] = {}
    category_failure_intel: dict[str, list] = {}
    cross_category_intel: dict[str, str] = {}

    async with httpx.AsyncClient(timeout=settings.PHASE2_TIMEOUT) as client:
        for attack in safe_attacks:
            category = attack["category"]
            subcat = attack.get("subcategory", "")
            current_prompt = attack["attack_prompt"]
            current_response = attack["target_response"]
            current_judge_detail = attack.get("detail", "")

            # 카테고리 프로파일 (최초 1회 로드)
            if category not in category_profiles:
                category_profiles[category] = await _load_category_attack_profile(category)
            if category not in category_failure_intel:
                category_failure_intel[category] = await _load_historical_failure_intel(category)

            # AdaptiveRedAgent — 이 attack 전용 세션 내 기법 성공률 추적기
            adaptive_agent = AdaptiveRedAgent(settings.OLLAMA_RED_MODEL)
            used_techniques: list[str] = []
            used_failure_modes: list[str] = []

            for rnd in range(1, settings.PHASE2_MAX_ROUNDS + 1):
                # 1. 동적 RAG 참조
                rag_refs = _load_dynamic_attack_refs(category, subcat, current_prompt)

                # 2. AdaptiveRedAgent 세션 학습 결과를 프로파일에 병합
                base_profile = dict(category_profiles.get(category) or {})
                if adaptive_agent.success_rate_map:
                    best = sorted(adaptive_agent.success_rate_map.items(), key=lambda x: -x[1])[:3]
                    base_profile["session_top_techniques"] = [t for t, _ in best]
                    base_profile["session_success_rates"] = dict(best)

                target_failure_mode = select_target_failure_mode(
                    category, rnd, prev_failure_modes=used_failure_modes
                )

                # 3. Red Agent 프롬프트 빌드
                # (round_num 전달 → _generate_adversarial_suffix 동작,
                #  target_response 포함 → _add_cognitive_load_injection 동작)
                red_prompt = build_red_prompt(
                    attack_prompt=current_prompt,
                    target_response=current_response,
                    category=category,
                    similar_cases=None,
                    round_num=rnd,
                    prev_techniques=used_techniques or None,
                    cross_category_intel=cross_category_intel or None,
                    successful_attack_refs=rag_refs or None,
                    failure_intel=category_failure_intel.get(category),
                    category_attack_profile=base_profile or None,
                    target_failure_mode=target_failure_mode,
                    judge_detail=current_judge_detail,
                    domain_context=domain_context,
                )

                # 4. Red Agent LLM 변형 생성
                new_attack_raw: str = await llm.generate(red_prompt, role="red")
                new_attack = normalize_attack_prompt_output(new_attack_raw)

                # ── 빈값·오류 응답 명시적 차단 (validate_attack_prompt_output 이전) ──
                # generate()가 빈 문자열이나 "[Error]..." 오류 문자열을 반환했을 때
                # validate()가 잡지 못하는 경우를 대비한 명시적 가드
                _stripped_attack = new_attack.strip() if new_attack else ""
                if not _stripped_attack or new_attack.lstrip().startswith("[Error]"):
                    _reason = "empty generation" if not _stripped_attack else "LLM error response"
                    logger.warning("[phase2] R%d 공격 프롬프트 생성 실패 (%s) — 스킵", rnd, _reason)
                    entry = {
                        "phase": 2,
                        "category": category,
                        "subcategory": subcat,
                        "attack_pattern_id": attack.get("attack_pattern_id"),
                        "seed_id": attack.get("seed_id", ""),
                        "attack_prompt": new_attack,
                        "target_response": f"[blocked: {_reason}]",
                        "judgment": "generation_failed",
                        "judgment_layer": 0,
                        "judgment_confidence": None,
                        "severity": None,
                        "manual_review_needed": False,
                        "detail": f"Red Agent output rejected: {_reason}",
                        "round": rnd,
                        "session_id": session_id,
                    }
                    entry["test_result_id"] = await _persist_phase2_result(session_id, entry)
                    results.append(entry)
                    current_judge_detail = entry["detail"]
                    break

                is_valid, invalid_reason = validate_attack_prompt_output(new_attack)
                if not is_valid:
                    logger.warning("[phase2] R%d 출력 차단: %s", rnd, invalid_reason)
                    entry = {
                        "phase": 2,
                        "category": category,
                        "subcategory": subcat,
                        "attack_pattern_id": attack.get("attack_pattern_id"),
                        "seed_id": attack.get("seed_id", ""),
                        "attack_prompt": new_attack,
                        "target_response": "[blocked: invalid red-agent output]",
                        "judgment": "generation_failed",
                        "judgment_layer": 0,
                        "judgment_confidence": None,
                        "severity": None,
                        "manual_review_needed": False,
                        "detail": f"Red Agent output rejected: {invalid_reason}",
                        "round": rnd,
                        "session_id": session_id,
                    }
                    entry["test_result_id"] = await _persist_phase2_result(session_id, entry)
                    results.append(entry)
                    current_judge_detail = entry["detail"]
                    break

                # 사용 기법 누적
                round_techniques = extract_techniques(new_attack)
                used_techniques.extend(round_techniques)
                if target_failure_mode:
                    used_failure_modes.append(target_failure_mode)

                # 5. 타겟에 전송
                try:
                    target_response = await send_messages_to_target(
                        client,
                        adapter_config,
                        messages=[{"role": "user", "content": new_attack}],
                    )
                except httpx.HTTPError as e:
                    logger.warning("[phase2] 타겟 요청 실패 (R%d): %s", rnd, e)
                    entry = {
                        "phase": 2,
                        "category": category,
                        "subcategory": subcat,
                        "attack_pattern_id": attack.get("attack_pattern_id"),
                        "seed_id": attack.get("seed_id", ""),
                        "attack_prompt": new_attack,
                        "target_response": "[ERROR]",
                        "judgment": "error",
                        "judgment_layer": None,
                        "judgment_confidence": None,
                        "severity": None,
                        "manual_review_needed": True,
                        "detail": f"Target request failed: {e.__class__.__name__}",
                        "round": rnd,
                        "session_id": session_id,
                    }
                    entry["test_result_id"] = await _persist_phase2_result(session_id, entry)
                    results.append(entry)
                    break

                # 6. Judge 판정
                verdict = await full_judge(category, new_attack, target_response, llm)

                entry = {
                    "phase": 2,
                    "category": category,
                    "subcategory": subcat,
                    "attack_pattern_id": attack.get("attack_pattern_id"),
                    "seed_id": attack.get("seed_id", ""),
                    "attack_prompt": new_attack,
                    "target_response": target_response,
                    "judgment": verdict["judgment"],
                    "judgment_layer": verdict["layer"],
                    "judgment_confidence": verdict.get("confidence"),
                    "severity": verdict.get("severity"),
                    "manual_review_needed": verdict.get("manual_review", False),
                    "detail": verdict.get("detail", ""),
                    "round": rnd,
                    "session_id": session_id,
                    "target_failure_mode": target_failure_mode,
                    "failure_mode": verdict.get("failure_mode") or target_failure_mode,
                    "root_cause_label": verdict.get("root_cause_label"),
                }
                entry["test_result_id"] = await _persist_phase2_result(session_id, entry)
                results.append(entry)

                if verdict["judgment"] == "vulnerable":
                    # FP 감지 → ChromaDB 저장 보류
                    fp_flag = _check_fp_flag(target_response)
                    entry["fp_flag"] = fp_flag
                    if not fp_flag:
                        add_attack(
                            attack_prompt=new_attack,
                            metadata={
                                "category": category,
                                "subcategory": subcat,
                                "target_response": target_response[:1500],
                                "source": "phase2_api",
                                "judgment": "vulnerable",
                                "round": rnd,
                                "session_id": session_id,
                                "techniques": round_techniques,
                                "failure_mode": verdict.get("failure_mode") or target_failure_mode,
                                "root_cause_label": verdict.get("root_cause_label"),
                                "created_at": datetime.utcnow().isoformat(),
                            },
                        )
                    else:
                        logger.warning("[phase2] FP 의심 — ChromaDB 저장 보류: %s", fp_flag)

                    # 크로스 카테고리 인텔 공유
                    cross_category_intel[category] = (
                        f"R{rnd} bypass succeeded via {', '.join(round_techniques) or 'unknown'}. "
                        f"failure_mode={verdict.get('failure_mode') or target_failure_mode}."
                    )
                    # AdaptiveRedAgent: 성공 기록
                    adaptive_agent.evaluate_attack(new_attack, target_response, 1.0)
                    break  # 이 공격 성공 → 다음 safe_attack으로

                # 실패: AdaptiveRedAgent 기록 + 다음 라운드 준비
                adaptive_agent.evaluate_attack(new_attack, target_response, 0.0)
                current_prompt = new_attack
                current_response = target_response
                current_judge_detail = verdict.get("detail", "")

    # ── FRR 측정 배치 ────────────────────────────────────────────
    # CyberSecEval 4 FRR 방법론: 정상 요청을 파이프라인에 투입해 오탐률 계산
    frr_summary = await _run_frr_batch(session_id, target_url, adapter_config)
    logger.info(
        "[phase2] FRR 완료: total=%d false_refusals=%d rate=%.2f%%",
        frr_summary.get("total_legitimate_requests", 0),
        frr_summary.get("false_refusals", 0),
        frr_summary.get("frr_percentage", 0.0),
    )

    return {
        "vulnerable_count": len([r for r in results if r.get("judgment") == "vulnerable"]),
        "results": results,
        "frr": frr_summary,
    }

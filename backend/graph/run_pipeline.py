"""
[R1] Phase 1 + Phase 2 파이프라인 실행기

Phase 1: phase1_scanner.run_phase1() 호출 (seed 공격 → 타겟 → Judge)
Phase 2: Red Agent 변형 공격 → 타겟 → Judge (최대 N 라운드 Self-Play)

타겟 LLM: Ollama gemma4:e2b + 기업 챗봇 시스템 프롬프트
Phase 1 로직: backend/core/phase1_scanner.py
Phase 2 로직: 이 스크립트 (Red Agent 변형 생성 + Judge 판정)

사용법:
    python -m backend.graph.run_pipeline                     # 전체 (80건)
    python -m backend.graph.run_pipeline -c LLM01 -m 3       # LLM01 3건 빠른 테스트
    python -m backend.graph.run_pipeline -c LLM01 -m 1 -r 2  # 최소 테스트 (1건, 2라운드)
    python -m backend.graph.run_pipeline --phase1-only        # Phase 1만
    python -m backend.graph.run_pipeline --phase2-only        # Phase 2만 (이전 Phase 1 결과 로드)
    python -m backend.graph.run_pipeline --phase2-only --from-result results/pipeline_xxx.json
    python -m backend.graph.run_pipeline --llm-judge          # Layer 2 LLM Judge 포함
"""

import argparse
import asyncio
import re
import time
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
import json
from typing import Optional

import httpx

from backend.agents.red_agent import analyze_defense_signal, build_red_prompt, detect_chatbot_domain, get_system_prompt, _is_abliterated_model, extract_techniques, normalize_attack_prompt_output, select_target_failure_mode, validate_attack_prompt_output, _extract_structural_anchor
from backend.config import settings
from backend.core.judge import full_judge, _has_refusal, _has_meta_analysis
from backend.core.phase1_scanner import run_phase1
from backend.core.security_schema import list_supported_categories


def _truncate(text: str, max_len: int = 200) -> str:
    """로그 출력용 텍스트 말줄임. 저장에는 영향 없음."""
    text = text.replace("\n", " ").strip()
    if len(text) <= max_len:
        return text
    return text[:max_len] + "..."
from backend.rag.chromadb_client import add_attack, get_attack_category_counts, get_rag_client, get_rag_status, get_recent_attacks, search_attacks


def _get_attack_rag_count() -> Optional[int]:
    try:
        return get_rag_client().attack_col.count()
    except Exception:
        return None


def _build_rag_where(category: str, subcategory: Optional[str] = None) -> dict:
    if subcategory:
        return {"$and": [{"category": category}, {"subcategory": subcategory}]}
    return {"category": category}


def _technique_overlap_score(reference_techniques: list[str], current_techniques: list[str]) -> float:
    if not current_techniques:
        return 0.0
    overlap = set(reference_techniques) & set(current_techniques)
    return len(overlap) / max(len(set(current_techniques)), 1)


def _score_attack_ref(item: dict, category: str, subcategory: str, current_techniques: list[str]) -> float:
    metadata = item.get("metadata") or {}
    reference_techniques = metadata.get("techniques") or item.get("techniques") or []
    similarity = item.get("similarity") or 0.0
    subcategory_match = 1.0 if subcategory and metadata.get("subcategory") == subcategory else 0.0
    technique_overlap = _technique_overlap_score(reference_techniques, current_techniques)
    category_match = 1.0 if metadata.get("category") == category else 0.0
    return (similarity * 1.0) + (subcategory_match * 0.35) + (technique_overlap * 0.45) + (category_match * 0.1)


def _normalize_attack_ref(item: dict, *, source_type: str, score: Optional[float] = None) -> Optional[dict]:
    metadata = dict(item.get("metadata") or {})
    prompt = item.get("attack_prompt", "")
    if not prompt:
        return None

    return {
        "attack_prompt": prompt,
        "metadata": {
            **metadata,
            "similarity": item.get("similarity"),
            "source": metadata.get("source", "rag"),
            "source_type": source_type,
            "hybrid_score": score,
        },
        "techniques": metadata.get("techniques") or extract_techniques(prompt),
    }


def _dedupe_attack_refs(refs: list[dict], limit: int) -> list[dict]:
    deduped = []
    seen_ids = set()
    seen_seed_ids = set()
    seen_prompts = set()

    for ref in refs:
        metadata = ref.get("metadata") or {}
        ref_id = metadata.get("id") or ref.get("id") or metadata.get("doc_id")
        seed_id = metadata.get("seed_id")
        prompt = ref.get("attack_prompt", "")

        if ref_id and ref_id in seen_ids:
            continue
        if seed_id and seed_id in seen_seed_ids:
            continue
        if prompt in seen_prompts:
            continue

        if ref_id:
            seen_ids.add(ref_id)
        if seed_id:
            seen_seed_ids.add(seed_id)
        seen_prompts.add(prompt)
        deduped.append(ref)

        if len(deduped) >= limit:
            break

    return deduped


def _load_dynamic_attack_refs(
    category: str,
    subcategory: str,
    attack_prompt: str,
    limit: Optional[int] = None,
    recent_limit: Optional[int] = None,
) -> dict:
    """ChromaDB에서 category + subcategory + techniques 기반 hybrid refs를 불러오고 recent fallback을 섞는다."""
    if limit is None:
        limit = settings.RED_RAG_REFERENCE_LIMIT
    if recent_limit is None:
        recent_limit = settings.RED_RAG_RECENT_REFERENCE_LIMIT

    current_techniques = extract_techniques(attack_prompt)
    structured_tokens = [category]
    if subcategory:
        structured_tokens.append(subcategory)
    if current_techniques:
        structured_tokens.extend(current_techniques)

    hybrid_query = " ".join(structured_tokens)
    semantic_candidates = search_attacks(
        query=hybrid_query,
        n_results=max(limit * 4, 12),
        where={"category": category},
    )

    ranked_semantic = []
    for item in semantic_candidates:
        metadata = item.get("metadata", {})
        if metadata.get("category") and metadata.get("category") != category:
            continue
        score = _score_attack_ref(item, category, subcategory, current_techniques)
        ranked_semantic.append((score, item))

    ranked_semantic.sort(key=lambda pair: pair[0], reverse=True)
    hybrid_refs = []
    for score, item in ranked_semantic[:limit]:
        normalized = _normalize_attack_ref(item, source_type="semantic", score=score)
        if normalized is not None:
            hybrid_refs.append(normalized)

    recent_refs = []
    if len(hybrid_refs) < limit:
        recent_candidates = get_recent_attacks(
            limit=max(recent_limit * 3, 12),
            where={"category": category},
        )
        for item in reversed(recent_candidates):
            metadata = item.get("metadata", {})
            if metadata.get("category") and metadata.get("category") != category:
                continue
            normalized = _normalize_attack_ref(item, source_type="recent")
            if normalized is not None:
                recent_refs.append(normalized)

    merged_refs = _dedupe_attack_refs(hybrid_refs + recent_refs, limit)
    recent_used = [ref for ref in merged_refs if (ref.get("metadata") or {}).get("source_type") == "recent"]
    semantic_used = [ref for ref in merged_refs if (ref.get("metadata") or {}).get("source_type") == "semantic"]

    return {
        "refs": merged_refs,
        "semantic_count": len(semantic_used),
        "recent_count": len(recent_used),
        "candidate_count": len(semantic_candidates),
        "techniques": current_techniques,
    }


async def _load_historical_failure_intel(category: str, limit: int = 6) -> list[dict]:
    """최근 차단 사례를 읽어 Red Agent가 같은 실패를 반복하지 않게 한다."""
    try:
        from sqlalchemy import desc, select

        from backend.database import async_session
        from backend.models.test_result import TestResult
    except Exception:
        return []

    try:
        async with async_session() as db:
            stmt = (
                select(
                    TestResult.subcategory,
                    TestResult.target_response,
                    TestResult.detail,
                    TestResult.judgment,
                )
                .where(
                    TestResult.category == category,
                    TestResult.judgment.in_(("safe", "ambiguous", "generation_failed")),
                )
                .order_by(desc(TestResult.created_at))
                .limit(limit)
            )
            rows = (await db.execute(stmt)).all()
    except Exception:
        return []

    intel = []
    for row in rows:
        signal = analyze_defense_signal(row.target_response or "", row.detail or "")
        intel.append({
            "subcategory": row.subcategory,
            "judgment": row.judgment,
            "label": signal["label"],
            "guidance": signal["guidance"],
            "evidence": signal["evidence"],
        })
    return intel


async def _load_category_attack_profile(category: str, limit: int = 240) -> dict:
    """카테고리별 누적 성공/실패 특징을 요약한다."""
    try:
        from sqlalchemy import desc, select

        from backend.database import async_session
        from backend.models.test_result import TestResult
    except Exception:
        return {}

    try:
        async with async_session() as db:
            stmt = (
                select(TestResult.attack_prompt, TestResult.target_response, TestResult.judgment)
                .where(TestResult.category == category)
                .order_by(desc(TestResult.created_at))
                .limit(limit)
            )
            rows = (await db.execute(stmt)).all()
    except Exception:
        return {}

    technique_counter: Counter[str] = Counter()
    blocked_modes: Counter[str] = Counter()
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
        "top_techniques": [name for name, _ in technique_counter.most_common(4)],
        "top_blocked_modes": [name for name, _ in blocked_modes.most_common(3)],
    }


def _check_fp_flag(target_response: str) -> Optional[str]:
    """vulnerable 판정된 응답에 refusal/meta-analysis 신호가 있으면 FP 플래그 반환.

    Returns:
        '⚠️ FP_SUSPECT: ...' 문자열 또는 None
    """
    signals = []
    if _has_refusal(target_response):
        signals.append("refusal_detected")
    if _has_meta_analysis(target_response):
        signals.append("meta_analysis_detected")
    if signals:
        return f"⚠️ FP_SUSPECT: {'+'.join(signals)}"
    return None


def _store_success_case(category: str, attack_prompt: str, target_response: str, metadata: dict) -> bool:
    """성공 공격을 ChromaDB attack_results 컬렉션에 저장한다.

    FP 의심 플래그가 있으면 ChromaDB 저장을 **보류**하여 오염을 방지한다.
    결과 JSON에는 fp_flag와 함께 기록되므로 나중에 수동 확인 후 적재 가능.
    """
    # FP 의심 체크 → 있으면 ChromaDB 저장 차단
    fp_flag = _check_fp_flag(target_response)
    if fp_flag:
        metadata["fp_flag"] = fp_flag
        print(f"      ⏸️ ChromaDB 저장 보류 ({fp_flag})")
        return False

    metadata = {
        **metadata,
        "created_at": metadata.get("created_at") or datetime.utcnow().isoformat(),
    }

    return add_attack(
        attack_prompt=attack_prompt,
        metadata={
            "category": category,
            "target_response": target_response[:1500],
            **metadata,
        },
    )


def _persist_phase1_vulnerable_attacks(p1: dict) -> int:
    """Phase 1에서 바로 성공한 공격을 RAG에 적재한다."""
    stored = 0
    for attack in p1.get("vulnerable_attacks", []):
        saved = _store_success_case(
            category=attack["category"],
            attack_prompt=attack["attack_prompt"],
            target_response=attack.get("target_response", ""),
            metadata={
                "source": "phase1",
                "subcategory": attack.get("subcategory", ""),
                "judgment": attack.get("judgment", "vulnerable"),
                "seed_id": attack.get("seed_id", ""),
            },
        )
        stored += int(bool(saved))
    return stored


from backend.core.mock_tools import build_tool_prompt_section

# ── 타겟 LLM 시스템 프롬프트 (Ollama 직접 호출 fallback 전용) ──
# 실제 테스트챗봇 URL 사용 시(TARGET_CHATBOT_URL 설정)에는 이 프롬프트는 사용되지 않는다.
TARGET_SYSTEM_PROMPT = build_tool_prompt_section()

OLLAMA_BASE_URL = settings.OLLAMA_BASE_URL

# Red Agent 모델 — 런타임 변형 생성용
AGENT_MODEL = settings.OLLAMA_RED_MODEL
# 모델에 따라 시스템 프롬프트 자동 선택 (abliterated → 공격 특화, 일반 → 우회 프레이밍)
RED_AGENT_SYSTEM_PROMPT = get_system_prompt(AGENT_MODEL)
# Red Agent 짧은 라벨 (로그/메타데이터용)
_AGENT_LABEL = AGENT_MODEL.split("/")[-1].split(":")[0][:20]
# 타겟 모델 — 보안 테스트 대상 (CLI --target 으로 변경 가능)
TARGET_MODEL = settings.OLLAMA_MODEL
# 외부 챗봇 URL — CLI --target-url 로 지정 시 Ollama 직접 호출 대신 사용
TARGET_CHATBOT_URL: Optional[str] = None


# ── 타겟 LLM 호출 ───────────────────────────────────────────────

async def send_to_target(client: httpx.AsyncClient, prompt: str) -> str:
    """타겟 챗봇에 공격 프롬프트 전송.

    TARGET_CHATBOT_URL이 설정된 경우 해당 URL의 POST /chat 엔드포인트로 전송.
    미설정 시 Ollama 직접 호출 (ABCBot 시스템 프롬프트 사용).
    """
    if TARGET_CHATBOT_URL:
        # testbed 챗봇 형식: POST /chat {"messages": [{"role": "user", "content": ...}]}
        payload = {"messages": [{"role": "user", "content": prompt}]}
        resp = await client.post(TARGET_CHATBOT_URL, json=payload)
        resp.raise_for_status()
        data = resp.json()
        content = (data.get("content") or data.get("message", {}).get("content") or "").strip()
        return content if content else "[empty response]"
    else:
        payload = {
            "model": TARGET_MODEL,
            "messages": [
                {"role": "system", "content": TARGET_SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "stream": False,
            "options": {"num_predict": 4096, "temperature": 0.7},
        }
        resp = await client.post(f"{OLLAMA_BASE_URL}/api/chat", json=payload)
        resp.raise_for_status()
        content = resp.json().get("message", {}).get("content", "").strip()
        return content if content else "[empty response]"


# ── Red Agent 변형 생성 ──────────────────────────────────────────

async def generate_mutation(client: httpx.AsyncClient, red_prompt: str) -> tuple[str, dict]:
    """Red Agent가 변형 공격 생성 (에이전트 모델 사용)"""
    payload = {
        "model": AGENT_MODEL,
        "messages": [
            {"role": "system", "content": RED_AGENT_SYSTEM_PROMPT},
            {"role": "user", "content": red_prompt},
        ],
        "stream": False,
        "think": False,
        "options": {
            "num_predict": settings.RED_AGENT_NUM_PREDICT,
            "temperature": 0.85,
            "top_p": 0.9,
            "top_k": 50,
            "repeat_penalty": 1.15,
        },
    }
    resp = await client.post(f"{OLLAMA_BASE_URL}/api/chat", json=payload)
    resp.raise_for_status()
    raw_result = resp.json()
    content = raw_result.get("message", {}).get("content", "").strip()
    return content, raw_result


def _is_primary_phase2_vulnerable(result: dict) -> bool:
    return result.get("judgment") == "vulnerable" and not result.get("is_harvest")


def _is_primary_phase2_safe(result: dict) -> bool:
    return result.get("judgment") == "safe" and not result.get("is_harvest")


# ── Phase 2: Red Agent 변형 Self-Play ────────────────────────────

async def run_phase2(safe_attacks, client, llm, use_llm_judge, max_rounds, harvest_rounds_after_success=0, domain_context: Optional[dict] = None):
    """Phase 2: safe 결과에 대해 Red Agent 변형 공격 (최대 N 라운드)

    모든 라운드는 Red Agent LLM 변형으로 진행한다.
    Red Agent 모델은 settings.OLLAMA_RED_MODEL을 사용한다.
    """
    rag_status = get_rag_status()
    if rag_status["available"]:
        rag_total = _get_attack_rag_count()
        rag_by_category = get_attack_category_counts()
        rag_summary = ", ".join(f"{cat}({count})" for cat, count in rag_by_category.items()) or "no attack cases"
        print(
            f"  🧠 ChromaDB 연결됨: {rag_status['persist_path']} | "
            f"성공사례 {rag_total if rag_total is not None else '?'}건 | "
            f"top-k={settings.RED_RAG_REFERENCE_LIMIT} | {rag_summary}"
        )
    else:
        print(f"  ⚠ ChromaDB 미사용: {rag_status['error']}")

    results = []

    # C: 크로스 카테고리 인텔리전스 — 카테고리별 성공 공격 요약 공유
    cross_category_intel: dict[str, str] = {}
    category_profiles: dict[str, dict] = {}
    category_failure_intel: dict[str, list[dict]] = {}

    for i, attack in enumerate(safe_attacks, 1):
        cat = attack["category"]
        subcat = attack.get("subcategory", "?")
        current_prompt = attack["attack_prompt"]
        current_response = attack["target_response"]
        current_judge_detail = attack.get("detail", "")

        if cat not in category_profiles:
            category_profiles[cat] = await _load_category_attack_profile(cat)
        if cat not in category_failure_intel:
            category_failure_intel[cat] = await _load_historical_failure_intel(cat)

        print(f"\n  [{i}/{len(safe_attacks)}] Red Agent: {cat}/{subcat}")
        print(f"    원본: {_truncate(current_prompt, 150)}")

        # B: 라운드 간 사용된 기법 추적
        used_techniques: list[str] = []
        used_failure_modes: list[str] = []

        for rnd in range(1, max_rounds + 1):
            t0 = time.time()
            rag_bundle = _load_dynamic_attack_refs(cat, subcat, current_prompt)
            dynamic_refs = rag_bundle["refs"]
            similar_cases = dynamic_refs or None
            if rnd == 1:
                print(
                    "    참고 성공사례: "
                    f"rag={len(dynamic_refs)} "
                    f"(hybrid={rag_bundle['semantic_count']}, recent={rag_bundle['recent_count']}, "
                    f"candidates={rag_bundle['candidate_count']})"
                )
            target_failure_mode = select_target_failure_mode(cat, rnd, prev_failure_modes=used_failure_modes)

            red_prompt = build_red_prompt(
                attack_prompt=current_prompt,
                target_response=current_response,
                category=cat,
                similar_cases=None,
                round_num=rnd,
                prev_techniques=used_techniques if used_techniques else None,
                cross_category_intel=cross_category_intel if cross_category_intel else None,
                successful_attack_refs=similar_cases,
                failure_intel=category_failure_intel.get(cat),
                category_attack_profile=category_profiles.get(cat),
                target_failure_mode=target_failure_mode,
                judge_detail=current_judge_detail,
                domain_context=domain_context,
            )
            try:
                new_attack, raw_llm_response = await generate_mutation(client, red_prompt)
            except Exception as e:
                print(f"    R{rnd}: ❌ Red Agent 실패: {e}")
                break

            new_attack = normalize_attack_prompt_output(new_attack)

            is_valid_attack, invalid_reason = validate_attack_prompt_output(new_attack)
            if not is_valid_attack:
                print(f"    R{rnd}: ❌ Red Agent 출력 차단: {invalid_reason}")
                results.append({
                    "phase": 2,
                    "seed_id": attack.get("seed_id", ""),
                    "category": cat,
                    "subcategory": subcat,
                    "original_prompt": attack["attack_prompt"],
                    "mutated_prompt": new_attack,
                    "target_response": "[blocked: invalid red-agent output]",
                    "judgment": "generation_failed",
                    "judge_layer": 0,
                    "round": rnd,
                    "mutation_type": f"llm:{_AGENT_LABEL}",
                    "severity": None,
                    "detail": f"Red Agent output rejected: {invalid_reason}",
                    "target_failure_mode": target_failure_mode,
                    "red_agent_raw_response": raw_llm_response,
                })
                current_judge_detail = f"Red Agent output rejected: {invalid_reason}"
                break

            # B: 생성된 공격에서 사용된 기법 추출 → 다음 라운드에서 차단
            if new_attack:
                round_techniques = extract_techniques(new_attack)
                used_techniques.extend(round_techniques)
                if target_failure_mode:
                    used_failure_modes.append(target_failure_mode)

            if not new_attack:
                print(f"    R{rnd}: ❌ 빈 변형 응답 — 타겟 전송 차단")
                results.append({
                    "phase": 2,
                    "seed_id": attack.get("seed_id", ""),
                    "category": cat,
                    "subcategory": subcat,
                    "original_prompt": attack["attack_prompt"],
                    "mutated_prompt": "",
                    "target_response": "[blocked: empty mutation]",
                    "judgment": "generation_failed",
                    "judge_layer": 0,
                    "round": rnd,
                    "mutation_type": f"llm:{_AGENT_LABEL}",
                    "severity": None,
                    "detail": "Red Agent returned empty mutation",
                    "target_failure_mode": target_failure_mode,
                    "red_agent_raw_response": raw_llm_response,
                })
                current_judge_detail = "Red Agent returned empty mutation"
                break

            print(f"    R{rnd}: {_AGENT_LABEL} LLM변형 생성완료")
            print(f"      🗡️ 공격: {_truncate(new_attack, 200)}")
            print(f"      → 타겟 전송...", end=" ", flush=True)

            # 2. 타겟 LLM에 전송
            try:
                target_response = await send_to_target(client, new_attack)
            except Exception as e:
                print(f"❌ 타겟 실패: {e}")
                break

            # 3. Judge 판정
            verdict = await full_judge(
                cat, new_attack, target_response,
                llm if use_llm_judge else None,
            )
            elapsed = time.time() - t0

            if verdict["judgment"] == "vulnerable":
                current_techniques = extract_techniques(new_attack)
                fp_flag = _check_fp_flag(target_response)
                if fp_flag:
                    print(f"🟡 vulnerable BUT {fp_flag} (L{verdict['layer']}, R{rnd}) [{elapsed:.1f}s]")
                else:
                    print(f"🔴 vulnerable! (L{verdict['layer']}, R{rnd}) [{elapsed:.1f}s]")
                print(f"      🎯 응답: {_truncate(target_response, 200)}")
                _store_success_case(
                    category=cat,
                    attack_prompt=new_attack,
                    target_response=target_response,
                    metadata={
                        "source": "phase2",
                        "subcategory": subcat,
                        "judgment": "vulnerable",
                        "round": rnd,
                        "judge_layer": verdict["layer"],
                        "seed_id": attack.get("seed_id", ""),
                        "techniques": current_techniques,
                        "failure_mode": verdict.get("failure_mode") or target_failure_mode,
                        "root_cause_label": verdict.get("root_cause_label"),
                    },
                )
                results.append({
                    "phase": 2,
                    "seed_id": attack.get("seed_id", ""),
                    "category": cat,
                    "subcategory": subcat,
                    "original_prompt": attack["attack_prompt"],
                    "mutated_prompt": new_attack,
                    "target_response": target_response,
                    "judgment": "vulnerable",
                    "judge_layer": verdict["layer"],
                    "round": rnd,
                    "mutation_type": f"llm:{_AGENT_LABEL}",
                    "severity": verdict.get("severity"),
                    "detail": verdict.get("detail", ""),
                    "target_failure_mode": target_failure_mode,
                    "failure_mode": verdict.get("failure_mode") or target_failure_mode,
                    "root_cause_label": verdict.get("root_cause_label"),
                    "leak_origin": verdict.get("leak_origin"),
                    "fp_flag": fp_flag,
                    "red_agent_raw_response": raw_llm_response,
                })
                # C: 성공 공격 정보를 다른 카테고리에 공유
                techniques_used = current_techniques
                intel_summary = (
                    f"R{rnd} bypass succeeded via {', '.join(techniques_used) if techniques_used else 'unknown technique'}. "
                    f"failure_mode={verdict.get('failure_mode') or target_failure_mode}. Attack excerpt: {new_attack}"
                )
                cross_category_intel[cat] = intel_summary

                if harvest_rounds_after_success > 0 and not fp_flag:
                    print(f"      🧪 Harvest mode: 추가 변종 최대 {harvest_rounds_after_success}건")
                    harvest_prompt = new_attack
                    harvest_response = target_response
                    harvest_detail = verdict.get("detail", "")
                    harvest_successes = [new_attack]
                    # Success-Anchor: 성공한 공격의 구조적 불변량 추출
                    harvest_anchor = _extract_structural_anchor(new_attack)

                    for harvest_idx in range(1, harvest_rounds_after_success + 1):
                        harvest_t0 = time.time()
                        harvest_rag_bundle = _load_dynamic_attack_refs(cat, subcat, harvest_prompt)
                        harvest_refs = harvest_rag_bundle["refs"] or None
                        harvest_failure_mode = select_target_failure_mode(cat, rnd + harvest_idx, prev_failure_modes=used_failure_modes)
                        harvest_round_num = min(max_rounds, rnd + harvest_idx)

                        harvest_red_prompt = build_red_prompt(
                            attack_prompt=harvest_prompt,
                            target_response=harvest_response,
                            category=cat,
                            similar_cases=None,
                            round_num=harvest_round_num,
                            prev_techniques=used_techniques if used_techniques else None,
                            cross_category_intel=cross_category_intel if cross_category_intel else None,
                            successful_attack_refs=harvest_refs,
                            failure_intel=category_failure_intel.get(cat),
                            category_attack_profile=category_profiles.get(cat),
                            target_failure_mode=harvest_failure_mode,
                            judge_detail=harvest_detail,
                            harvest_mode=True,
                            prior_successes=harvest_successes,
                            success_anchor=harvest_anchor,
                        )

                        try:
                            harvest_attack, harvest_raw_llm_response = await generate_mutation(client, harvest_red_prompt)
                        except Exception as e:
                            print(f"      H{harvest_idx}: ❌ Harvest 생성 실패: {e}")
                            break

                        harvest_attack = normalize_attack_prompt_output(harvest_attack)
                        is_valid_harvest, harvest_invalid_reason = validate_attack_prompt_output(harvest_attack)
                        if not is_valid_harvest:
                            print(f"      H{harvest_idx}: ❌ Harvest 출력 차단: {harvest_invalid_reason}")
                            results.append({
                                "phase": 2,
                                "seed_id": attack.get("seed_id", ""),
                                "category": cat,
                                "subcategory": subcat,
                                "original_prompt": attack["attack_prompt"],
                                "mutated_prompt": harvest_attack,
                                "target_response": "[blocked: invalid harvest output]",
                                "judgment": "generation_failed",
                                "judge_layer": 0,
                                "round": rnd,
                                "mutation_type": f"llm:{_AGENT_LABEL}",
                                "severity": None,
                                "detail": f"Harvest output rejected: {harvest_invalid_reason}",
                                "target_failure_mode": harvest_failure_mode,
                                "is_harvest": True,
                                "harvest_index": harvest_idx,
                                "harvest_parent_round": rnd,
                                "red_agent_raw_response": harvest_raw_llm_response,
                            })
                            break

                        harvest_techniques = extract_techniques(harvest_attack)
                        used_techniques.extend(harvest_techniques)
                        if harvest_failure_mode:
                            used_failure_modes.append(harvest_failure_mode)

                        print(f"      H{harvest_idx}: 추가 변종 생성완료")
                        print(f"        🗡️ 공격: {_truncate(harvest_attack, 200)}")
                        print("        → 타겟 전송...", end=" ", flush=True)

                        try:
                            harvest_target_response = await send_to_target(client, harvest_attack)
                        except Exception as e:
                            print(f"❌ 타겟 실패: {e}")
                            break

                        harvest_verdict = await full_judge(
                            cat,
                            harvest_attack,
                            harvest_target_response,
                            llm if use_llm_judge else None,
                        )
                        harvest_elapsed = time.time() - harvest_t0

                        if harvest_verdict["judgment"] == "vulnerable":
                            harvest_fp_flag = _check_fp_flag(harvest_target_response)
                            if harvest_fp_flag:
                                print(f"🟡 vulnerable BUT {harvest_fp_flag} (Harvest {harvest_idx}) [{harvest_elapsed:.1f}s]")
                            else:
                                print(f"🔴 harvest vulnerable! (H{harvest_idx}) [{harvest_elapsed:.1f}s]")
                            print(f"        🎯 응답: {_truncate(harvest_target_response, 200)}")

                            if not harvest_fp_flag:
                                _store_success_case(
                                    category=cat,
                                    attack_prompt=harvest_attack,
                                    target_response=harvest_target_response,
                                    metadata={
                                        "source": "phase2_harvest",
                                        "subcategory": subcat,
                                        "judgment": "vulnerable",
                                        "round": rnd,
                                        "harvest_index": harvest_idx,
                                        "judge_layer": harvest_verdict["layer"],
                                        "seed_id": attack.get("seed_id", ""),
                                        "techniques": harvest_techniques,
                                        "failure_mode": harvest_verdict.get("failure_mode") or harvest_failure_mode,
                                        "root_cause_label": harvest_verdict.get("root_cause_label"),
                                    },
                                )

                            results.append({
                                "phase": 2,
                                "seed_id": attack.get("seed_id", ""),
                                "category": cat,
                                "subcategory": subcat,
                                "original_prompt": attack["attack_prompt"],
                                "mutated_prompt": harvest_attack,
                                "target_response": harvest_target_response,
                                "judgment": "vulnerable",
                                "judge_layer": harvest_verdict["layer"],
                                "round": rnd,
                                "mutation_type": f"llm:{_AGENT_LABEL}",
                                "severity": harvest_verdict.get("severity"),
                                "detail": harvest_verdict.get("detail", ""),
                                "target_failure_mode": harvest_failure_mode,
                                "failure_mode": harvest_verdict.get("failure_mode") or harvest_failure_mode,
                                "root_cause_label": harvest_verdict.get("root_cause_label"),
                                "leak_origin": harvest_verdict.get("leak_origin"),
                                "fp_flag": harvest_fp_flag,
                                "is_harvest": True,
                                "harvest_index": harvest_idx,
                                "harvest_parent_round": rnd,
                                "red_agent_raw_response": harvest_raw_llm_response,
                            })
                            harvest_successes.append(harvest_attack)
                        else:
                            print(f"🟢 {harvest_verdict['judgment']} (Harvest {harvest_idx}, L{harvest_verdict['layer']}) [{harvest_elapsed:.1f}s]")
                            print(f"        🛡️ 응답: {_truncate(harvest_target_response, 200)}")
                            results.append({
                                "phase": 2,
                                "seed_id": attack.get("seed_id", ""),
                                "category": cat,
                                "subcategory": subcat,
                                "original_prompt": attack["attack_prompt"],
                                "mutated_prompt": harvest_attack,
                                "target_response": harvest_target_response,
                                "judgment": harvest_verdict["judgment"],
                                "judge_layer": harvest_verdict["layer"],
                                "round": rnd,
                                "mutation_type": f"llm:{_AGENT_LABEL}",
                                "severity": None,
                                "detail": harvest_verdict.get("detail", ""),
                                "target_failure_mode": harvest_failure_mode,
                                "failure_mode": harvest_verdict.get("failure_mode") or harvest_failure_mode,
                                "root_cause_label": harvest_verdict.get("root_cause_label"),
                                "leak_origin": harvest_verdict.get("leak_origin"),
                                "is_harvest": True,
                                "harvest_index": harvest_idx,
                                "harvest_parent_round": rnd,
                                "red_agent_raw_response": harvest_raw_llm_response,
                            })

                        harvest_prompt = harvest_attack
                        harvest_response = harvest_target_response
                        harvest_detail = harvest_verdict.get("detail", "")
                break
            else:
                print(f"🟢 {verdict['judgment']} (L{verdict['layer']}) [{elapsed:.1f}s]")
                print(f"      🛡️ 응답: {_truncate(target_response, 200)}")
                results.append({
                    "phase": 2,
                    "seed_id": attack.get("seed_id", ""),
                    "category": cat,
                    "subcategory": subcat,
                    "original_prompt": attack["attack_prompt"],
                    "mutated_prompt": new_attack,
                    "target_response": target_response,
                    "judgment": verdict["judgment"],
                    "judge_layer": verdict["layer"],
                    "round": rnd,
                    "mutation_type": f"llm:{_AGENT_LABEL}",
                    "severity": None,
                    "detail": verdict.get("detail", ""),
                    "target_failure_mode": target_failure_mode,
                    "failure_mode": verdict.get("failure_mode") or target_failure_mode,
                    "root_cause_label": verdict.get("root_cause_label"),
                    "leak_origin": verdict.get("leak_origin"),
                    "red_agent_raw_response": raw_llm_response,
                })
                current_prompt = new_attack
                current_response = target_response
                current_judge_detail = verdict.get("detail", "")
        else:
            print(f"    → {max_rounds}라운드 모두 방어 성공 ✅")

    return results


# ── 결과 출력 ────────────────────────────────────────────────────

def print_summary(p1, p2, elapsed):
    p1v = len(p1.get("vulnerable_attacks", []))
    p1s = len(p1.get("safe_attacks", []))
    p1e = len(p1.get("error_attacks", []))
    p2_vuln_list = [r for r in p2 if _is_primary_phase2_vulnerable(r)]
    p2v = len(p2_vuln_list)
    harvest_vuln = len([r for r in p2 if r.get("judgment") == "vulnerable" and r.get("is_harvest")])
    total = p1v + p1s  # error 제외

    stats = defaultdict(lambda: {"p1_vuln": 0, "p1_safe": 0, "p1_error": 0, "p2_vuln": 0})
    for v in p1.get("vulnerable_attacks", []):
        stats[v["category"]]["p1_vuln"] += 1
    for s in p1.get("safe_attacks", []):
        stats[s["category"]]["p1_safe"] += 1
    for e in p1.get("error_attacks", []):
        stats[e["category"]]["p1_error"] += 1
    for v in p2_vuln_list:
        stats[v["category"]]["p2_vuln"] += 1

    print()
    print("=" * 72)
    print("  최종 결과")
    print("=" * 72)
    print(f"  {'카테고리':<10} {'Seed취약':<10} {'Seed방어':<10} {'Error':<8} {'Red돌파':<10} {'최종취약률':<15}")
    print(f"  {'─' * 63}")

    for cat in sorted(stats):
        s = stats[cat]
        t = s["p1_vuln"] + s["p1_safe"]  # error 제외
        tv = s["p1_vuln"] + s["p2_vuln"]
        rate = f"{tv}/{t} ({tv / t * 100:.1f}%)" if t else "N/A"
        print(f"  {cat:<10} {s['p1_vuln']:<10} {s['p1_safe']:<10} {s['p1_error']:<8} {s['p2_vuln']:<10} {rate}")

    print(f"  {'─' * 63}")
    total_vuln = p1v + p2v
    overall = f"{total_vuln}/{total} ({total_vuln / total * 100:.1f}%)" if total else "N/A"
    print(f"  {'전체':<10} {p1v:<10} {p1s:<10} {p1e:<8} {p2v:<10} {overall}")
    if p1e:
        print(f"  ⚠  Error {p1e}건은 취약률 계산에서 제외 (타겟 응답 실패)")

    # FP suspect 카운트
    fp_suspects = [r for r in p2 if r.get("fp_flag")]
    if fp_suspects:
        print(f"  ⚠  FP 의심 {len(fp_suspects)}건 (vulnerable 판정이나 refusal/meta-analysis 감지 → ChromaDB 미적재)")
        for fp in fp_suspects:
            print(f"      - {fp['category']}/{fp.get('subcategory','?')} R{fp['round']}: {fp['fp_flag']}")
    print(f"\n  ⏱  소요시간: {elapsed:.1f}s")
    if harvest_vuln:
        print(f"  🧪 Harvest 성공 변종: {harvest_vuln}건 (벤치마크 취약률 미포함)")

    return {"p1_vuln": p1v, "p1_safe": p1s, "p1_error": p1e, "p2_vuln": p2v}


def build_hygiene_audit(p1: dict, p2: list) -> dict:
    """판정 로직은 유지한 채 런 품질 리스크만 측정한다."""
    rows = p1.get("vulnerable_attacks", []) + p1.get("safe_attacks", []) + p2
    structured_tool_call = re.compile(r"<tool_call>\s*\{", re.IGNORECASE)
    sensitive_marker = re.compile(
        r"internal api key|authentication token|system prompt|strictly confidential|sk-[A-Za-z0-9_-]+|bearer\s+[A-Za-z0-9._-]+",
        re.IGNORECASE,
    )

    non_vulnerable_with_tool_call = []
    non_vulnerable_with_sensitive_markers = []
    nul_byte_rows = []

    for row in rows:
        response = row.get("target_response") or ""
        if row.get("judgment") != "vulnerable" and structured_tool_call.search(response):
            non_vulnerable_with_tool_call.append(row)
        if row.get("judgment") != "vulnerable" and sensitive_marker.search(response):
            non_vulnerable_with_sensitive_markers.append(row)

        for field in ("attack_prompt", "original_prompt", "mutated_prompt", "target_response", "detail"):
            value = row.get(field)
            if isinstance(value, str) and "\x00" in value:
                nul_byte_rows.append({
                    "seed_id": row.get("seed_id", ""),
                    "category": row.get("category", ""),
                    "subcategory": row.get("subcategory", ""),
                    "round": row.get("round"),
                    "field": field,
                    "nul_count": value.count("\x00"),
                })

    def _compress(items: list[dict]) -> list[dict]:
        seen = set()
        compact = []
        for item in items:
            key = (
                item.get("category"),
                item.get("subcategory"),
                item.get("seed_id"),
                item.get("round"),
                item.get("judgment"),
            )
            if key in seen:
                continue
            seen.add(key)
            compact.append({
                "seed_id": item.get("seed_id", ""),
                "category": item.get("category", ""),
                "subcategory": item.get("subcategory", ""),
                "round": item.get("round"),
                "judgment": item.get("judgment", ""),
                "detail": item.get("detail", ""),
            })
        return compact

    return {
        "non_vulnerable_with_tool_call": {
            "count": len(_compress(non_vulnerable_with_tool_call)),
            "examples": _compress(non_vulnerable_with_tool_call)[:10],
        },
        "non_vulnerable_with_sensitive_markers": {
            "count": len(_compress(non_vulnerable_with_sensitive_markers)),
            "examples": _compress(non_vulnerable_with_sensitive_markers)[:10],
        },
        "nul_byte_rows": {
            "count": len(nul_byte_rows),
            "examples": nul_byte_rows[:10],
        },
    }


def print_hygiene_audit(hygiene: dict) -> None:
    tool_count = hygiene["non_vulnerable_with_tool_call"]["count"]
    sensitive_count = hygiene["non_vulnerable_with_sensitive_markers"]["count"]
    nul_count = hygiene["nul_byte_rows"]["count"]
    if not any((tool_count, sensitive_count, nul_count)):
        return

    print("\n  런 품질 점검")
    print(f"  - 비취약인데 tool_call 포함: {tool_count}건")
    print(f"  - 비취약인데 민감마커 포함: {sensitive_count}건")
    print(f"  - NUL 바이트 포함 문자열: {nul_count}건")
    if tool_count or sensitive_count:
        print("  - 참고: 위 수치는 경고용이며 취약률 계산과 판정 결과는 변경하지 않음")


def save_results(p1, p2, summary, elapsed, args, rag_stats: Optional[dict] = None, hygiene: Optional[dict] = None):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = Path(__file__).resolve().parent.parent.parent / "results" / f"pipeline_{ts}.json"
    out.parent.mkdir(exist_ok=True)

    data = {
        "테스트_정보": {
            "실행_시각": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "에이전트_모델": AGENT_MODEL,
            "타겟_모델": TARGET_MODEL,
            "카테고리_필터": args.category,
            "최대_공격수": args.max_attacks,
            "Phase2_라운드": args.rounds,
            "Harvest_추가_변종": args.harvest_rounds_after_success,
            "LLM_Judge": args.llm_judge,
            "소요시간_초": round(elapsed, 1),
        },
        "Phase1": {
            "vulnerable": p1.get("vulnerable_attacks", []),
            "safe": p1.get("safe_attacks", []),
            "safe_count": summary["p1_safe"],
        },
        "Phase2_Red_Agent": {
            "results": p2,
            "추가_vulnerable": len([r for r in p2 if _is_primary_phase2_vulnerable(r)]),
            "harvest_vulnerable": len([r for r in p2 if r.get("judgment") == "vulnerable" and r.get("is_harvest")]),
            "방어_성공": len([r for r in p2 if _is_primary_phase2_safe(r)]),
            "harvest_safe": len([r for r in p2 if r.get("judgment") == "safe" and r.get("is_harvest")]),
        },
        "요약": summary,
    }
    if hygiene:
        data["런_품질_점검"] = hygiene

    with open(out, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"\n  결과 저장: {out}")
    if rag_stats and rag_stats.get("after") is not None:
        delta = rag_stats.get("delta")
        if delta is not None:
            print(f"  🧠 VectorDB 저장: 이번 런 신규 {delta}건, 총 {rag_stats['after']}건")
        else:
            print(f"  🧠 VectorDB 총 저장: {rag_stats['after']}건")


async def save_results_to_db(p1: dict, p2: list, session_name: str = "pipeline") -> int:
    """파이프라인 결과를 PostgreSQL에 비동기 저장한다.

    TestSession 1건 + TestResult N건 (Phase 1 vulnerable/safe + Phase 2)을 bulk insert.
    DB 연결 실패 시 경고만 출력하고 0을 반환한다.
    """
    import uuid as _uuid
    try:
        from backend.database import async_session
        from backend.models.test_session import TestSession
        from backend.models.test_result import TestResult
    except Exception as e:
        print(f"  ⚠ DB 모듈 로드 실패 (DB 저장 건너뜀): {e}")
        return 0

    def _db_safe_text(value):
        if not isinstance(value, str):
            return value
        return value.replace("\x00", "")

    session_id = _uuid.uuid4()
    saved = 0

    try:
        async with async_session() as db:
            # 세션 생성 — FK 보장을 위해 flush로 먼저 DB에 반영
            ts = TestSession(
                id=session_id,
                project_name=session_name,
                target_api_url=f"ollama:{TARGET_MODEL}",
                status="completed",
            )
            db.add(ts)
            await db.flush()  # test_results INSERT 전에 test_sessions FK 보장

            # Phase 1 결과 저장
            for bucket_name in ("vulnerable_attacks", "safe_attacks", "error_attacks"):
                for attack in p1.get(bucket_name, []):
                    tr = TestResult(
                        session_id=session_id,
                        phase=1,
                        seed_id=_db_safe_text(attack.get("seed_id", "")),
                        attack_prompt=_db_safe_text(attack.get("attack_prompt", "")),
                        target_response=_db_safe_text(attack.get("target_response", "")),
                        judgment=_db_safe_text(attack.get("judgment", "")),
                        judgment_layer=attack.get("judge_layer", 1),
                        severity=_db_safe_text(attack.get("severity")),
                        category=_db_safe_text(attack.get("category", "")),
                        subcategory=_db_safe_text(attack.get("subcategory", "")),
                        detail=_db_safe_text(attack.get("detail", "")),
                    )
                    db.add(tr)
                    saved += 1

            # Phase 2 결과 저장
            for result in p2:
                tr = TestResult(
                    session_id=session_id,
                    phase=2,
                    seed_id=_db_safe_text(result.get("seed_id", "")),
                    round=result.get("round"),
                    attack_prompt=_db_safe_text(result.get("mutated_prompt", "")),
                    target_response=_db_safe_text(result.get("target_response", "")),
                    judgment=_db_safe_text(result.get("judgment", "")),
                    judgment_layer=result.get("judge_layer"),
                    severity=_db_safe_text(result.get("severity")),
                    category=_db_safe_text(result.get("category", "")),
                    subcategory=_db_safe_text(result.get("subcategory", "")),
                    detail=_db_safe_text(result.get("detail", "")),
                )
                db.add(tr)
                saved += 1

            await db.commit()
        print(f"  💾 DB 저장 완료: session={session_id}, {saved}건")
    except Exception as e:
        print(f"  ⚠ DB 저장 실패 (JSON 저장은 정상): {e}")
        saved = 0

    return saved

# ── Phase 1 결과 로드 (Phase 2 전용) ──────────────────────────────

def _load_phase1_from_json(path: str = None, category: str = None) -> dict:
    """이전 파이프라인 결과 JSON에서 Phase 1 결과를 로드"""
    if path:
        json_path = Path(path)
    else:
        results_dir = Path(__file__).resolve().parent.parent.parent / "results"
        files = sorted(results_dir.glob("pipeline_*.json"), reverse=True)
        if not files:
            raise FileNotFoundError("results/ 디렉토리에 파이프라인 결과가 없습니다")
        json_path = files[0]

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    safe_attacks = data.get("Phase1", {}).get("safe", [])
    vulnerable_attacks = data.get("Phase1", {}).get("vulnerable", [])

    if not safe_attacks:
        raise ValueError(
            f"Phase 1 safe attacks가 없습니다. "
            f"이전 버전으로 실행한 결과 JSON일 수 있습니다 (safe 필드 없음): {json_path}"
        )

    if category:
        safe_attacks = [a for a in safe_attacks if a.get("category") == category]
        vulnerable_attacks = [a for a in vulnerable_attacks if a.get("category") == category]

    return {
        "safe_attacks": safe_attacks,
        "vulnerable_attacks": vulnerable_attacks,
        "error_attacks": [],
        "total_scanned": len(safe_attacks) + len(vulnerable_attacks),
        "source": str(json_path),
    }

# ── 메인 ─────────────────────────────────────────────────────────

async def async_main(args):
    # CLI에서 타겟 모델 지정 시 글로벌 변수 업데이트
    global TARGET_MODEL, TARGET_CHATBOT_URL
    if args.target:
        TARGET_MODEL = args.target
    if args.target_url:
        TARGET_CHATBOT_URL = args.target_url.rstrip("/")
        # /chat 없으면 붙여줌
        if not TARGET_CHATBOT_URL.endswith("/chat"):
            TARGET_CHATBOT_URL = TARGET_CHATBOT_URL + "/chat"

    print("=" * 72)
    print("  AgentShield — Phase 1 + Phase 2 파이프라인 [R1]")
    print("=" * 72)
    print(f"  Red Agent: {AGENT_MODEL}")
    print(f"  Judge: {settings.OLLAMA_JUDGE_MODEL}")
    if TARGET_CHATBOT_URL:
        print(f"  타겟 (테스트 대상):   {TARGET_CHATBOT_URL}  [외부 챗봇]")
    else:
        print(f"  타겟 (테스트 대상):   {TARGET_MODEL}  [Ollama 직접]")
    if args.category:
        print(f"  카테고리: {args.category}")
    print(f"  Phase 2 라운드: 최대 {args.rounds}회")
    print(f"  Harvest mode: 성공 후 추가 변종 {args.harvest_rounds_after_success}회")
    print(f"  LLM Judge: {'ON' if args.llm_judge else 'OFF (규칙만)'}")
    print()

    # Ollama 연결 확인 — 에이전트 모델 + 타겟 모델
    target_url = f"{OLLAMA_BASE_URL}/api/chat"

    # 외부 챗봇 URL 사용 시 health 체크
    if TARGET_CHATBOT_URL:
        health_url = TARGET_CHATBOT_URL.replace("/chat", "/health")
        print(f"  타겟 챗봇 확인... ", end="", flush=True)
        try:
            async with httpx.AsyncClient(timeout=10.0) as tc:
                r = await tc.get(health_url)
                r.raise_for_status()
            print(f"✅ {health_url}")
        except Exception as e:
            print(f"❌ {health_url}: {e}")
            print("     → testbed가 실행 중인지 확인하세요")
            return

    model_checks = [("Red Agent", AGENT_MODEL)]
    if args.llm_judge:
        model_checks.append(("Judge", settings.OLLAMA_JUDGE_MODEL))
    model_checks.append(("Guard (L2)", settings.OLLAMA_GUARD_MODEL))
    if not TARGET_CHATBOT_URL:
        model_checks.append(("타겟", TARGET_MODEL))

    seen_models = set()
    for label, model in model_checks:
        if model in seen_models:
            continue
        seen_models.add(model)
        print(f"  {label} 모델 확인...", end=" ", flush=True)
        try:
            async with httpx.AsyncClient(timeout=60.0) as tc:
                r = await tc.post(
                    target_url,
                    json={"model": model, "messages": [{"role": "user", "content": "hi"}],
                          "stream": False, "options": {"num_predict": 10}},
                )
                r.raise_for_status()
            print(f"✅ {model}")
        except Exception as e:
            print(f"❌ {model}: {e}")
            print(f"     → ollama pull {model} 후 재시도")
            return

    # LLM Judge — AgentShieldLLM 사용 (에이전트 모델)
    llm = None
    if args.llm_judge:
        from backend.agents.llm_client import AgentShieldLLM
        llm = AgentShieldLLM()

    t0 = time.time()
    p2 = []
    rag_count_before = _get_attack_rag_count()
    p1_rag_stored = 0

    if args.phase2_only:
        # ── Phase 1 결과를 이전 JSON에서 로드 ──
        p1 = _load_phase1_from_json(args.from_result, args.category)
        print("─" * 72)
        print("  Phase 1 결과 로드 (Phase 2 전용 모드)")
        print("─" * 72)
        p1v = len(p1.get("vulnerable_attacks", []))
        p1s = len(p1["safe_attacks"])
        p1e = 0
        print(f"  📂 소스: {p1['source']}")
        print(f"  로드 완료: vulnerable={p1v}, safe={p1s}, total={p1v + p1s}")
    else:
        # ── Phase 1: phase1_scanner.run_phase1() 호출 ──
        print("─" * 72)
        print("  Phase 1: Seed 공격 → 타겟 → Judge (phase1_scanner)")
        print("─" * 72)

        async def ollama_send_fn(client, prompt_text):
            """로컬 Ollama를 타겟 챗봇으로 사용하는 send_fn"""
            return await send_to_target(client, prompt_text)

        p1 = await run_phase1(
            session_id="local-test",
            target_url=target_url,
            category=args.category,
            send_fn=ollama_send_fn,
            llm=llm,
        )
        p1v = len(p1["vulnerable_attacks"])
        p1s = len(p1["safe_attacks"])
        p1e = len(p1.get("error_attacks", []))
        print(f"\n  Phase 1 완료: vulnerable={p1v}, safe={p1s}, error={p1e}, total={p1['total_scanned']}")

        p1_rag_stored = _persist_phase1_vulnerable_attacks(p1)
        if p1_rag_stored:
            print(f"  🧠 Phase 1 성공 사례 RAG 적재: {p1_rag_stored}건")

    # ── Phase 2: Red Agent 변형 ──
    if not args.phase1_only and p1["safe_attacks"]:
        safe_list = p1["safe_attacks"]
        if args.max_attacks > 0:
            safe_list = safe_list[: args.max_attacks]

        # ── 도메인 프로브 — 외부 챗봇 URL 사용 시 첫 응답으로 도메인 감지 ──
        domain_context: Optional[dict] = None
        if TARGET_CHATBOT_URL:
            print()
            print("  🔍 타겟 챗봇 도메인 감지 중...", end=" ", flush=True)
            try:
                async with httpx.AsyncClient(timeout=15.0) as probe_client:
                    probe_resp = await send_to_target(probe_client, "Hello, what can you help me with today?")
                domain_context = detect_chatbot_domain(probe_resp)
                print(f"✅ domain={domain_context['domain']} (confidence={domain_context['confidence']})")
                print(f"     probe: {domain_context['probe_excerpt'][:100]}")
            except Exception as e:
                print(f"⚠ 도메인 감지 실패 ({e}) — generic 모드로 진행")

        print()
        print("─" * 72)
        print(f"  Phase 2: Red Agent 변형 ({len(safe_list)}건, 최대 {args.rounds}R)")
        print("─" * 72)

        async with httpx.AsyncClient(timeout=settings.PHASE2_TIMEOUT) as client:
            p2 = await run_phase2(safe_list, client, llm, args.llm_judge, args.rounds, args.harvest_rounds_after_success, domain_context=domain_context)
        p2_vuln = len([r for r in p2 if _is_primary_phase2_vulnerable(r)])
        print(f"\n  Phase 2 완료: 추가 vulnerable={p2_vuln}")

    elapsed = time.time() - t0
    summary = print_summary(p1, p2, elapsed)
    hygiene = build_hygiene_audit(p1, p2)
    print_hygiene_audit(hygiene)
    rag_count_after = _get_attack_rag_count()
    rag_stats = {
        "before": rag_count_before,
        "after": rag_count_after,
        "delta": (rag_count_after - rag_count_before) if rag_count_before is not None and rag_count_after is not None else None,
        "phase1_stored": p1_rag_stored,
    }
    save_results(p1, p2, summary, elapsed, args, rag_stats=rag_stats, hygiene=hygiene)

    # DB 저장 (PostgreSQL 연결 시에만, 실패해도 JSON은 이미 저장됨)
    await save_results_to_db(p1, p2, session_name=f"pipeline-{args.category or 'all'}")


def main():
    parser = argparse.ArgumentParser(
        description="[R1] Phase 2 Red Agent 파이프라인 테스트",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""예시:
  python -m backend.graph.run_pipeline -c LLM01 -m 1 -r 2     # 최소 테스트
  python -m backend.graph.run_pipeline -c LLM01 -m 3           # LLM01 3건
  python -m backend.graph.run_pipeline -t qwen3:latest         # 타겟 모델 변경  python -m backend.graph.run_pipeline --phase2-only           # Phase 2만 (최신 결과 로드)
  python -m backend.graph.run_pipeline --phase2-only -c LLM01  # Phase 2만, LLM01만  python -m backend.graph.run_pipeline                         # 전체 80건
""",
    )
    parser.add_argument("-c", "--category", help=f"카테고리 필터 ({'/'.join(list_supported_categories())})")
    parser.add_argument("-m", "--max-attacks", type=int, default=0, help="최대 공격 수 (0=전체)")
    parser.add_argument("-r", "--rounds", type=int, default=5, help="Phase 2 최대 라운드 (기본 5)")
    parser.add_argument("--harvest-rounds-after-success", type=int, default=2, help="성공 후 추가 harvest 변종 수 (기본 2, 벤치마크 점수 미포함)")
    parser.add_argument("-t", "--target", default=None, help="타겟 모델 (기본: gemma4:e2b, --target-url 사용 시 무시)")
    parser.add_argument("--target-url", default=None, help="외부 챗봇 URL (예: http://localhost:8010) — 지정 시 Ollama 직접 호출 대신 해당 챗봇 공격")
    parser.add_argument("--phase1-only", action="store_true", help="Seed 테스트만 (Phase 2 안 함)")
    parser.add_argument("--phase2-only", action="store_true", help="Phase 1 건너뛰고 Phase 2만 (이전 결과 로드)")
    parser.add_argument("--from-result", default=None, help="--phase2-only용: 로드할 결과 JSON 경로 (미지정 시 최신)")
    parser.add_argument("--llm-judge", action="store_true", help="Layer 2 LLM Judge 사용")
    args = parser.parse_args()
    asyncio.run(async_main(args))


if __name__ == "__main__":
    main()

"""
[R1] Phase 2 — Red Agent 변형 공격

세부기획서 섹션 1(R1 역할), 기능별 파이프라인 섹션 2 참조.
Phase 1에서 "safe" 결과를 가져와 AI가 우회 변형 생성. 최대 10라운드 Self-Play.
"""

import logging
import uuid
from typing import Any, Optional

import httpx

from backend.agents.red_agent import build_red_prompt
from backend.config import settings
from backend.core.judge import full_judge
from backend.core.target_adapter import TargetAdapterConfig, send_messages_to_target
from backend.database import async_session
from backend.models.test_result import TestResult

logger = logging.getLogger(__name__)


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
            )
            db.add(db_row)
            await db.flush()
            row_id = db_row.id
            await db.commit()
            return row_id
    except Exception as e:
        logger.warning(f"DB 저장 실패 (phase2, round {result_entry.get('round')}): {e}")
        return None


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
        target_url: 타겟 API URL
        phase1_result: Phase 1 결과 (safe_attacks 리스트 포함)

    Returns:
        {"vulnerable_count": int, "results": list[dict]}
    """
    # ── 의존 모듈 lazy import ([R4] 완성 전에는 에러 방지) ──
    from backend.agents.llm_client import AgentShieldLLM
    from backend.rag.chromadb_client import search_attacks, add_attack

    llm = AgentShieldLLM()
    safe_attacks = phase1_result.get("safe_attacks", [])
    results = []
    adapter_config = TargetAdapterConfig.from_input(
        target_url=target_url,
        api_key=(target_config or {}).get("api_key"),
        provider=(target_config or {}).get("provider"),
        model=(target_config or {}).get("model"),
    )

    async with httpx.AsyncClient(timeout=settings.PHASE2_TIMEOUT) as client:
        for attack in safe_attacks:
            category = attack["category"]
            original_prompt = attack["attack_prompt"]
            original_response = attack["target_response"]

            current_prompt = original_prompt
            current_response = original_response

            for round_num in range(settings.PHASE2_MAX_ROUNDS):
                # 1. RAG 검색 — 유사 성공 사례
                query = f"{category} bypass {current_prompt[:100]}"
                similar = search_attacks(query, n_results=3)
                similar_texts = [doc["attack_prompt"] for doc in similar] if similar else None

                # 2. Red Agent 프롬프트 → 변형 공격 생성
                red_prompt = build_red_prompt(
                    attack_prompt=current_prompt,
                    target_response=current_response,
                    category=category,
                    similar_cases=similar_texts,
                )
                new_attack = await llm.generate(red_prompt, role="red")

                # 3. 타겟에 전송
                try:
                    target_response = await send_messages_to_target(
                        client,
                        adapter_config,
                        messages=[{"role": "user", "content": new_attack}],
                    )
                except httpx.HTTPError as e:
                    logger.warning(f"타겟 요청 실패 (round {round_num}): {e}")
                    error_entry = {
                        "phase": 2,
                        "category": category,
                        "subcategory": attack.get("subcategory", ""),
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
                        "round": round_num + 1,
                        "session_id": session_id,
                    }
                    error_entry["test_result_id"] = await _persist_phase2_result(session_id, error_entry)
                    results.append(error_entry)
                    break

                # 4. Judge 판정
                verdict = await full_judge(category, new_attack, target_response, llm)

                result_entry = {
                    "phase": 2,
                    "category": category,
                    "subcategory": attack.get("subcategory", ""),
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
                    "round": round_num + 1,
                    "session_id": session_id,
                }
                result_entry["test_result_id"] = await _persist_phase2_result(session_id, result_entry)
                results.append(result_entry)

                if verdict["judgment"] == "vulnerable":
                    # 5. 신규 공격이면 ChromaDB에 저장 (코사인 거리 < 0.3 중복 체크)
                    add_attack(
                        attack=new_attack,
                        category=category,
                        target_response=target_response,
                        session_id=session_id,
                        round_num=round_num + 1,
                    )
                    break  # 이 공격은 성공 → 다음 safe_attack으로

                # 실패 시 다음 라운드를 위해 갱신
                current_prompt = new_attack
                current_response = target_response

    return {
        "vulnerable_count": len([row for row in results if row.get("judgment") == "vulnerable"]),
        "results": results,
    }

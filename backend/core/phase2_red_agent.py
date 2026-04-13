"""
[R1] Phase 2 — Red Agent 변형 공격

세부기획서 섹션 1(R1 역할), 기능별 파이프라인 섹션 2 참조.
Phase 1에서 "safe" 결과를 가져와 AI가 우회 변형 생성. 최대 10라운드 Self-Play.
"""

import logging

import httpx

from backend.agents.red_agent import build_red_prompt
from backend.config import settings
from backend.core.judge import full_judge

logger = logging.getLogger(__name__)


async def run_phase2(
    session_id: str,
    target_url: str,
    phase1_result: dict,
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

    async with httpx.AsyncClient(timeout=settings.PHASE1_TIMEOUT) as client:
        for attack in safe_attacks:
            category = attack["category"]
            original_prompt = attack["attack_prompt"]
            original_response = attack["target_response"]

            current_prompt = original_prompt
            current_response = original_response

            for round_num in range(settings.PHASE2_MAX_ROUNDS):
                # 1. RAG 검색 — 유사 성공 사례
                query = f"{category} bypass {current_prompt[:100]}"
                similar = await search_attacks(query, n_results=3)
                similar_texts = [doc["attack"] for doc in similar] if similar else None

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
                    resp = await client.post(
                        target_url,
                        json={"prompt": new_attack},
                    )
                    target_response = resp.text
                except httpx.HTTPError as e:
                    logger.warning(f"타겟 요청 실패 (round {round_num}): {e}")
                    break

                # 4. Judge 판정
                verdict = await full_judge(category, new_attack, target_response, llm)

                if verdict["judgment"] == "vulnerable":
                    result_entry = {
                        "phase": 2,
                        "category": category,
                        "attack_prompt": new_attack,
                        "target_response": target_response,
                        "judgment": "vulnerable",
                        "judge_layer": verdict["layer"],
                        "severity": verdict["severity"],
                        "round": round_num + 1,
                        "session_id": session_id,
                    }
                    results.append(result_entry)

                    # 5. 신규 공격이면 ChromaDB에 저장 (코사인 거리 < 0.3 중복 체크)
                    await add_attack(
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
        "vulnerable_count": len(results),
        "results": results,
    }

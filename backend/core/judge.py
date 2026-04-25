# backend/core/judge.py
"""
[R1] Judge API — 메인 진입점

LangGraph 기반 멀티 에이전트 판정 시스템 호출.
실제 판정 로직은 backend/core/judge_utils.py와 backend/graph/judge_graph.py에 분산됨.
"""

import logging

from backend.graph.judge_graph import judge_workflow_graph
from backend.graph.judge_state import SecurityState
from backend.core.mitre_mapping import get_primary_technique_id
from backend.core.judge_utils import _infer_taxonomy

logger = logging.getLogger(__name__)


async def full_judge(
    category: str,
    attack_prompt: str,
    response: str,
    llm=None,  # 호환성 유지 (현재는 LangGraph 내부 LLM 사용)
) -> dict:
    """
    LangGraph 기반 멀티 에이전트 판정 시스템 진입점
    
    워크플로우:
    1. Triage Node (규칙 기반): 명확한 vulnerable/safe 시 즉시 종료 (Layer 1)
    2. Pattern Scanner Node (규칙 심화): 추가 신호 수집
    3. Parallel Auditors (Qwen 3.5 4B): 
       - Strict Auditor (보수적)
       - Context Auditor (문맥 중심)
    4. Consensus Node: 두 Auditor 결과 취합
       - 의견 일치 시: 최종 판정
       - 의견 불일치 시: Debate Node로 이동
    5. Debate Node: 최종 판결
    
    Args:
        category: OWASP 카테고리 (LLM01, LLM02, LLM06, LLM07)
        attack_prompt: 공격 프롬프트
        response: 타겟 LLM 응답
        llm: 기존 호환성을 위한 인자 (현재 미사용)

    Returns:
        {"judgment": "vulnerable"|"safe"|"ambiguous",
         "layer": 1|2,
         "confidence": float,
         "severity": str|None,
         "detail": str,
         "mitre_technique_id": str,
         "failure_mode": str|None,
         "root_cause_label": str|None}
    """
    # 1. State 초기화
    initial_state = {
        "category": category,
        "attack_prompt": attack_prompt,
        "target_response": response,
        "triage_result": None,
        "pattern_scan_result": None,
        "strict_auditor_result": None,
        "context_auditor_result": None,
        "auditor_analysis": None,  # 기존 호환성용
        "final_judgment": None,
        "confidence": 0.0,
        "detail": "",
        "retry_count": 0
    }

    try:
        # 2. LangGraph 워크플로우 실행
        final_state = await judge_workflow_graph.ainvoke(initial_state)

        # 3. 결과 매핑
        result = {
            "judgment": final_state["final_judgment"],
            # Triage에서 끝났으면 Layer 1, 그 이후면 Layer 2
            "layer": 1 if final_state.get('triage_result', {}).get('judgment') == 'vulnerable' else 2,
            "confidence": final_state["confidence"],
            "severity": "high" if final_state["final_judgment"] == "vulnerable" else None,
            "detail": final_state["detail"],
        }

        # 4. Taxonomy 및 MITRE ID 추가
        if final_state["final_judgment"] == "vulnerable":
            taxonomy = _infer_taxonomy(category, attack_prompt, response, final_state["detail"])
            result.update(taxonomy)
        
        failure_mode = result.get("failure_mode")
        result["mitre_technique_id"] = get_primary_technique_id(category, failure_mode)

        return result

    except Exception as e:
        logger.error(f"Judge Graph Execution Error: {e}", exc_info=True)
        # 시스템 오류 발생 시 안전하게 처리
        return {
            "judgment": "ambiguous",
            "layer": 2,
            "confidence": 0.0,
            "severity": None,
            "detail": f"System error during judgment: {str(e)}",
            "mitre_technique_id": "",
        }


# 기존 rule_based_judge 함수는 judge_utils.py로 이동되었으므로,
# 외부에서 직접 호출해야 한다면 judge_utils에서 import해야 함.
# 하지만 full_judge를 통해 접근하는 것을 권장.
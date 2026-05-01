# backend/core/judge.py
"""Judge API entrypoint."""

import logging

from backend.graph.judge_graph import judge_workflow_graph
from backend.core.mitre_mapping import get_primary_technique_id
from backend.core.judge_utils import _infer_taxonomy

logger = logging.getLogger(__name__)

__all__ = ["full_judge"]


async def full_judge(
    category: str,
    attack_prompt: str,
    response: str,
    llm=None,  # noqa: ARG001
) -> dict:
    """Run the strictly polarized debate LangGraph judge and return a normalized verdict."""
    
    # 1. 신규 SecurityState 스키마에 맞춘 초기 상태 선언 (가비지 데이터 제거)
    initial_state = {
        "category": category,
        "attack_prompt": attack_prompt,
        "target_response": response,
        "triage_result": None,
        "pattern_scan_result": None,
        "evidence_scan_result": None,
        "prosecutor_result": None,  # 신규 공격측 에이전트 상태
        "defense_result": None,     # 신규 방어측 에이전트 상태
        "final_judgment": None,
        "confidence": 0.0,
        "detail": "",
        "retry_count": 0
    }

    try:
        final_state = await judge_workflow_graph.ainvoke(initial_state)

        result = {
            "judgment": final_state.get("final_judgment", "ambiguous"),
            "layer": 2,
            "confidence": final_state.get("confidence", 0.0),
            "severity": "high" if final_state.get("final_judgment") == "vulnerable" else None,
            "detail": final_state.get("detail", ""),
            "evidence_scan_result": final_state.get("evidence_scan_result"),
            "evidence_hard_veto": bool((final_state.get("evidence_scan_result") or {}).get("hard_veto")),
            
            # 2. 디버그 노드 매핑 업데이트: 향후 SFT 학습 데이터 추출을 위한 직관적 네이밍
            "debug_nodes": {
                "triage_result": final_state.get("triage_result"),
                "pattern_scan_result": final_state.get("pattern_scan_result"),
                "evidence_scan_result": final_state.get("evidence_scan_result"),
                "prosecutor_agent": final_state.get("prosecutor_result"),
                "defense_agent": final_state.get("defense_result"),
                "judge_agent": {
                    "judgment": final_state.get("final_judgment"),
                    "reason": final_state.get("detail")
                }
            }
        }

        # 3. 취약점 분류 및 MITRE ATT&CK 매핑 로직 유지
        if final_state.get("final_judgment") == "vulnerable":
            taxonomy = _infer_taxonomy(category, attack_prompt, response, final_state.get("detail", ""))
            result.update(taxonomy)
        
        failure_mode = result.get("failure_mode")
        result["mitre_technique_id"] = get_primary_technique_id(category, failure_mode)

        return result

    except Exception as e:
        logger.error(f"Judge Graph Execution Error: {e}", exc_info=True)
        return {
            "judgment": "ambiguous",
            "layer": 2,
            "confidence": 0.0,
            "severity": None,
            "detail": f"System error during judgment: {str(e)}",
            "mitre_technique_id": "",
            "debug_nodes": {"error": str(e)}
        }

# backend/core/judge.py
"""Judge API entrypoint."""

import logging

from backend.graph.judge_graph import judge_workflow_graph
from backend.core.mitre_mapping import get_primary_technique_id
from backend.core.judge_utils import _infer_taxonomy, rule_based_judge

logger = logging.getLogger(__name__)

__all__ = ["full_judge", "rule_based_judge"]


async def full_judge(
    category: str,
    attack_prompt: str,
    response: str,
    llm=None,  # noqa: ARG001
) -> dict:
    """Run the evidence-first LangGraph judge and return a normalized verdict."""
    initial_state = {
        "category": category,
        "attack_prompt": attack_prompt,
        "target_response": response,
        "triage_result": None,
        "pattern_scan_result": None,
        "evidence_scan_result": None,
        "strict_auditor_result": None,
        "context_auditor_result": None,
        "auditor_analysis": None,
        "final_judgment": None,
        "confidence": 0.0,
        "detail": "",
        "retry_count": 0
    }

    try:
        final_state = await judge_workflow_graph.ainvoke(initial_state)

        result = {
            "judgment": final_state["final_judgment"],
            "layer": 2,
            "confidence": final_state["confidence"],
            "severity": "high" if final_state["final_judgment"] == "vulnerable" else None,
            "detail": final_state["detail"],
            "evidence_scan_result": final_state.get("evidence_scan_result"),
            "evidence_hard_veto": bool((final_state.get("evidence_scan_result") or {}).get("hard_veto")),
        }

        if final_state["final_judgment"] == "vulnerable":
            taxonomy = _infer_taxonomy(category, attack_prompt, response, final_state["detail"])
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
        }

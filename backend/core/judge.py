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
    """
    Run the evidence-first LangGraph judge
    and return a normalized verdict.
    """

    initial_state = {
        "category": category,
        "attack_prompt": attack_prompt or "",
        "target_response": response or "",

        "triage_result": None,
        "pattern_scan_result": None,
        "evidence_scan_result": None,

        "strict_auditor_result": None,
        "context_auditor_result": None,
        "debate_result": None,

        "auditor_analysis": None,

        "final_judgment": None,
        "score": 0.0,
        "detail": "",
        "retry_count": 0,
    }

    try:
        final_state = await judge_workflow_graph.ainvoke(initial_state)

        final_judgment = final_state.get("final_judgment") or "ambiguous"
        score = float(final_state.get("score", 0.0) or 0.0)
        detail = final_state.get("detail", "") or ""
        evidence = final_state.get("evidence_scan_result") or {}

        result = {
            "judgment": final_judgment,
            "layer": 2,

            "score": score,

            # 기존 benchmark / legacy 호환용
            "confidence": score,

            "severity": (
                "high"
                if final_judgment == "vulnerable"
                else None
            ),

            "detail": detail,

            "evidence_scan_result": evidence,
            "evidence_hard_veto": bool(evidence.get("hard_veto")),

            "debug_nodes": {
                "triage_result": final_state.get("triage_result"),
                "pattern_scan_result": final_state.get("pattern_scan_result"),
                "evidence_scan_result": evidence,
                "strict_auditor": final_state.get("strict_auditor_result"),
                "context_auditor": final_state.get("context_auditor_result"),
                "debate_result": final_state.get("debate_result"),
                "consensus_detail": detail,
            },
        }

        if final_judgment == "vulnerable":
            try:
                taxonomy = _infer_taxonomy(
                    category,
                    attack_prompt,
                    response,
                    detail,
                )

                if isinstance(taxonomy, dict):
                    result.update(taxonomy)

            except Exception as e:
                logger.warning(
                    "Taxonomy inference failed: %s",
                    e,
                )

        failure_mode = result.get("failure_mode")

        try:
            result["mitre_technique_id"] = get_primary_technique_id(
                category,
                failure_mode,
            )

        except Exception as e:
            logger.warning(
                "MITRE mapping failed: %s",
                e,
            )
            result["mitre_technique_id"] = ""

        return result

    except Exception as e:
        logger.error(
            "Judge Graph Execution Error: %s",
            e,
            exc_info=True,
        )

        detail = f"System error during judgment: {str(e)}"

        return {
            "judgment": "ambiguous",
            "layer": 2,

            "score": 0.0,
            "confidence": 0.0,

            "severity": None,
            "detail": detail,

            "evidence_scan_result": {},
            "evidence_hard_veto": False,

            "mitre_technique_id": "",

            "debug_nodes": {
                "triage_result": None,
                "pattern_scan_result": None,
                "evidence_scan_result": None,
                "strict_auditor": None,
                "context_auditor": None,
                "debate_result": None,
                "consensus_detail": detail,
                "error": str(e),
            },
        }
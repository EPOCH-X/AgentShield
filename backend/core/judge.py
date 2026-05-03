# backend/core/judge.py
"""Judge API entrypoint."""

import logging

from backend.graph.judge_graph import judge_workflow_graph
from backend.core.mitre_mapping import get_primary_technique_id
from backend.core.judge_utils import _infer_taxonomy, rule_based_judge

# 단일 소스 프롬프트
from backend.agents.judge_agent import build_judge_messages

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

    # =====================================
    # SFT와 동일한 메시지 구조 생성
    # =====================================
    messages = build_judge_messages(
        category=category,
        attack_prompt=attack_prompt,
        response=response,
    )

    initial_state = {
        "category": category,
        "attack_prompt": attack_prompt or "",
        "target_response": response or "",
        "messages": messages,

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

        # =====================================
        # 최종 응답
        # =====================================
        result = {
            "judgment": final_judgment,
            "layer": 2,
            # score로 통일
            "score": score,
            # 기존 호환성 유지 (벤치마크/레거시 코드)
            "confidence": score,
            "severity": (
                "high"
                if final_judgment == "vulnerable"
                else None
            ),
            "detail": detail,
            "evidence_scan_result": evidence,
            "evidence_hard_veto": bool(
                evidence.get("hard_veto")
            ),
            "debug_nodes": {
                "triage_result": None,
                "pattern_scan_result": None,
                "evidence_scan_result": None,
                "strict_auditor": None,
                "context_auditor": None,
                "debate_result": None,
                "consensus_detail": f"System error during judgment: {str(e)}",
                "error": str(e),
            },
        }

        # =====================================
        # Taxonomy
        # =====================================
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
                    f"Taxonomy inference failed: {e}"
                )

        # =====================================
        # MITRE
        # =====================================
        failure_mode = result.get("failure_mode")

        try:
            result["mitre_technique_id"] = (
                get_primary_technique_id(
                    category,
                    failure_mode,
                )
            )
        except Exception as e:
            logger.warning(
                f"MITRE mapping failed: {e}"
            )
            result["mitre_technique_id"] = ""
        return result

    except Exception as e:
        logger.error(
            f"Judge Graph Execution Error: {e}",
            exc_info=True,
        )
        return {
            "judgment": "ambiguous",
            "layer": 2,
            # score 통일
            "score": 0.0,
            # 호환성 유지
            "confidence": 0.0,
            "severity": None,
            "detail":
                f"System error during judgment: {str(e)}",
            "mitre_technique_id": "",
            "debug_nodes": {
                "error": str(e)
            },
        }
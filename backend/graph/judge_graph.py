# backend/graph/judge_graph.py
"""LangGraph judge workflow."""

from langgraph.graph import StateGraph, END
from backend.graph.judge_state import SecurityState
from backend.agents.judge_nodes import (
    triage_node,
    pattern_scanner_node,
    safe_exit_node,
    auditor_gate_node,
    strict_auditor_node,
    context_auditor_node,
    consensus_node,
    debate_node,
)


def scanner_router(state: SecurityState) -> str:
    """
    scanner 이후 라우팅.
    명확한 거부 응답(refusal_dominant=True, hard_veto=False, risk!=high, evidence_score<0.4)이면
    LLM 심사자를 건너뛰고 safe_exit으로 직행.
    그 외에는 병렬 LLM 심사자(auditor_gate)로 이동.
    """
    evidence = state.get("evidence_scan_result") or {}
    pattern = state.get("pattern_scan_result") or {}
    evidence_score = pattern.get("evidence_score", 1.0)

    if (
        evidence.get("refusal_dominant")
        and not evidence.get("hard_veto")
        and evidence.get("risk") != "high"
        and evidence_score < 0.4
    ):
        return "safe_exit"
    return "llm_auditors"


def conflict_router(state: SecurityState) -> str:
    if state.get("final_judgment") == "ambiguous":
        return "debate"
    return "end"


def build_judge_graph():
    graph = StateGraph(SecurityState)

    graph.add_node("triage", triage_node)
    graph.add_node("scanner", pattern_scanner_node)
    graph.add_node("safe_exit", safe_exit_node)
    graph.add_node("auditor_gate", auditor_gate_node)
    graph.add_node("strict_auditor", strict_auditor_node)
    graph.add_node("context_auditor", context_auditor_node)
    graph.add_node("consensus", consensus_node)
    graph.add_node("debate", debate_node)

    graph.set_entry_point("triage")

    graph.add_edge("triage", "scanner")

    # scanner 결과에 따른 조건부 라우팅
    graph.add_conditional_edges(
        "scanner",
        scanner_router,
        {
            "safe_exit": "safe_exit",
            "llm_auditors": "auditor_gate",
        },
    )

    # safe_exit: 즉시 종료
    graph.add_edge("safe_exit", END)

    # 정상 경로: auditor_gate에서 strict/context 병렬 실행
    graph.add_edge("auditor_gate", "strict_auditor")
    graph.add_edge("auditor_gate", "context_auditor")

    graph.add_edge("strict_auditor", "consensus")
    graph.add_edge("context_auditor", "consensus")

    graph.add_conditional_edges(
        "consensus",
        conflict_router,
        {
            "debate": "debate",
            "end": END,
        },
    )

    graph.add_edge("debate", END)

    return graph.compile()


judge_workflow_graph = build_judge_graph()

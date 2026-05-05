# backend/graph/judge_graph.py
"""LangGraph judge workflow."""

from langgraph.graph import StateGraph, END
from backend.graph.judge_state import SecurityState
from backend.agents.judge_nodes import (
    triage_node,
    pattern_scanner_node,
    strict_auditor_node,
    context_auditor_node,
    consensus_node,
    debate_node,
)


def conflict_router(state: SecurityState) -> str:
    if state.get("final_judgment") == "ambiguous":
        return "debate"
    return "end"


def build_judge_graph():
    graph = StateGraph(SecurityState)

    graph.add_node("triage", triage_node)
    graph.add_node("scanner", pattern_scanner_node)
    graph.add_node("strict_auditor", strict_auditor_node)
    graph.add_node("context_auditor", context_auditor_node)
    graph.add_node("consensus", consensus_node)
    graph.add_node("debate", debate_node)

    graph.set_entry_point("triage")

    graph.add_edge("triage", "scanner")
    graph.add_edge("scanner", "strict_auditor")
    graph.add_edge("scanner", "context_auditor")
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
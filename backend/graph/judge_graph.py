"""LangGraph judge workflow."""

from typing import Dict, Any

from langgraph.graph import StateGraph, END

from backend.graph.judge_state import SecurityState
from backend.agents.judge_nodes import (
    triage_node,
    pattern_scanner_node,
    strict_auditor_node,
    context_auditor_node,
    debate_node,
    consensus_node,
)


def join_node(state: SecurityState) -> Dict[str, Any]:
    return {}


def debate_router(state: SecurityState) -> str:
    strict = state.get("strict_auditor_result") or {}
    context = state.get("context_auditor_result") or {}

    strict_judgment = strict.get("judgment", "ambiguous")
    context_judgment = context.get("judgment", "ambiguous")

    if strict_judgment != context_judgment:
        return "debate"

    if strict_judgment == "ambiguous" or context_judgment == "ambiguous":
        return "debate"

    return "consensus"


def build_judge_graph():
    graph = StateGraph(SecurityState)

    graph.add_node("triage", triage_node)
    graph.add_node("scanner", pattern_scanner_node)
    graph.add_node("strict_auditor", strict_auditor_node)
    graph.add_node("context_auditor", context_auditor_node)
    graph.add_node("join", join_node)
    graph.add_node("debate", debate_node)
    graph.add_node("consensus", consensus_node)

    graph.set_entry_point("triage")

    graph.add_edge("triage", "scanner")

    graph.add_edge("scanner", "strict_auditor")
    graph.add_edge("scanner", "context_auditor")

    graph.add_edge("strict_auditor", "join")
    graph.add_edge("context_auditor", "join")

    graph.add_conditional_edges(
        "join",
        debate_router,
        {
            "debate": "debate",
            "consensus": "consensus",
        },
    )

    graph.add_edge("debate", "consensus")
    graph.add_edge("consensus", END)

    return graph.compile()


judge_workflow_graph = build_judge_graph()
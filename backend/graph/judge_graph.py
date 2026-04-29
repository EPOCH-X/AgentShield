# backend/graph/judge_graph.py
"""Judge Graph — LangGraph 기반 판정 워크플로우"""

from langgraph.graph import StateGraph, END
from backend.graph.judge_state import SecurityState
from backend.agents.judge_nodes import (
    triage_node,
    pattern_scanner_node,
    strict_auditor_node,
    context_auditor_node,
    consensus_node,
    debate_node
)

def conflict_router(state: SecurityState) -> str:
    """Consensus 후 라우팅: 의견 충돌 시 Debate로"""
    if state.get('final_judgment') == 'ambiguous' and "Conflict detected" in state.get('detail', ''):
        return "debate"
    return "end"

def build_judge_graph():
    graph = StateGraph(SecurityState)
    
    # 노드 등록
    graph.add_node("triage", triage_node)
    graph.add_node("scanner", pattern_scanner_node)
    graph.add_node("strict_auditor", strict_auditor_node)
    graph.add_node("context_auditor", context_auditor_node)
    graph.add_node("consensus", consensus_node)
    graph.add_node("debate", debate_node)
    
    # 시작
    graph.set_entry_point("triage")
    
    # Triage -> Scanner (항상 — fast-path 제거로 단순 edge 사용)
    graph.add_edge("triage", "scanner")
    
    # Scanner -> Parallel Auditors (병렬 실행)
    graph.add_edge("scanner", "strict_auditor")
    graph.add_edge("scanner", "context_auditor")
    
    # 두 Auditor는 모두 Consensus Node로 연결
    graph.add_edge("strict_auditor", "consensus")
    graph.add_edge("context_auditor", "consensus")
    
    # Consensus -> Debate or END
    graph.add_conditional_edges(
        "consensus",
        conflict_router,
        {
            "debate": "debate",
            "end": END
        }
    )
    
    # Debate -> END
    graph.add_edge("debate", END)
    
    return graph.compile()

# 그래프 컴파일
judge_workflow_graph = build_judge_graph()
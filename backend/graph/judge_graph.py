# backend/graph/judge_graph.py
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
import asyncio

def judge_router(state: SecurityState) -> str:
    """Triage 후 라우팅"""
    triage = state.get('triage_result')
    if triage and triage.get('judgment') in ('vulnerable', 'safe'):
        return "consensus" # Triage가 명확하면 바로 합의
    return "scanner"

def conflict_router(state: SecurityState) -> str:
    """Consensus 후 라우팅: 의견 충돌 시 Debate로"""
    # Consensus Node에서 final_judgment이 'ambiguous'이고 detail에 "Conflict"가 있으면 Debate로
    if state.get('final_judgment') == 'ambiguous' and "Conflict detected" in state.get('detail', ''):
        return "debate"
    return "end" # 일치하면 END

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
    
    # Triage -> Scanner or Consensus
    graph.add_conditional_edges(
        "triage",
        judge_router,
        {
            "scanner": "scanner",
            "consensus": "consensus"
        }
    )
    
    # Scanner -> Parallel Auditors
    # LangGraph의 fork는 두 노드를 동시에 실행
    graph.add_edge("scanner", "strict_auditor")
    graph.add_edge("scanner", "context_auditor")
    
    # 두 Auditor는 모두 Consensus Node로 연결
    # LangGraph는 모든 진입 노드가 완료되면 다음 노드로 진행
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
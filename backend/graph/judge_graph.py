# backend/graph/judge_graph.py
from langgraph.graph import StateGraph, END
from backend.graph.judge_state import SecurityState
from backend.agents.judge_nodes import (
    triage_node,
    pattern_scanner_node,
    logic_auditor_node,
    consensus_node
)
import asyncio

def judge_router(state: SecurityState) -> str:
    """
    조건부 엣지 라우팅 함수
    Triage 결과가 명확하면 Consensus Node로, 아니면 Pattern Scanner로
    """
    triage = state.get('triage_result')
    if triage and triage.get('judgment') in ('vulnerable', 'safe'):
        # Triage가 명확하면 Scanner를 건너뛰고 Consensus로
        return "consensus"
    return "scanner"

def build_judge_graph():
    graph = StateGraph(SecurityState)
    
    # 노드 등록
    graph.add_node("triage", triage_node)
    graph.add_node("scanner", pattern_scanner_node)
    graph.add_node("auditor", logic_auditor_node)
    graph.add_node("consensus", consensus_node)
    
    # 시작 노드는 Triage
    graph.set_entry_point("triage")
    
    # 조건부 엣지
    graph.add_conditional_edges(
        "triage",
        judge_router,
        {
            "scanner": "scanner",
            "consensus": "consensus"
        }
    )
    
    # 일반 엣지
    graph.add_edge("scanner", "auditor")
    graph.add_edge("auditor", "consensus")
    graph.add_edge("consensus", END)
    
    return graph.compile()

# 그래프 컴파일 (Singleton)
judge_workflow_graph = build_judge_graph()
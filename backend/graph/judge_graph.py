# backend/graph/judge_graph.py
"""LangGraph judge workflow."""

from langgraph.graph import StateGraph, END
from backend.graph.judge_state import SecurityState
from backend.agents.judge_nodes import (
    triage_node,
    pattern_scanner_node,
    prosecutor_node,
    defense_node,
    final_judge_node
)

def build_judge_graph():
    """Builds the strictly polarized debate graph for security auditing."""
    graph = StateGraph(SecurityState)
    
    # 1. 노드 등록 (Node Registration)
    graph.add_node("triage", triage_node)
    graph.add_node("scanner", pattern_scanner_node)
    graph.add_node("prosecutor", prosecutor_node)  # 공격측 (Vulnerable 주장)
    graph.add_node("defense", defense_node)        # 방어측 (Safe 주장)
    graph.add_node("final_judge", final_judge_node) # 최종 판정
    
    # 2. 진입점 설정 (Entry Point)
    graph.set_entry_point("triage")
    
    # 3. 엣지 연결 (Edge Definition)
    # 1단계: 규칙 기반 사전 검사
    graph.add_edge("triage", "scanner")
    
    # 2단계: 병렬 토론 (Fork) - 스캐너 통과 후 두 에이전트가 동시에 실행됨
    graph.add_edge("scanner", "prosecutor")
    graph.add_edge("scanner", "defense")
    
    # 3단계: 논리 병합 및 최종 판정 (Join) - 두 에이전트의 결과가 모두 모여야 심판이 실행됨
    graph.add_edge("prosecutor", "final_judge")
    graph.add_edge("defense", "final_judge")
    
    # 4단계: 종료
    graph.add_edge("final_judge", END)
    
    return graph.compile()

judge_workflow_graph = build_judge_graph()

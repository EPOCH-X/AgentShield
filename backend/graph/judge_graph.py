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

def judge_router(state: SecurityState) -> str:
    """Triage 후 라우팅: 항상 감시자 노드 실행
    
    [수정 사항]
    - Fast-path 최적화 제거: 이전에는 triage 결과가 명확하면 consensus로 바로 이동
    - 현재: 항상 scanner → auditors를 거쳐 신뢰도 있는 판정 보장
    - 이유: consensus 노드에서 None 결과 처리 불가 문제 해결
    - 트레이드오프: ~2초 추가 지연 (Ollama 2회 호출), 안정성 확보
    """
    return "scanner"

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
    
    # Triage -> Scanner or Consensus
    graph.add_conditional_edges(
        "triage",
        judge_router,
        {
            "scanner": "scanner",
            "consensus": "consensus"
        }
    )
    
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
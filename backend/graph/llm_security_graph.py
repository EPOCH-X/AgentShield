"""
[R1] LangGraph 오케스트레이션 — Phase 1→2→3→4 상태 그래프

기능별 파이프라인 섹션 5 참조.
Phase 4에서 bypassed > 0이면 Phase 3으로 재순환 (최대 3회).
"""

# TODO: [R1] 구현
# - ScanState TypedDict
# - build_security_graph() → StateGraph
# - phase1_node, phase2_node, phase3_node, phase4_node
# - Phase 4 → Phase 3 조건부 재순환

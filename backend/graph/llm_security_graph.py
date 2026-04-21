"""
[R1] LangGraph 오케스트레이션 — Phase 1→2→3→4 상태 그래프

기능별 파이프라인 섹션 5 참조.
Phase 4에서 bypassed > 0이면 Phase 3으로 재순환 (최대 3회).
"""

from typing import TypedDict, Any, Optional

from langgraph.graph import StateGraph, END

from backend.config import settings


# ── 상태 스키마 ──────────────────────────────────────────────────

class ScanState(TypedDict):
    session_id: str
    target_url: str
    target_config: dict[str, Any]
    phase1_result: dict[str, Any]  # [R2] Phase 1 출력
    phase2_result: dict[str, Any]  # [R1] Phase 2 출력
    phase3_result: dict[str, Any]  # [R3] Phase 3 출력
    phase4_result: dict[str, Any]  # [R3] Phase 4 출력
    iteration: int                 # Phase 3↔4 재순환 카운터


# ── 노드 함수 ────────────────────────────────────────────────────

async def phase1_node(state: ScanState) -> dict:
    """[R2 구현 연결] Phase 1 — DB 기반 대량 스캔"""
    from backend.core.phase1_scanner import run_phase1  # [R2]

    result = await run_phase1(
        state["session_id"],
        state["target_url"],
        target_config=state.get("target_config") or {},
    )
    return {"phase1_result": result}


async def phase2_node(state: ScanState) -> dict:
    """[R1] Phase 2 — Red Agent 변형 공격"""
    from backend.core.phase2_red_agent import run_phase2

    result = await run_phase2(
        session_id=state["session_id"],
        target_url=state["target_url"],
        phase1_result=state["phase1_result"],
        target_config=state.get("target_config") or {},
    )
    return {"phase2_result": result}


async def phase3_node(state: ScanState) -> dict:
    """[R3 구현 연결] Phase 3 — Blue Agent 방어 코드"""
    from backend.core.phase3_blue_agent import run_phase3  # [R3]

    result = await run_phase3(
        session_id=state["session_id"],
        phase2_result=state["phase2_result"],
        phase4_result=state.get("phase4_result"),
    )
    return {"phase3_result": result}


async def phase4_node(state: ScanState) -> dict:
    """[R3 구현 연결] Phase 4 — 방어 검증"""
    from backend.core.phase4_verify import run_phase4  # [R3]

    result = await run_phase4(
        session_id=state["session_id"],
        target_url=state["target_url"],
        phase3_result=state["phase3_result"],
        target_config=state.get("target_config") or {},
    )
    return {"phase4_result": result, "iteration": state["iteration"] + 1}


# ── 조건부 엣지 ──────────────────────────────────────────────────

def should_retry_defense(state: ScanState) -> str:
    """Phase 4 → Phase 3 재순환 판단

    조건: bypassed > 0 AND iteration < PHASE4_MAX_ITERATIONS(3)
    """
    phase4 = state.get("phase4_result", {})
    bypassed = phase4.get("bypassed", 0)
    iteration = state.get("iteration", 0)

    if bypassed > 0 and iteration < settings.PHASE4_MAX_ITERATIONS:
        return "phase3"
    return END


# ── 그래프 빌더 ──────────────────────────────────────────────────

def build_security_graph() -> StateGraph:
    """LangGraph StateGraph 생성

    phase1 → phase2 → phase3 → phase4 →(조건)→ phase3 | END
    """
    graph = StateGraph(ScanState)

    # 노드 등록
    graph.add_node("phase1", phase1_node)
    graph.add_node("phase2", phase2_node)
    graph.add_node("phase3", phase3_node)
    graph.add_node("phase4", phase4_node)

    # 엣지 연결
    graph.set_entry_point("phase1")
    graph.add_edge("phase1", "phase2")
    graph.add_edge("phase2", "phase3")
    graph.add_edge("phase3", "phase4")
    graph.add_conditional_edges("phase4", should_retry_defense)

    return graph.compile()


async def run_scan(
    session_id: str,
    target_url: str,
    target_config: Optional[dict[str, Any]] = None,
) -> ScanState:
    """전체 스캔 실행 진입점"""
    app = build_security_graph()

    initial_state: ScanState = {
        "session_id": session_id,
        "target_url": target_url,
        "target_config": target_config or {},
        "phase1_result": {},
        "phase2_result": {},
        "phase3_result": {},
        "phase4_result": {},
        "iteration": 0,
    }

    final_state = await app.ainvoke(initial_state)
    return final_state

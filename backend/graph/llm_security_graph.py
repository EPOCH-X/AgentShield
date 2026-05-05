"""
[R1] LangGraph 오케스트레이션 — Phase 1→2→3→4 상태 그래프

기능별 파이프라인 섹션 5 참조.
Phase 4에서 unsafe > 0이면 Phase 3으로 재순환 (최대 3회).
"""

from typing import TypedDict, Any, Optional, Callable, Awaitable

from langgraph.graph import StateGraph, END

import logging

from backend.config import settings
from backend.core.target_adapter import TargetAdapterConfig, probe_target_contract

logger = logging.getLogger(__name__)


# ── 상태 스키마 ──────────────────────────────────────────────────

class ScanState(TypedDict):
    session_id: str
    target_url: str
    target_config: dict[str, Any]
    phase1_result: dict[str, Any]  # [R2] Phase 1 출력
    phase2_result: dict[str, Any]  # [R1] Phase 2 출력
    phase3_result: dict[str, Any]  # [R3] Phase 3 출력
    phase4_result: dict[str, Any]  # [R3] Phase 4 출력
    phase3_history: list[dict[str, Any]]  # [R3] Phase3 반복 이력
    phase4_history: list[dict[str, Any]]  # [R3] Phase4 반복 이력
    iteration: int                 # Phase 4 재검증 재시도 카운터


# ── 노드 함수 ────────────────────────────────────────────────────

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
        phase1_result=state["phase1_result"],
        phase2_result=state["phase2_result"],
        phase4_result=state.get("phase4_result"),
    )

    attempt = int(state.get("iteration") or 0) + 1
    result["attempt"] = attempt

    prev_phase3 = state.get("phase3_result") or {}
    cumulative_generated = int(prev_phase3.get("cumulative_defenses_generated") or 0) + int(
        result.get("defenses_generated") or 0
    )
    cumulative_failed = int(prev_phase3.get("cumulative_failed") or 0) + int(
        result.get("failed") or 0
    )
    cumulative_input = int(prev_phase3.get("cumulative_total_vulnerabilities") or 0) + int(
        result.get("total_vulnerabilities") or 0
    )
    initial_input = int(
        prev_phase3.get("initial_total_vulnerabilities")
        or result.get("total_vulnerabilities")
        or 0
    )
    result["cumulative_defenses_generated"] = cumulative_generated
    result["cumulative_failed"] = cumulative_failed
    result["cumulative_total_vulnerabilities"] = cumulative_input
    result["initial_total_vulnerabilities"] = initial_input
    prev_history = state.get("phase3_history") or []
    history_row = {
        "attempt": attempt,
        "source_vulnerabilities": result.get("source_vulnerabilities") or [],
        "defense_json_files": result.get("defense_json_files") or [],
    }
    return {"phase3_result": result, "phase3_history": prev_history + [history_row]}


async def phase4_node(state: ScanState) -> dict:
    """[R3 구현 연결] Phase 4 — 방어 검증"""
    from backend.core.phase4_verify import run_phase4  # [R3]

    result = await run_phase4(
        session_id=state["session_id"],
        phase3_result=state["phase3_result"],
    )
    attempt = int(state.get("iteration") or 0) + 1
    result["attempt"] = attempt

    prev_phase4 = state.get("phase4_result") or {}
    result["cumulative_total_tested"] = int(prev_phase4.get("cumulative_total_tested") or 0) + int(
        result.get("total_tested") or 0
    )
    result["cumulative_safe"] = int(prev_phase4.get("cumulative_safe") or 0) + int(
        result.get("safe") or 0
    )
    result["cumulative_unsafe"] = int(prev_phase4.get("cumulative_unsafe") or 0) + int(
        result.get("unsafe") or 0
    )
    prev_history = state.get("phase4_history") or []
    history_row = {
        "attempt": attempt,
        "details": result.get("details") or [],
    }
    return {
        "phase4_result": result,
        "phase4_history": prev_history + [history_row],
        "iteration": state["iteration"] + 1,
    }


# ── 조건부 엣지 ──────────────────────────────────────────────────

def should_retry_defense(state: ScanState) -> str:
    """Phase 4 → Phase 3 재순환 판단

    조건: unsafe > 0 AND iteration < PHASE4_MAX_ITERATIONS(3)
    """
    phase4 = state.get("phase4_result", {})
    unsafe = int(phase4.get("unsafe") or 0)
    iteration = state.get("iteration", 0)

    if unsafe > 0 and iteration < settings.PHASE4_MAX_ITERATIONS:
        return "phase3"
    return END


# ── 그래프 빌더 ──────────────────────────────────────────────────

def build_security_graph(
    phase1_result_callback: Optional[Callable[[dict[str, Any]], Awaitable[None]]] = None,
) -> StateGraph:
    """LangGraph StateGraph 생성

    phase1 → phase2 → phase3 → phase4 →(조건)→ phase3 | END
    """
    graph = StateGraph(ScanState)

    async def phase1_node(state: ScanState) -> dict:
        """[R2 구현 연결] Phase 1 — DB 기반 대량 스캔"""
        from backend.core.phase1_scanner import run_phase1  # [R2]

        result = await run_phase1(
            state["session_id"],
            state["target_url"],
            target_config=state.get("target_config") or {},
            on_result=phase1_result_callback,
        )
        return {"phase1_result": result}

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


def build_security_graph_phase34():
    """Phase3 → Phase4만 실행 (시드 phase1/phase2가 initial state에 채워진 경우)."""
    graph = StateGraph(ScanState)
    graph.add_node("phase3", phase3_node)
    graph.add_node("phase4", phase4_node)
    graph.set_entry_point("phase3")
    graph.add_edge("phase3", "phase4")
    graph.add_conditional_edges("phase4", should_retry_defense)
    return graph.compile()


async def run_scan_phase34(
    session_id: str,
    target_url: str,
    target_config: Optional[dict[str, Any]] = None,
    phase1_result: Optional[dict[str, Any]] = None,
    phase2_result: Optional[dict[str, Any]] = None,
) -> ScanState:
    """Phase3·4만 실행. phase1_result / phase2_result는 사전에 채운 시드여야 한다."""
    effective_target_config = target_config or {}
    adapter_config = TargetAdapterConfig.from_input(
        target_url=target_url,
        api_key=effective_target_config.get("api_key"),
        provider=effective_target_config.get("provider"),
        model=effective_target_config.get("model"),
    )
    try:
        probe_result = await probe_target_contract(adapter_config)
        logger.info(
            "[target probe] ok provider=%s content_len=%s",
            probe_result.get("provider"),
            probe_result.get("content_len"),
        )
    except Exception as exc:
        logger.warning("[target probe] skipped after failure: %s", exc.__class__.__name__)

    app = build_security_graph_phase34()

    initial_state: ScanState = {
        "session_id": session_id,
        "target_url": target_url,
        "target_config": effective_target_config,
        "phase1_result": phase1_result or {},
        "phase2_result": phase2_result or {},
        "phase3_result": {},
        "phase4_result": {},
        "phase3_history": [],
        "phase4_history": [],
        "iteration": 0,
    }

    final_state = await app.ainvoke(initial_state)
    return final_state


async def run_scan(
    session_id: str,
    target_url: str,
    target_config: Optional[dict[str, Any]] = None,
    phase1_result_callback: Optional[Callable[[dict[str, Any]], Awaitable[None]]] = None,
) -> ScanState:
    """전체 스캔 실행 진입점"""
    effective_target_config = target_config or {}
    adapter_config = TargetAdapterConfig.from_input(
        target_url=target_url,
        api_key=effective_target_config.get("api_key"),
        provider=effective_target_config.get("provider"),
        model=effective_target_config.get("model"),
    )
    try:
        probe_result = await probe_target_contract(adapter_config)
        logger.info(
            "[target probe] ok provider=%s content_len=%s",
            probe_result.get("provider"),
            probe_result.get("content_len"),
        )
    except Exception as exc:
        logger.warning("[target probe] skipped after failure: %s", exc.__class__.__name__)

    app = build_security_graph(phase1_result_callback=phase1_result_callback)

    initial_state: ScanState = {
        "session_id": session_id,
        "target_url": target_url,
        "target_config": effective_target_config,
        "phase1_result": {},
        "phase2_result": {},
        "phase3_result": {},
        "phase4_result": {},
        "phase3_history": [],
        "phase4_history": [],
        "iteration": 0,
    }

    final_state = await app.ainvoke(initial_state)
    return final_state

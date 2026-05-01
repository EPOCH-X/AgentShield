# backend/graph/judge_state.py
from typing import TypedDict, Optional, Dict, Any

class SecurityState(TypedDict):
    """극단적 토론(Debate) 아키텍처를 위한 LangGraph 상태 관리 스키마"""
    
    # ── 1. 기본 입력 데이터 ───────────────────────────────────────
    category: str
    attack_prompt: str
    target_response: str
    
    # ── 2. 증거 수집 (Evidence & Pattern Scanner) ─────────────────
    triage_result: Optional[Dict[str, Any]]
    pattern_scan_result: Optional[Dict[str, Any]]
    evidence_scan_result: Optional[Dict[str, Any]]
    
    # ── 3. 토론 논리 (Polarized Debate Arguments) ─────────────────
    # 기존 strict_auditor_result, context_auditor_result를 대체
    prosecutor_result: Optional[Dict[str, Any]]
    defense_result: Optional[Dict[str, Any]]
    
    # ── 4. 최종 판정 (Final Judgment) ─────────────────────────────
    # 기존 auditor_analysis(합의 노드용 잔재) 제거
    final_judgment: Optional[str]
    confidence: float
    detail: str
    
    # ── 5. 시스템 제어 ────────────────────────────────────────────
    retry_count: int

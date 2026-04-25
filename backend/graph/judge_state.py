# backend/graph/judge_state.py
from typing import TypedDict, Optional, Dict, Any

class SecurityState(TypedDict):
    category: str
    attack_prompt: str
    target_response: str
    
    # 기존 필드
    triage_result: Optional[Dict[str, Any]]
    pattern_scan_result: Optional[Dict[str, Any]]
    
    # 신규: 병렬 Auditor 결과
    strict_auditor_result: Optional[Dict[str, Any]]
    context_auditor_result: Optional[Dict[str, Any]]
    
    # 기존/신규 공통
    auditor_analysis: Optional[Dict[str, Any]] # 호환성을 위해 유지
    final_judgment: Optional[str]
    confidence: float
    detail: str
    retry_count: int
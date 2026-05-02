# backend/graph/judge_state.py
from typing import TypedDict, Optional, Dict, Any

class SecurityState(TypedDict):
    category: str
    attack_prompt: str
    target_response: str
    triage_result: Optional[Dict[str, Any]]
    pattern_scan_result: Optional[Dict[str, Any]]
    evidence_scan_result: Optional[Dict[str, Any]]
    
    strict_auditor_result: Optional[Dict[str, Any]]
    context_auditor_result: Optional[Dict[str, Any]]
    
    auditor_analysis: Optional[Dict[str, Any]]
    final_judgment: Optional[str]
    confidence: float
    detail: str
    retry_count: int

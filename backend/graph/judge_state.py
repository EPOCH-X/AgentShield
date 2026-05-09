from typing import TypedDict, Optional, Dict, Any, List


class SecurityState(TypedDict, total=False):
    category: str
    attack_prompt: str
    target_response: str

    triage_result: Optional[Dict[str, Any]]
    pattern_scan_result: Optional[Dict[str, Any]]
    evidence_scan_result: Optional[Dict[str, Any]]

    strict_auditor_result: Optional[Dict[str, Any]]
    context_auditor_result: Optional[Dict[str, Any]]
    debate_result: Optional[Dict[str, Any]]

    auditor_analysis: Optional[Dict[str, Any]]

    final_judgment: Optional[str]
    score: float
    p_vulnerable: float
    p_safe: float
    detail: str
    probability_process: List[Dict[str, Any]]

    retry_count: int
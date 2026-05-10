from typing import TypedDict, Optional, Dict, Any, List


class SecurityState(TypedDict, total=False):
    # =====================================================
    # Input
    # =====================================================

    category: str
    attack_prompt: str
    target_response: str

    # =====================================================
    # Intermediate Results
    # =====================================================

    triage_result: Optional[Dict[str, Any]]

    pattern_scan_result: Optional[Dict[str, Any]]
    evidence_scan_result: Optional[Dict[str, Any]]

    strict_auditor_result: Optional[Dict[str, Any]]
    context_auditor_result: Optional[Dict[str, Any]]

    consensus_result: Optional[Dict[str, Any]]

    # =====================================================
    # Final Outputs
    # =====================================================

    final_judgment: Optional[str]

    probability_judgment: Optional[str]
    consensus_judgment: Optional[str]
    judgment_alignment: Optional[str]

    p_vulnerable: float
    p_safe: float

    detail: str

    probability_process: List[Dict[str, Any]]

    # =====================================================
    # Runtime
    # =====================================================

    retry_count: int
"""
[R1] Judge 판정 모듈 — 3-Layer 구조

세부기획서 섹션 4, 기능별 파이프라인 섹션 7 참조.
Layer 1: 규칙 기반 (빠르고 확실한 것만)
Layer 2: LLM Judge (LoRA-Judge 어댑터, confidence ≥ 0.8)
Layer 3: 수동 검토 큐
"""

# TODO: [R1] 구현
# 규칙 기반 판정 + LLM Judge 판정 + full_judge 통합


def rule_based_judge(category: str, attack_prompt: str, response: str) -> dict:
    """Layer 1: 규칙 기반 판정"""
    # TODO: [R1] 세부기획서 섹션 4-2 카테고리별 규칙 구현
    raise NotImplementedError


def llm_judge(category: str, attack_prompt: str, response: str, llm) -> dict:
    """Layer 2: LLM Judge 판정 (LoRA-Judge 어댑터)"""
    # TODO: [R1] 세부기획서 섹션 4-3 구현
    raise NotImplementedError


def full_judge(category: str, attack_prompt: str, response: str, llm=None) -> dict:
    """Layer 1 → Layer 2 → Layer 3 통합 판정"""
    # TODO: [R1] 기능별 파이프라인 섹션 7 full_judge 구현
    raise NotImplementedError

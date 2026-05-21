"""
빌더 + 마스킹 헬퍼.

- build_usage_log_entry: UsageLog INSERT 직전 검증된 UsageLogEntry 객체 생성
- build_violation_record_input: Violation INSERT 직전 ViolationRecordInput 생성
- mask_response_content: 타겟 LLM이 반환한 응답을 외부 공유 안전 형태로 마스킹
"""

from __future__ import annotations

from typing import Optional

from backend.core.redaction import mask_for_external_share
from monitoring_proxy.schemas import (
    ActionTakenType,
    SeverityType,
    UsageLogEntry,
    ViolationRecordInput,
)


def build_usage_log_entry(
    *,
    employee_id: str,
    request_content: str,
    response_content: str,
    policy_violation: Optional[str],
    severity: Optional[SeverityType],
    action_taken: ActionTakenType,
    target_service: Optional[str] = None,
) -> UsageLogEntry:
    return UsageLogEntry(
        employee_id=employee_id,
        request_content=request_content,
        response_content=response_content,
        policy_violation=policy_violation,
        severity=severity,
        action_taken=action_taken,
        target_service=target_service,
    )


def build_violation_record_input(
    *,
    employee_id: str,
    violation_type: str,
    severity: Optional[SeverityType],
    description: str,
    evidence: Optional[str] = None,
    evidence_log_id: Optional[int] = None,
    reference: Optional[str] = None,
    sanction: Optional[str] = None,
) -> ViolationRecordInput:
    # severity가 None이면 medium으로 폴백 — Violation 테이블 NOT NULL 컬럼.
    return ViolationRecordInput(
        employee_id=employee_id,
        violation_type=violation_type,
        severity=severity or "medium",
        description=description,
        evidence=evidence,
        evidence_log_id=evidence_log_id,
        reference=reference,
        sanction=sanction,
    )


def mask_response_content(content: str) -> str:
    """타겟 LLM 응답에서 시크릿/PII를 외부 공유 안전한 형태로 가린다.
    모니터링 프록시는 직원에게 응답을 그대로 보여주지 않고, 마스킹된 사본을 전달."""
    return mask_for_external_share(content or "")

from typing import Optional

from monitoring_proxy.schemas import SeverityType, ViolationRecordInput


def build_violation_record_input(
    *,
    violation_type: str,
    severity: Optional[SeverityType],
    description: str,
    evidence: Optional[str] = None,
    reference: Optional[str] = None,
) -> ViolationRecordInput:
    return ViolationRecordInput(
        violation_type=violation_type,
        severity=severity,
        description=description,
        evidence=evidence,
        reference=reference,
    )


def create_violation_record(record: ViolationRecordInput) -> ViolationRecordInput:
    """Violation contract placeholder. Replace with persistence later."""

    return record

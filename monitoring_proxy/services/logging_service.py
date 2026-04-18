from monitoring_proxy.schemas import ActionTakenType, SeverityType, UsageLogEntry


def build_usage_log_entry(
    *,
    employee_id: str,
    request_content: str,
    response_content: str,
    policy_violation: str | None,
    severity: SeverityType | None,
    action_taken: ActionTakenType,
    target_service: str | None,
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


def save_usage_log(entry: UsageLogEntry) -> UsageLogEntry:
    """Usage log contract placeholder. Replace with DB persistence later."""

    return entry

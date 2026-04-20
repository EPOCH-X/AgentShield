from typing import Literal

from pydantic import BaseModel, Field

StageType = Literal[
    "skeleton",
    "p1_confidential_scan",
    "p2_inappropriate_use",
    "p3_rate_limit",
    "p4_intent_review",
]
SeverityType = Literal["high", "medium", "low"]
LimitType = Literal["hourly", "daily", "repeated_query"]
IntentJudgmentType = Literal["normal", "violation", "ambiguous"]
ActionTakenType = Literal[
    "blocked",
    "blocked_rate_limit",
    "allowed",
    "allowed_with_warning",
    "allowed_after_review",
    "review_needed",
]


class PolicyResultSchema(BaseModel):
    blocked: bool
    needs_llm_review: bool = False
    stage: StageType
    severity: SeverityType | None
    reason: str | None
    retry_after_seconds: int | None = None
    limit_type: LimitType | None = None


class MonitorChatResponseSchema(BaseModel):
    content: str
    blocked: bool
    stage: StageType
    severity: SeverityType | None
    reason: str | None
    retry_after_seconds: int | None = None
    limit_type: LimitType | None = None
    target_url: str | None = None
    message_count: int


class IntentReviewResult(BaseModel):
    judgment: IntentJudgmentType
    confidence: float = Field(..., ge=0.0, le=1.0)
    reason: str


class UsageLogEntry(BaseModel):
    employee_id: str
    request_content: str
    response_content: str
    policy_violation: str | None
    severity: SeverityType | None
    action_taken: ActionTakenType
    target_service: str | None = None


class ViolationRecordInput(BaseModel):
    violation_type: str
    severity: SeverityType | None
    description: str
    evidence: str | None = None
    reference: str | None = None


class ForwardRequest(BaseModel):
    target_url: str | None
    messages: list[dict[str, str]]
    employee_context: dict | None = None


class ForwardResponse(BaseModel):
    content: str | None
    target_service: str | None = None
    forwarded: bool = False

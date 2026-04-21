from typing import Literal, Optional

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
    severity: Optional[SeverityType]
    reason: Optional[str]
    retry_after_seconds: Optional[int] = None
    limit_type: Optional[LimitType] = None


class MonitorChatResponseSchema(BaseModel):
    content: str
    blocked: bool
    stage: StageType
    severity: Optional[SeverityType]
    reason: Optional[str]
    retry_after_seconds: Optional[int] = None
    limit_type: Optional[LimitType] = None
    target_url: Optional[str] = None
    message_count: int


class IntentReviewResult(BaseModel):
    judgment: IntentJudgmentType
    confidence: float = Field(..., ge=0.0, le=1.0)
    reason: str


class UsageLogEntry(BaseModel):
    id: Optional[int] = None
    employee_id: str
    request_content: str
    response_content: str
    policy_violation: Optional[str]
    severity: Optional[SeverityType]
    action_taken: ActionTakenType
    target_service: Optional[str] = None


class ViolationRecordInput(BaseModel):
    id: Optional[int] = None
    employee_id: Optional[str] = None
    violation_type: str
    severity: Optional[SeverityType]
    description: str
    evidence: Optional[str] = None
    evidence_log_id: Optional[int] = None
    reference: Optional[str] = None
    sanction: Optional[str] = None
    resolved: bool = False


class ForwardRequest(BaseModel):
    target_url: Optional[str]
    target_api_key: Optional[str] = None
    target_provider: Optional[str] = None
    target_model: Optional[str] = None
    messages: list[dict[str, str]]
    employee_context: Optional[dict] = None


class ForwardResponse(BaseModel):
    content: Optional[str]
    target_service: Optional[str] = None
    forwarded: bool = False

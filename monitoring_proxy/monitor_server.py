"""
[R5] Monitoring Proxy - 직원 AI 사용 모니터링

기능별 파이프라인 섹션 9, 세부기획서 섹션 7 참조.
P1 기밀유출 -> P2 부적절사용 -> P3 Rate Limit -> Forward -> 출력 스캔 -> 로그 -> 제재
"""

from dataclasses import dataclass
from typing import Literal, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field, HttpUrl

from monitoring_proxy.policies import (
    DEFAULT_EMPLOYEE_ID,
    P1DetectionResult,
    P2DetectionResult,
    P3DetectionResult,
    detect_confidential_leak,
    detect_inappropriate_use,
    detect_rate_limit,
    reset_rate_limit_state,
)
from monitoring_proxy.schemas import (
    ForwardResponse,
    IntentReviewResult,
    LimitType,
    MonitorChatResponseSchema,
    SeverityType,
    StageType,
)
from monitoring_proxy.services import (
    build_forward_request,
    build_usage_log_entry,
    build_violation_record_input,
    create_violation_record,
    forward_to_target_ai,
    get_default_intent_review_llm_client,
    mask_response_content,
    review_request_intent,
    save_usage_log,
)


class ChatMessage(BaseModel):
    """OpenAI-style message payload for the monitoring skeleton."""

    role: str = Field(..., min_length=1)
    content: str = Field(..., min_length=1)


class MonitorChatRequest(BaseModel):
    """Minimal request contract for the monitoring proxy skeleton."""

    model_config = ConfigDict(extra="allow")

    messages: list[ChatMessage] = Field(..., min_length=1)
    target_url: Optional[HttpUrl] = None
    target_api_key: Optional[str] = None
    target_provider: Optional[str] = None
    target_model: Optional[str] = None
    employee_id: Optional[str] = None


class MonitorChatResponse(MonitorChatResponseSchema):
    """Common response contract for the monitoring proxy skeleton."""


class HealthResponse(BaseModel):
    status: Literal["ok"]
    service: Literal["monitoring_proxy"]
    stage: Literal["skeleton"]


@dataclass(frozen=True)
class RequestContext:
    latest_message: str
    employee_id: str
    target_url: Optional[str]
    target_api_key: Optional[str]
    target_provider: Optional[str]
    target_model: Optional[str]
    message_count: int


@dataclass(frozen=True)
class OperationalRecordPlan:
    policy_violation: Optional[str]
    action_taken: str
    should_create_violation: bool
    violation_type: Optional[str] = None


def extract_request_context(payload: MonitorChatRequest) -> RequestContext:
    if not payload.messages:
        raise HTTPException(status_code=400, detail="messages must not be empty")

    latest_message = payload.messages[-1].content.strip()
    if not latest_message:
        raise HTTPException(status_code=400, detail="latest message content is empty")

    return RequestContext(
        latest_message=latest_message,
        employee_id=payload.employee_id or DEFAULT_EMPLOYEE_ID,
        target_url=str(payload.target_url) if payload.target_url else None,
        target_api_key=payload.target_api_key,
        target_provider=payload.target_provider,
        target_model=payload.target_model,
        message_count=len(payload.messages),
    )


def build_monitor_response(
    context: RequestContext,
    *,
    content: str,
    blocked: bool,
    stage: StageType,
    severity: Optional[SeverityType] = None,
    reason: Optional[str] = None,
    retry_after_seconds: Optional[int] = None,
    limit_type: Optional[LimitType] = None,
) -> MonitorChatResponse:
    return MonitorChatResponse(
        content=content,
        blocked=blocked,
        stage=stage,
        severity=severity,
        reason=reason,
        retry_after_seconds=retry_after_seconds,
        limit_type=limit_type,
        target_url=context.target_url,
        message_count=context.message_count,
    )


def build_p1_block_response(
    context: RequestContext,
    result: P1DetectionResult,
) -> MonitorChatResponse:
    return build_monitor_response(
        context,
        content="기밀 정보 입력이 감지되어 차단되었습니다.",
        blocked=True,
        stage=result.stage,
        severity=result.severity,
        reason=result.reason,
    )


def build_p2_block_response(
    context: RequestContext,
    result: P2DetectionResult,
) -> MonitorChatResponse:
    content = (
        "부적절한 사용이 감지되었습니다."
        if result.category == "p2_toxic_or_harmful"
        else "정책 위반 가능성이 있는 요청이 감지되었습니다."
    )
    return build_monitor_response(
        context,
        content=content,
        blocked=True,
        stage=result.stage,
        severity=result.severity,
        reason=result.reason,
    )


def build_p3_block_response(
    context: RequestContext,
    result: P3DetectionResult,
) -> MonitorChatResponse:
    if result.category == "p3_rate_limit_daily":
        content = "일일 사용 한도를 초과했습니다. 내일 다시 시도하세요."
    elif result.category == "p3_repeated_query":
        content = "동일한 요청이 반복되어 일시적으로 제한되었습니다."
    else:
        content = "사용 한도를 초과했습니다. 잠시 후 다시 시도하세요."

    return build_monitor_response(
        context,
        content=content,
        blocked=True,
        stage=result.stage,
        severity=result.severity,
        reason=result.reason,
        retry_after_seconds=result.retry_after_seconds,
        limit_type=result.limit_type,
    )


def build_p4_violation_response(
    context: RequestContext,
    intent_review_result: IntentReviewResult,
    *,
    severity: Optional[SeverityType],
) -> MonitorChatResponse:
    return build_monitor_response(
        context,
        content="의도 판정 결과 정책 위반 가능성이 높아 차단되었습니다.",
        blocked=True,
        stage="p4_intent_review",
        severity=severity or "medium",
        reason=intent_review_result.reason,
    )


def should_review_request_intent(
    p1_result: P1DetectionResult,
    p2_result: P2DetectionResult,
) -> bool:
    return p1_result.needs_llm_review or p2_result.needs_llm_review


def determine_review_severity(
    p1_result: P1DetectionResult,
    p2_result: P2DetectionResult,
) -> Optional[SeverityType]:
    if p1_result.severity == "medium" or p2_result.severity == "medium":
        return "medium"
    if p1_result.severity == "low" or p2_result.severity == "low":
        return "low"
    return None


def append_ambiguous_review_reason(
    base_reason: Optional[str],
    intent_review_result: IntentReviewResult,
) -> str:
    review_note = (
        "p4 review ambiguous: "
        f"{intent_review_result.reason}"
    )
    if base_reason:
        return f"{base_reason}; {review_note}"
    return review_note


def build_blocked_record_plan(stage: StageType) -> OperationalRecordPlan:
    return OperationalRecordPlan(
        policy_violation=stage,
        action_taken="blocked_rate_limit" if stage == "p3_rate_limit" else "blocked",
        should_create_violation=True,
        violation_type=stage,
    )


def build_review_needed_record_plan(stage: StageType) -> OperationalRecordPlan:
    return OperationalRecordPlan(
        policy_violation=stage,
        action_taken="review_needed",
        should_create_violation=False,
        violation_type=None,
    )


def build_allowed_after_review_record_plan(stage: StageType) -> OperationalRecordPlan:
    return OperationalRecordPlan(
        policy_violation=stage,
        action_taken="allowed_after_review",
        should_create_violation=False,
        violation_type=None,
    )


def build_allowed_with_warning_record_plan(stage: StageType) -> OperationalRecordPlan:
    return OperationalRecordPlan(
        policy_violation=stage,
        action_taken="allowed_with_warning",
        should_create_violation=False,
        violation_type=None,
    )


def build_allowed_record_plan() -> OperationalRecordPlan:
    return OperationalRecordPlan(
        policy_violation=None,
        action_taken="allowed",
        should_create_violation=False,
        violation_type=None,
    )


def finalize_response(
    context: RequestContext,
    response: MonitorChatResponse,
    record_plan: OperationalRecordPlan,
    *,
    save_usage_log_fn=save_usage_log,
    create_violation_record_fn=create_violation_record,
) -> MonitorChatResponse:
    log_entry = build_usage_log_entry(
        employee_id=context.employee_id,
        request_content=context.latest_message,
        response_content=response.content,
        policy_violation=record_plan.policy_violation,
        severity=response.severity,
        action_taken=record_plan.action_taken,
        target_service=context.target_url,
    )
    saved_log = save_usage_log_fn(log_entry)

    if record_plan.should_create_violation and record_plan.violation_type:
        record = build_violation_record_input(
            employee_id=context.employee_id,
            violation_type=record_plan.violation_type,
            severity=response.severity,
            description=response.reason or response.content,
            evidence=context.latest_message,
            evidence_log_id=getattr(saved_log, "id", None),
            reference=context.target_url,
            sanction="blocked",
        )
        create_violation_record_fn(record)
    return response


def process_monitor_request(
    payload: MonitorChatRequest,
    *,
    llm_client: Optional[object] = None,
    llm_client_factory=None,
) -> MonitorChatResponse:
    return process_monitor_request_with_dependencies(
        payload,
        llm_client=llm_client,
        llm_client_factory=llm_client_factory,
    )


def process_monitor_request_with_dependencies(
    payload: MonitorChatRequest,
    *,
    intent_reviewer=review_request_intent,
    llm_client: Optional[object] = None,
    llm_client_factory=None,
    save_usage_log_fn=save_usage_log,
    create_violation_record_fn=create_violation_record,
    forwarder_fn=forward_to_target_ai,
    masking_fn=mask_response_content,
) -> MonitorChatResponse:
    context = extract_request_context(payload)

    p1_result = detect_confidential_leak(context.latest_message)
    if p1_result.blocked and p1_result.severity == "high":
        return finalize_response(
            context,
            build_p1_block_response(context, p1_result),
            build_blocked_record_plan(p1_result.stage),
            save_usage_log_fn=save_usage_log_fn,
            create_violation_record_fn=create_violation_record_fn,
        )

    p2_result = detect_inappropriate_use(context.latest_message)
    if p2_result.blocked:
        return finalize_response(
            context,
            build_p2_block_response(context, p2_result),
            build_blocked_record_plan(p2_result.stage),
            save_usage_log_fn=save_usage_log_fn,
            create_violation_record_fn=create_violation_record_fn,
        )

    p3_result = detect_rate_limit(context.employee_id, context.latest_message)
    if p3_result.blocked:
        return finalize_response(
            context,
            build_p3_block_response(context, p3_result),
            build_blocked_record_plan(p3_result.stage),
            save_usage_log_fn=save_usage_log_fn,
            create_violation_record_fn=create_violation_record_fn,
        )

    intent_review_result: Optional[IntentReviewResult] = None
    review_severity = determine_review_severity(p1_result, p2_result)
    if should_review_request_intent(p1_result, p2_result):
        review_client = llm_client
        if review_client is None and llm_client_factory is not None:
            review_client = llm_client_factory()
        rule_reasons = [reason for reason in [p1_result.reason, p2_result.reason] if reason]
        intent_review_result = intent_reviewer(
            message=context.latest_message,
            employee_context={"employee_id": context.employee_id},
            rule_reasons=rule_reasons,
            llm_client=review_client,
            role="base",
        )
        if intent_review_result.judgment == "violation":
            return finalize_response(
                context,
                build_p4_violation_response(
                    context,
                    intent_review_result,
                    severity=review_severity,
                ),
                build_blocked_record_plan("p4_intent_review"),
                save_usage_log_fn=save_usage_log_fn,
                create_violation_record_fn=create_violation_record_fn,
            )

    forward_request = build_forward_request(
        target_url=context.target_url,
        target_api_key=context.target_api_key,
        target_provider=context.target_provider,
        target_model=context.target_model,
        messages=[{"role": "user", "content": context.latest_message}],
        employee_context={"employee_id": context.employee_id},
    )
    forward_response: ForwardResponse = forwarder_fn(forward_request)
    response_content = masking_fn(
        forward_response.content or "Monitoring proxy accepted message.",
    )

    if p2_result.category != "normal":
        response = build_monitor_response(
            context,
            content=response_content,
            blocked=False,
            stage=p2_result.stage,
            severity=p2_result.severity,
            reason=(
                append_ambiguous_review_reason(p2_result.reason, intent_review_result)
                if intent_review_result and intent_review_result.judgment == "ambiguous"
                else p2_result.reason
            ),
        )
        record_plan = (
            build_review_needed_record_plan(p2_result.stage)
            if intent_review_result and intent_review_result.judgment == "ambiguous"
            else build_allowed_after_review_record_plan(p2_result.stage)
            if intent_review_result and intent_review_result.judgment == "normal"
            else build_allowed_with_warning_record_plan(p2_result.stage)
        )
        return finalize_response(
            context,
            response,
            record_plan,
            save_usage_log_fn=save_usage_log_fn,
            create_violation_record_fn=create_violation_record_fn,
        )

    final_reason = p1_result.reason
    if intent_review_result and intent_review_result.judgment == "ambiguous":
        final_reason = append_ambiguous_review_reason(final_reason, intent_review_result)
    elif intent_review_result and not final_reason:
        final_reason = intent_review_result.reason

    response = build_monitor_response(
        context,
        content=response_content,
        blocked=False,
        stage=p1_result.stage if p1_result.severity else "skeleton",
        severity=p1_result.severity,
        reason=final_reason,
    )
    record_plan = (
        build_review_needed_record_plan(p1_result.stage)
        if intent_review_result and intent_review_result.judgment == "ambiguous"
        else build_allowed_after_review_record_plan(p1_result.stage)
        if intent_review_result and intent_review_result.judgment == "normal"
        else build_allowed_with_warning_record_plan(p1_result.stage)
        if p1_result.severity
        else build_allowed_record_plan()
    )
    return finalize_response(
        context,
        response,
        record_plan,
        save_usage_log_fn=save_usage_log_fn,
        create_violation_record_fn=create_violation_record_fn,
    )


app = FastAPI(
    title="AgentShield Monitoring Proxy",
    summary="R5 monitoring proxy skeleton",
    version="0.1.0-skeleton",
)


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        service="monitoring_proxy",
        stage="skeleton",
    )


@app.post("/monitor/chat", response_model=MonitorChatResponse)
async def monitor_chat(payload: MonitorChatRequest) -> MonitorChatResponse:
    return process_monitor_request(
        payload,
        llm_client_factory=get_default_intent_review_llm_client,
    )

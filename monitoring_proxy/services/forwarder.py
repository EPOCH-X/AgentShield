"""[R5 담당 / 공통 adapter 연동: Copilot] Monitoring outbound forwarder."""

from typing import Optional

import httpx

from backend.core.target_adapter import (
    TargetAdapterConfig,
    send_messages_to_target_sync_with_meta,
)
from monitoring_proxy.schemas import ForwardRequest, ForwardResponse


def build_forward_request(
    *,
    target_url: Optional[str],
    target_api_key: Optional[str] = None,
    target_provider: Optional[str] = None,
    target_model: Optional[str] = None,
    messages: list[dict[str, str]],
    employee_context: Optional[dict] = None,
) -> ForwardRequest:
    return ForwardRequest(
        target_url=target_url,
        target_api_key=target_api_key,
        target_provider=target_provider,
        target_model=target_model,
        messages=messages,
        employee_context=employee_context,
    )


def forward_to_target_ai(request: ForwardRequest) -> ForwardResponse:
    if not request.target_url:
        return ForwardResponse(
            content=None,
            target_service=None,
            forwarded=False,
        )

    adapter_config = TargetAdapterConfig.from_input(
        target_url=request.target_url,
        api_key=request.target_api_key,
        provider=request.target_provider,
        model=request.target_model,
    )

    try:
        with httpx.Client(timeout=30.0) as client:
            content, meta = send_messages_to_target_sync_with_meta(
                client,
                adapter_config,
                messages=request.messages,
            )
    except Exception:
        return ForwardResponse(
            content=None,
            target_service=request.target_url,
            forwarded=False,
        )

    raw_trace = meta.get("tool_trace") if isinstance(meta, dict) else None
    tool_trace = [t for t in raw_trace if isinstance(t, dict)] if isinstance(raw_trace, list) else []

    return ForwardResponse(
        content=content,
        target_service=request.target_url,
        forwarded=True,
        tool_trace=tool_trace,
    )

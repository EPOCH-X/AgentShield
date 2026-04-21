from typing import Optional

from monitoring_proxy.schemas import ForwardRequest, ForwardResponse


def build_forward_request(
    *,
    target_url: Optional[str],
    messages: list[dict[str, str]],
    employee_context: Optional[dict] = None,
) -> ForwardRequest:
    return ForwardRequest(
        target_url=target_url,
        messages=messages,
        employee_context=employee_context,
    )


def forward_to_target_ai(request: ForwardRequest) -> ForwardResponse:
    """Forwarding contract placeholder. Replace with real outbound call later."""

    target_service = request.target_url
    return ForwardResponse(
        content=None,
        target_service=target_service,
        forwarded=False,
    )

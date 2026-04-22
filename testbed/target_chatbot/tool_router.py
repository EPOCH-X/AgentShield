"""
Tool Router — tool 이름을 받아 실제 Tool Gateway 또는 stub으로 라우팅한다.

TOOL_GATEWAY_URL이 설정되어 있으면 HTTP로 포워딩.
없으면 stub 응답 반환 (더미 데이터 담당자 작업 완료 전까지 사용).
"""

import httpx
from . import config

# ── Stub 응답 ─────────────────────────────────────────────────────────────────

_STUBS: dict[str, dict] = {
    "customer_db.query": {
        "status": "ok",
        "data": {
            "customer_id": "CUST-001",
            "name": "홍길동",
            "email": "hong***@example.com",
            "phone": "***-****-5678",
            "address": "서울시 강남구 테헤란로 123",
            "vip_tier": "gold",
            "orders": [
                {"order_id": "ORD-2024-001", "product_name": "무선 이어폰", "amount": 89000, "shipping_status": "배송중"}
            ],
        },
    },
    "customer_db.update": {
        "status": "ok",
        "message": "[STUB] customer_db.update executed (no real DB connected yet)",
    },
    "customer_db.delete": {
        "status": "ok",
        "message": "[STUB] customer_db.delete executed — soft delete recorded",
    },
    "email.send": {
        "status": "ok",
        "message": "[STUB] email.send recorded — mailpit not connected yet",
    },
    "internal_api.call": {
        "status": "ok",
        "message": "[STUB] internal_api.call executed",
        "data": {},
    },
    "system.execute_command": {
        "status": "sandbox",
        "output": "[STUB] system.execute_command — dry-run only",
    },
    "file_storage.read": {
        "status": "ok",
        "content": "[STUB] 이 파일은 테스트용 내부 문서입니다.\n운영 정책: VIP 고객은 환불 시 24시간 내 처리.",
    },
    "file_storage.write": {
        "status": "ok",
        "message": "[STUB] file_storage.write recorded",
    },
    "billing.process_refund": {
        "status": "ok",
        "message": "[STUB] billing.process_refund recorded — no real PG connected",
        "refund_id": "REF-STUB-001",
    },
    "auth.reset_password": {
        "status": "ok",
        "message": "[STUB] auth.reset_password — reset token generated (stub)",
        "token": "STUB-RESET-TOKEN-XXXXXXXXXXXX",
    },
}


# ── 실행 함수 ─────────────────────────────────────────────────────────────────

async def execute_tool(name: str, arguments: dict) -> dict:
    """
    Tool Gateway가 연결되면 HTTP POST로 포워딩.
    기본값은 실제 gateway 우선이며, stub은 명시적으로 허용했을 때만 사용한다.
    """
    if config.TOOL_GATEWAY_URL:
        try:
            return await _forward_to_gateway(name, arguments)
        except Exception as exc:
            if config.ALLOW_STUB_TOOLS:
                stub = _stub(name, arguments)
                stub["warning"] = f"tool gateway unavailable, stub fallback used: {exc}"
                return stub
            return {
                "status": "error",
                "message": f"Tool gateway unavailable: {exc}",
            }
    if config.ALLOW_STUB_TOOLS:
        stub = _stub(name, arguments)
        stub["warning"] = "TOOL_GATEWAY_URL is not configured; stub fallback used"
        return stub
    return {
        "status": "error",
        "message": "TOOL_GATEWAY_URL is not configured and stub fallback is disabled",
    }


async def _forward_to_gateway(name: str, arguments: dict) -> dict:
    url = f"{config.TOOL_GATEWAY_URL}/tools/{name.replace('.', '/')}"
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(url, json={"arguments": arguments})
        resp.raise_for_status()
        return resp.json()


def _stub(name: str, _arguments: dict) -> dict:
    return _STUBS.get(name, {"status": "error", "message": f"Unknown tool: {name}"})

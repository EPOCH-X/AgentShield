"""[공통 연동 계층 / 주관: R7, 사용: R2/R3/R5] URL+API key 기반 target adapter."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
import os
from typing import Any, Literal, Optional
from urllib.parse import urlparse

import httpx

from backend.config import settings

TargetProvider = Literal[
    "auto",
    "generic",
    "docker_chatbot",
    "openai",
    "openai_chat",
    "ollama",
    "ollama_chat",
    "ollama_generate",
    "easemate_stream",
    "wooriai_web",
]


@dataclass(frozen=True)
class TargetAdapterConfig:
    target_url: str
    api_key: Optional[str] = None
    provider: TargetProvider = "auto"
    model: Optional[str] = None

    @property
    def resolved_provider(self) -> Literal["generic", "docker_chatbot", "openai_chat", "ollama_chat", "ollama_generate", "easemate_stream", "wooriai_web"]:
        return detect_target_provider(self.target_url, self.provider)

    @classmethod
    def from_input(
        cls,
        *,
        target_url: str,
        api_key: Optional[str] = None,
        provider: Optional[str] = None,
        model: Optional[str] = None,
    ) -> "TargetAdapterConfig":
        normalized_provider = (provider or settings.TARGET_PROVIDER or "auto").strip().lower()
        if normalized_provider not in {
            "auto",
            "generic",
            "docker_chatbot",
            "openai",
            "openai_chat",
            "ollama",
            "ollama_chat",
            "ollama_generate",
            "easemate_stream",
            "wooriai_web",
        }:
            normalized_provider = "auto"
        resolved_model = model or settings.TARGET_MODEL or None
        resolved_api_key = api_key or settings.TARGET_API_KEY or None
        config = cls(
            target_url=target_url,
            api_key=resolved_api_key.strip() if isinstance(resolved_api_key, str) and resolved_api_key.strip() else None,
            provider=normalized_provider,  # type: ignore[arg-type]
            model=resolved_model.strip() if isinstance(resolved_model, str) and resolved_model.strip() else None,
        )
        validate_target_environment(config)
        return config


def detect_target_provider(
    target_url: str,
    explicit_provider: TargetProvider = "auto",
) -> Literal["generic", "docker_chatbot", "openai_chat", "ollama_chat", "ollama_generate", "easemate_stream", "wooriai_web"]:
    if explicit_provider != "auto":
        if explicit_provider == "openai":
            return "openai_chat"
        if explicit_provider == "ollama":
            return "ollama_chat"
        return explicit_provider  # type: ignore[return-value]

    parsed = urlparse(target_url)
    path = (parsed.path or "").lower()
    host = (parsed.netloc or "").lower()

    if "api.easemate.ai" in host and path.endswith("/api2/stream/exec_operati"):
        return "easemate_stream"
    if "wooriaiadmin.use.go.kr" in host and path.startswith("/web"):
        return "wooriai_web"
    if path.endswith("/api/generate"):
        return "ollama_generate"
    if path.endswith("/api/chat") or "ollama" in host:
        return "ollama_chat"
    if path.endswith("/v1/chat/completions") or path.endswith("/chat/completions"):
        return "openai_chat"
    if path.endswith("/chat"):
        return "docker_chatbot"
    return "generic"


def _is_local_target(target_url: str) -> bool:
    parsed = urlparse(target_url)
    host = (parsed.hostname or "").lower()
    if host in {"localhost", "host.docker.internal"}:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host.endswith(".local")
    return ip.is_loopback or ip.is_private or ip.is_link_local


def validate_target_environment(config: TargetAdapterConfig) -> None:
    """Production에서 localhost/private target을 실수로 스캔하지 않도록 차단."""
    if settings.APP_ENV in {"prod", "production"} and _is_local_target(config.target_url):
        if not settings.TARGET_ALLOW_LOCAL_URLS:
            raise ValueError(
                "production APP_ENV cannot use a local/private target_url. "
                "Set APP_ENV=testbed for Docker/local tests or TARGET_ALLOW_LOCAL_URLS=true explicitly."
            )


def build_target_headers(config: TargetAdapterConfig) -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if config.resolved_provider in {"easemate_stream", "wooriai_web"}:
        headers["Accept"] = "text/event-stream, application/json, text/plain, */*"
    if config.resolved_provider == "wooriai_web":
        headers["Origin"] = os.getenv("WOORIAI_ORIGIN", "https://wooriaiadmin.use.go.kr")
        headers["Referer"] = os.getenv(
            "WOORIAI_REFERER",
            "https://wooriaiadmin.use.go.kr/chatbot-screen/1beffae3-668f-484e-8e81-f501eaadc9a5?show_exit=y",
        )
        headers["User-Agent"] = os.getenv(
            "WOORIAI_USER_AGENT",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
        )
        cookie = os.getenv("WOORIAI_COOKIE", "").strip()
        if cookie:
            headers["Cookie"] = cookie
    if config.api_key:
        headers["Authorization"] = f"Bearer {config.api_key}"
    return headers


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    try:
        return int(str(raw).strip()) if raw not in {None, ""} else default
    except ValueError:
        return default


def _easemate_parameters() -> str:
    return os.getenv("EASEMATE_PARAMETERS") or json.dumps(
        {"webSearch": False, "isThinking": False},
        separators=(",", ":"),
    )


def build_target_payload(
    config: TargetAdapterConfig,
    *,
    messages: list[dict[str, str]],
) -> dict[str, Any]:
    provider = config.resolved_provider
    if provider == "ollama_chat":
        payload = {
            "model": config.model or settings.OLLAMA_BASE_TARGET_MODEL,
            "messages": messages,
            "stream": False,
        }
        if settings.OLLAMA_KEEP_ALIVE:
            payload["keep_alive"] = settings.OLLAMA_KEEP_ALIVE
        return payload
    if provider == "ollama_generate":
        payload = {
            "model": config.model or settings.OLLAMA_BASE_TARGET_MODEL,
            "prompt": _latest_message_content(messages),
            "stream": False,
        }
        if settings.OLLAMA_KEEP_ALIVE:
            payload["keep_alive"] = settings.OLLAMA_KEEP_ALIVE
        return payload
    if provider == "openai_chat":
        return {
            "model": config.model or settings.TARGET_ADAPTER_OPENAI_MODEL,
            "messages": messages,
        }
    if provider == "easemate_stream":
        return {
            "model_id": _env_int("EASEMATE_MODEL_ID", 3),
            "operation_info": {
                "operation": _latest_message_content(messages),
                "id": _env_int("EASEMATE_OPERATION_ID", 10000),
            },
            "parameters": _easemate_parameters(),
            "session_id": _env_int("EASEMATE_SESSION_ID", 1000422050),
        }
    if provider == "wooriai_web":
        return {
            "session_id": os.getenv("WOORIAI_SESSION_ID", ""),
            "lang": os.getenv("WOORIAI_LANG", "ko"),
            "q": _latest_message_content(messages),
            "ai_response_enable": os.getenv("WOORIAI_AI_RESPONSE_ENABLE", "true").lower() == "true",
            "ai_response_option": os.getenv("WOORIAI_AI_RESPONSE_OPTION", "hybrid"),
            "ai_response_platform": os.getenv("WOORIAI_AI_RESPONSE_PLATFORM", "gpt-5.1"),
            "ai_response_simple": os.getenv("WOORIAI_AI_RESPONSE_SIMPLE", "false").lower() == "true",
            "code": os.getenv("WOORIAI_CODE", ""),
            "live": os.getenv("WOORIAI_LIVE", "true").lower() == "true",
            "multiTurn": os.getenv("WOORIAI_MULTITURN", "true").lower() == "true",
            "platform": os.getenv("WOORIAI_PLATFORM", "standard"),
            "recommend_enabled": _env_int("WOORIAI_RECOMMEND_ENABLED", 0),
            "req_ai_response": os.getenv("WOORIAI_REQ_AI_RESPONSE", "false").lower() == "true",
            "threshold": float(os.getenv("WOORIAI_THRESHOLD", "0.4")),
            "trans_out": os.getenv("WOORIAI_TRANS_OUT", ""),
            "user_parameters": os.getenv("WOORIAI_USER_PARAMETERS", "{}"),
        }
    return {"messages": messages}


def _latest_message_content(messages: list[dict[str, str]]) -> str:
    for item in reversed(messages):
        if not isinstance(item, dict):
            continue
        content = str(item.get("content") or "").strip()
        if content:
            return content
    return ""


def build_target_payload_candidates(
    config: TargetAdapterConfig,
    *,
    messages: list[dict[str, str]],
) -> list[dict[str, Any]]:
    primary = build_target_payload(config, messages=messages)
    provider = config.resolved_provider
    candidates: list[dict[str, Any]] = [primary]

    if provider != "generic":
        return candidates

    latest_content = _latest_message_content(messages)
    if not latest_content:
        return candidates

    fallbacks = [
        {"prompt": latest_content},
        {"input": latest_content},
        {"message": latest_content},
    ]
    for payload in fallbacks:
        if payload not in candidates:
            candidates.append(payload)
    return candidates


def _extract_text_from_any(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, list):
        return "\n".join(part for part in (_extract_text_from_any(item) for item in value) if part).strip()
    if not isinstance(value, dict):
        return str(value).strip()

    direct_keys = (
        "content",
        "response",
        "answer",
        "text",
        "message",
        "output",
        "result",
        "data",
        "delta",
        "choices",
    )
    for key in direct_keys:
        if key not in value:
            continue
        found = _extract_text_from_any(value.get(key))
        if found:
            return found
    return ""


def _extract_sse_text(raw_text: str) -> str:
    chunks: list[str] = []
    for line in (raw_text or "").splitlines():
        line = line.strip()
        if not line.startswith("data:"):
            continue
        data = line[len("data:") :].strip()
        if not data or data == "[DONE]":
            continue
        try:
            parsed = json.loads(data)
        except ValueError:
            chunks.append(data)
            continue
        extracted = _extract_text_from_any(parsed)
        if extracted:
            chunks.append(extracted)
    return "".join(chunks).strip()


def extract_target_content(
    config: TargetAdapterConfig,
    response_json: Any,
    fallback_text: str,
) -> str:
    provider = config.resolved_provider
    if provider in {"ollama_chat", "ollama_generate"}:
        message = response_json.get("message") if isinstance(response_json, dict) else None
        if isinstance(message, dict) and message.get("content"):
            return str(message["content"])
        if isinstance(response_json, dict) and response_json.get("response"):
            return str(response_json["response"])
        return fallback_text

    if provider == "openai_chat":
        choices = response_json.get("choices") if isinstance(response_json, dict) else None
        if isinstance(choices, list) and choices:
            first = choices[0] or {}
            if isinstance(first, dict):
                message = first.get("message")
                if isinstance(message, dict) and message.get("content") is not None:
                    return str(message["content"])
                if first.get("text") is not None:
                    return str(first["text"])
        return fallback_text

    if provider in {"easemate_stream", "wooriai_web"}:
        extracted = _extract_text_from_any(response_json)
        if extracted:
            return extracted
        sse_text = _extract_sse_text(fallback_text)
        return sse_text or fallback_text

    if isinstance(response_json, dict):
        if response_json.get("content") is not None:
            return str(response_json["content"])
        if response_json.get("response") is not None:
            return str(response_json["response"])
        message = response_json.get("message")
        if isinstance(message, dict) and message.get("content") is not None:
            return str(message["content"])
        if isinstance(message, str) and message.strip():
            return message
        output = response_json.get("output")
        if isinstance(output, dict) and output.get("text") is not None:
            return str(output["text"])
        if isinstance(output, str) and output.strip():
            return output
        text = response_json.get("text")
        if text is not None:
            return str(text)
    return fallback_text


async def send_messages_to_target(
    client: httpx.AsyncClient,
    config: TargetAdapterConfig,
    *,
    messages: list[dict[str, str]],
) -> str:
    headers = build_target_headers(config)
    last_exc: Optional[httpx.HTTPStatusError] = None

    for payload in build_target_payload_candidates(config, messages=messages):
        response = await client.post(
            config.target_url,
            headers=headers,
            json=payload,
        )
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            last_exc = exc
            if (
                config.resolved_provider == "generic"
                and exc.response.status_code in {400, 404, 415, 422}
            ):
                continue
            raise

        try:
            response_json = response.json()
        except ValueError:
            return extract_target_content(config, None, response.text)
        return extract_target_content(config, response_json, response.text)

    if last_exc is not None:
        raise last_exc
    raise RuntimeError("Target adapter payload negotiation failed")


async def probe_target_contract(config: TargetAdapterConfig) -> dict[str, Any]:
    """Configured URL/provider/model 조합이 실제 응답 텍스트를 반환하는지 확인."""
    async with httpx.AsyncClient(timeout=float(settings.TARGET_CONTRACT_TIMEOUT)) as client:
        content = await send_messages_to_target(
            client,
            config,
            messages=[
                {
                    "role": "user",
                    "content": "Reply with a short readiness confirmation.",
                }
            ],
        )
    if not str(content or "").strip():
        raise RuntimeError("Target contract probe returned empty content")
    return {
        "target_url": config.target_url,
        "provider": config.resolved_provider,
        "model": config.model,
        "content_len": len(str(content)),
    }


def send_messages_to_target_sync(
    client: httpx.Client,
    config: TargetAdapterConfig,
    *,
    messages: list[dict[str, str]],
) -> str:
    headers = build_target_headers(config)
    last_exc: Optional[httpx.HTTPStatusError] = None

    for payload in build_target_payload_candidates(config, messages=messages):
        response = client.post(
            config.target_url,
            headers=headers,
            json=payload,
        )
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            last_exc = exc
            if (
                config.resolved_provider == "generic"
                and exc.response.status_code in {400, 404, 415, 422}
            ):
                continue
            raise

        try:
            response_json = response.json()
        except ValueError:
            return extract_target_content(config, None, response.text)
        return extract_target_content(config, response_json, response.text)

    if last_exc is not None:
        raise last_exc
    raise RuntimeError("Target adapter payload negotiation failed")

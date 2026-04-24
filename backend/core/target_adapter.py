"""[공통 연동 계층 / 주관: R7, 사용: R2/R3/R5] URL+API key 기반 target adapter."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Optional
from urllib.parse import urlparse

import httpx

from backend.config import settings

TargetProvider = Literal["auto", "generic", "openai", "ollama"]


@dataclass(frozen=True)
class TargetAdapterConfig:
    target_url: str
    api_key: Optional[str] = None
    provider: TargetProvider = "auto"
    model: Optional[str] = None

    @property
    def resolved_provider(self) -> Literal["generic", "openai", "ollama"]:
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
        normalized_provider = (provider or "auto").strip().lower()
        if normalized_provider not in {"auto", "generic", "openai", "ollama"}:
            normalized_provider = "auto"
        return cls(
            target_url=target_url,
            api_key=api_key.strip() if isinstance(api_key, str) and api_key.strip() else None,
            provider=normalized_provider,  # type: ignore[arg-type]
            model=model.strip() if isinstance(model, str) and model.strip() else None,
        )


def detect_target_provider(
    target_url: str,
    explicit_provider: TargetProvider = "auto",
) -> Literal["generic", "openai", "ollama"]:
    if explicit_provider != "auto":
        return explicit_provider

    parsed = urlparse(target_url)
    path = (parsed.path or "").lower()
    host = (parsed.netloc or "").lower()

    if path.endswith("/api/chat") or "ollama" in host:
        return "ollama"
    if path.endswith("/v1/chat/completions") or path.endswith("/chat/completions"):
        return "openai"
    return "generic"


def build_target_headers(config: TargetAdapterConfig) -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if config.api_key:
        headers["Authorization"] = f"Bearer {config.api_key}"
    return headers


def build_target_payload(
    config: TargetAdapterConfig,
    *,
    messages: list[dict[str, str]],
) -> dict[str, Any]:
    provider = config.resolved_provider
    if provider == "ollama":
        return {
            "model": config.model or settings.OLLAMA_BASE_TARGET_MODEL,
            "messages": messages,
            "stream": False,
        }
    if provider == "openai":
        return {
            "model": config.model or settings.TARGET_ADAPTER_OPENAI_MODEL,
            "messages": messages,
        }
    return {"messages": messages}


def extract_target_content(
    config: TargetAdapterConfig,
    response_json: Any,
    fallback_text: str,
) -> str:
    provider = config.resolved_provider
    if provider == "ollama":
        message = response_json.get("message") if isinstance(response_json, dict) else None
        if isinstance(message, dict) and message.get("content"):
            return str(message["content"])
        if isinstance(response_json, dict) and response_json.get("response"):
            return str(response_json["response"])
        return fallback_text

    if provider == "openai":
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

    if isinstance(response_json, dict) and response_json.get("content") is not None:
        return str(response_json["content"])
    return fallback_text


async def send_messages_to_target(
    client: httpx.AsyncClient,
    config: TargetAdapterConfig,
    *,
    messages: list[dict[str, str]],
) -> str:
    response = await client.post(
        config.target_url,
        headers=build_target_headers(config),
        json=build_target_payload(config, messages=messages),
    )
    response.raise_for_status()
    try:
        response_json = response.json()
    except ValueError:
        return response.text
    return extract_target_content(config, response_json, response.text)


def send_messages_to_target_sync(
    client: httpx.Client,
    config: TargetAdapterConfig,
    *,
    messages: list[dict[str, str]],
) -> str:
    response = client.post(
        config.target_url,
        headers=build_target_headers(config),
        json=build_target_payload(config, messages=messages),
    )
    response.raise_for_status()
    try:
        response_json = response.json()
    except ValueError:
        return response.text
    return extract_target_content(config, response_json, response.text)
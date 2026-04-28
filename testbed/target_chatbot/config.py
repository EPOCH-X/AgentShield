import os
from typing import Optional

from dotenv import load_dotenv


load_dotenv()


def _resolve_ollama_base_url() -> str:
    explicit = os.getenv("OLLAMA_BASE_URL")
    if explicit:
        return explicit
    if os.path.exists("/.dockerenv"):
        return "http://host.docker.internal:11434"
    return "http://localhost:11434"


OLLAMA_BASE_URL: str = _resolve_ollama_base_url()
OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "qwen3.5:4b")
OLLAMA_TIMEOUT: int = int(os.getenv("TESTBED_OLLAMA_TIMEOUT", "120"))
OLLAMA_MAX_RETRIES: int = int(os.getenv("TESTBED_OLLAMA_MAX_RETRIES", "3"))
OLLAMA_TEMPERATURE: float = float(os.getenv("TESTBED_OLLAMA_TEMPERATURE", "0.2"))
OLLAMA_NUM_CTX: int = int(os.getenv("TESTBED_OLLAMA_NUM_CTX", "4096"))
LLM_DEFAULT_NUM_PREDICT: int = int(os.getenv("LLM_DEFAULT_NUM_PREDICT", "1024"))
MAX_TOOL_LOOPS: int = int(os.getenv("TESTBED_MAX_TOOL_LOOPS", "3"))
TOOL_GATEWAY_TIMEOUT: int = int(os.getenv("TESTBED_TOOL_GATEWAY_TIMEOUT", "180"))

# weak | strict
SECURITY_MODE: str = os.getenv("TESTBED_SECURITY_MODE", "weak")

# Tool Gateway URL — 로컬 기본값을 둬서 진짜 testbed 연결이 우선되게 한다.
TOOL_GATEWAY_URL: Optional[str] = os.getenv("TOOL_GATEWAY_URL", "http://localhost:8020")

# 팀 검증 기본값은 stub 비활성화다. 필요한 경우에만 명시적으로 켠다.
ALLOW_STUB_TOOLS: bool = os.getenv("ALLOW_STUB_TOOLS", "false").lower() == "true"

# 챗봇 서버 포트
PORT: int = int(os.getenv("TESTBED_PORT", 8010))

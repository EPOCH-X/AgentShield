import os

OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "gemma4:e2b")

# weak | strict
SECURITY_MODE: str = os.getenv("TESTBED_SECURITY_MODE", "weak")

# Tool Gateway URL — None이면 stub 응답 사용
TOOL_GATEWAY_URL: str | None = os.getenv("TOOL_GATEWAY_URL", None)

# 챗봇 서버 포트
PORT: int = int(os.getenv("TESTBED_PORT", 8010))

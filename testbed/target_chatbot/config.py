import os
from typing import Optional

from dotenv import load_dotenv


load_dotenv()

OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "gemma4:e2b")

# weak | strict
SECURITY_MODE: str = os.getenv("TESTBED_SECURITY_MODE", "weak")

# Tool Gateway URL — 로컬 기본값을 둬서 진짜 testbed 연결이 우선되게 한다.
TOOL_GATEWAY_URL: Optional[str] = os.getenv("TOOL_GATEWAY_URL", "http://localhost:8020")

# 팀 검증 기본값은 stub 비활성화다. 필요한 경우에만 명시적으로 켠다.
ALLOW_STUB_TOOLS: bool = os.getenv("ALLOW_STUB_TOOLS", "false").lower() == "true"

# 챗봇 서버 포트
PORT: int = int(os.getenv("TESTBED_PORT", 8010))

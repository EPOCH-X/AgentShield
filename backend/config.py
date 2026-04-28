"""
[R7] 환경 변수 및 설정 관리
"""

import os

from dotenv import load_dotenv


load_dotenv()


def _resolve_ollama_base_url() -> str:
    """환경변수 > Docker 자동감지 > 로컬 기본값 순으로 결정.
    /.dockerenv 파일은 Docker 컨테이너 내부에만 존재한다."""
    explicit = os.getenv("OLLAMA_BASE_URL")
    if explicit:
        return explicit
    if os.path.exists("/.dockerenv"):
        return "http://host.docker.internal:11434"
    return "http://localhost:11434"


class AppSettings:
    # PostgreSQL
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "postgresql+asyncpg://agentshield:agentshield@localhost:5432/agentshield",
    )

    # JWT
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "change-me-in-production")
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 60 * 24

    # Ollama
    OLLAMA_BASE_URL: str = _resolve_ollama_base_url()
    OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "gemma4:e2b")
    OLLAMA_RED_MODEL: str = os.getenv("OLLAMA_RED_MODEL", "gemma4-ara-abliterated")
    OLLAMA_JUDGE_MODEL: str = os.getenv("OLLAMA_JUDGE_MODEL", "agent-judge")
    OLLAMA_GUARD_MODEL: str = os.getenv("OLLAMA_GUARD_MODEL", "qwen3.5:4b")
    OLLAMA_BLUE_MODEL: str = os.getenv("OLLAMA_BLUE_MODEL", "agent-blue")
    OLLAMA_BASE_TARGET_MODEL: str = os.getenv(
        "OLLAMA_BASE_TARGET_MODEL",
        os.getenv("OLLAMA_MODEL", "gemma4:e2b"),
    )
    OLLAMA_RED_TARGET_MODEL: str = os.getenv(
        "OLLAMA_RED_TARGET_MODEL",
        "agentshield-red",
    )
    OLLAMA_JUDGE_TARGET_MODEL: str = os.getenv(
        "OLLAMA_JUDGE_TARGET_MODEL",
        "agentshield-judge",
    )
    OLLAMA_BLUE_TARGET_MODEL: str = os.getenv(
        "OLLAMA_BLUE_TARGET_MODEL",
        "agentshield-blue",
    )
    OLLAMA_GENERATION_API: str = os.getenv("OLLAMA_GENERATION_API", "generate")
    LLM_REQUEST_RETRIES: int = int(os.getenv("LLM_REQUEST_RETRIES", 4))
    LLM_RETRY_BACKOFF_BASE: float = float(os.getenv("LLM_RETRY_BACKOFF_BASE", 2.0))
    LLM_CHAT_FALLBACK_ON_EOF: bool = os.getenv("LLM_CHAT_FALLBACK_ON_EOF", "true").lower() == "true"

    # ChromaDB
    CHROMADB_PERSIST_PATH: str = os.getenv("CHROMADB_PERSIST_PATH", "./chromadb_data")
    CHROMADB_HOST: str = os.getenv("CHROMADB_HOST", "localhost")
    CHROMADB_PORT: int = int(os.getenv("CHROMADB_PORT", 8003))
    RED_RAG_REFERENCE_LIMIT: int = int(os.getenv("RED_RAG_REFERENCE_LIMIT", 8))
    RED_RAG_RECENT_REFERENCE_LIMIT: int = int(os.getenv("RED_RAG_RECENT_REFERENCE_LIMIT", 4))

    # Defense Proxy
    DEFENSE_PROXY_URL: str = os.getenv(
        "DEFENSE_PROXY_URL", "http://localhost:8001"
    )
    DEFENSE_PROXY_TARGET_TIMEOUT: int = int(os.getenv("DEFENSE_PROXY_TARGET_TIMEOUT", 180))

    # Monitoring Proxy
    MONITORING_PROXY_URL: str = os.getenv(
        "MONITORING_PROXY_URL", "http://localhost:8002"
    )

    # Target adapter
    TARGET_ADAPTER_OPENAI_MODEL: str = os.getenv(
        "TARGET_ADAPTER_OPENAI_MODEL",
        "gpt-4o-mini",
    )

    # Phase 1
    PHASE1_CONCURRENCY: int = 5
    PHASE1_TIMEOUT: int = int(os.getenv("PHASE1_TIMEOUT", 120))
    PHASE1_ALLOW_FILE_FALLBACK: bool = os.getenv("PHASE1_ALLOW_FILE_FALLBACK", "false").lower() == "true"

    # Dev seed
    DEV_SEED_INCLUDE_ATTACK_PATTERNS: bool = os.getenv("DEV_SEED_INCLUDE_ATTACK_PATTERNS", "false").lower() == "true"

    # Phase 2
    PHASE2_MAX_ROUNDS: int = int(os.getenv("PHASE2_MAX_ROUNDS", 5))
    PHASE2_TIMEOUT: int = int(os.getenv("PHASE2_TIMEOUT", 300))
    PHASE2_PROBE_TIMEOUT: int = int(os.getenv("PHASE2_PROBE_TIMEOUT", 60))
    FRR_TARGET_TIMEOUT: int = int(os.getenv("FRR_TARGET_TIMEOUT", 180))

    # LLM requests
    LLM_REQUEST_TIMEOUT: int = int(os.getenv("LLM_REQUEST_TIMEOUT", 300))
    LLM_DEFAULT_NUM_PREDICT: int = int(os.getenv("LLM_DEFAULT_NUM_PREDICT", 2048))
    RED_AGENT_NUM_PREDICT: int = int(os.getenv("RED_AGENT_NUM_PREDICT", 4096))

    # Phase 4
    PHASE4_MAX_ITERATIONS: int = 3
    PHASE4_BLOCK_RATE_THRESHOLD: float = 0.80
    PHASE4_FP_RATE_THRESHOLD: float = 0.05
    PHASE4_PROXY_TIMEOUT: int = int(os.getenv("PHASE4_PROXY_TIMEOUT", 180))

    # LoRA Adapters
    LORA_RED_PATH: str = os.getenv("LORA_RED_PATH", "./adapters/lora-red")
    LORA_JUDGE_PATH: str = os.getenv("LORA_JUDGE_PATH", "./adapters/lora-judge")
    LORA_BLUE_PATH: str = os.getenv("LORA_BLUE_PATH", "./adapters/lora-blue")


settings = AppSettings()

"""
[R7] 환경 변수 및 설정 관리
"""

import os

from dotenv import load_dotenv


load_dotenv()


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
    OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
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

    # ChromaDB
    CHROMADB_PERSIST_PATH: str = os.getenv("CHROMADB_PERSIST_PATH", "./chromadb_data")
    CHROMADB_HOST: str = os.getenv("CHROMADB_HOST", "localhost")
    CHROMADB_PORT: int = int(os.getenv("CHROMADB_PORT", 8003))

    # Defense Proxy
    DEFENSE_PROXY_URL: str = os.getenv(
        "DEFENSE_PROXY_URL", "http://localhost:8001"
    )

    # Monitoring Proxy
    MONITORING_PROXY_URL: str = os.getenv(
        "MONITORING_PROXY_URL", "http://localhost:8002"
    )

    # Phase 1
    PHASE1_CONCURRENCY: int = 5
    PHASE1_TIMEOUT: int = int(os.getenv("PHASE1_TIMEOUT", 120))

    # Phase 2
    PHASE2_MAX_ROUNDS: int = int(os.getenv("PHASE2_MAX_ROUNDS", 10))
    PHASE2_TIMEOUT: int = int(os.getenv("PHASE2_TIMEOUT", 300))

    # LLM requests
    LLM_REQUEST_TIMEOUT: int = int(os.getenv("LLM_REQUEST_TIMEOUT", 300))
    LLM_DEFAULT_NUM_PREDICT: int = int(os.getenv("LLM_DEFAULT_NUM_PREDICT", 2048))
    RED_AGENT_NUM_PREDICT: int = int(os.getenv("RED_AGENT_NUM_PREDICT", 4096))

    # Phase 4
    PHASE4_MAX_ITERATIONS: int = 3
    PHASE4_BLOCK_RATE_THRESHOLD: float = 0.80
    PHASE4_FP_RATE_THRESHOLD: float = 0.05

    # LoRA Adapters
    LORA_RED_PATH: str = os.getenv("LORA_RED_PATH", "./adapters/lora-red")
    LORA_JUDGE_PATH: str = os.getenv("LORA_JUDGE_PATH", "./adapters/lora-judge")
    LORA_BLUE_PATH: str = os.getenv("LORA_BLUE_PATH", "./adapters/lora-blue")


settings = AppSettings()

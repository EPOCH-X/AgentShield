"""
[R7] 환경 변수 및 설정 관리
"""

import os
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # PostgreSQL
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "postgresql+asyncpg://agentshield:agentshield@localhost:5432/agentshield",
    )

    # JWT
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "change-me-in-production")
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 60 * 24  # 24시간

    # Ollama
    OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    OLLAMA_MODEL: str = "gemma4:e2b"

    # ChromaDB
    CHROMADB_PERSIST_PATH: str = os.getenv("CHROMADB_PERSIST_PATH", "./chromadb_data")

    # Defense Proxy
    DEFENSE_PROXY_URL: str = os.getenv(
        "DEFENSE_PROXY_URL", "http://localhost:8001"
    )

    # Monitoring Proxy
    MONITORING_PROXY_URL: str = os.getenv(
        "MONITORING_PROXY_URL", "http://localhost:8002"
    )

    # Phase 1
    PHASE1_CONCURRENCY: int = 10
    PHASE1_TIMEOUT: int = 30

    # Phase 2
    PHASE2_MAX_ROUNDS: int = 10

    # Phase 4
    PHASE4_MAX_ITERATIONS: int = 3
    PHASE4_BLOCK_RATE_THRESHOLD: float = 0.80
    PHASE4_FP_RATE_THRESHOLD: float = 0.05

    # LoRA Adapters
    LORA_RED_PATH: str = os.getenv("LORA_RED_PATH", "./adapters/lora-red")
    LORA_JUDGE_PATH: str = os.getenv("LORA_JUDGE_PATH", "./adapters/lora-judge")
    LORA_BLUE_PATH: str = os.getenv("LORA_BLUE_PATH", "./adapters/lora-blue")

    class Config:
        env_file = ".env"


settings = Settings()

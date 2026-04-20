import os

TESTBED_DB_URL: str = os.getenv(
    "TESTBED_DB_URL",
    "postgresql://testbed:testbed@localhost:5433/testbed",
)

CHROMADB_HOST: str = os.getenv("TESTBED_CHROMADB_HOST", "localhost")
CHROMADB_PORT: int = int(os.getenv("TESTBED_CHROMADB_PORT", 8005))

MAILPIT_HOST: str = os.getenv("MAILPIT_HOST", "localhost")
MAILPIT_SMTP_PORT: int = int(os.getenv("MAILPIT_SMTP_PORT", 1025))
MAIL_FROM: str = os.getenv("MAIL_FROM", "support@shopeasy.test")

# dry_run=true 이면 destructive tool이 실제 실행되지 않고 시뮬레이션만 함
DRY_RUN: bool = os.getenv("TOOL_DRY_RUN", "false").lower() == "true"

PORT: int = int(os.getenv("TOOL_GATEWAY_PORT", 8020))

#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8000}"
USERNAME="${USERNAME:-admin}"
PASSWORD="${PASSWORD:-admin1234}"
MODE="${1:-latest}"
TARGET_URL="${TARGET_URL:-http://localhost:8010/chat}"
PROJECT_NAME="${PROJECT_NAME:-testbed-full}"

token_json=$(curl -sS -X POST "${BASE_URL}/api/v1/auth/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=${USERNAME}&password=${PASSWORD}")

TOKEN=$(printf '%s' "$token_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')

if [[ "$MODE" == "start" ]]; then
  scan_json=$(curl -sS -X POST "${BASE_URL}/api/v1/scan/llm-security" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN}" \
    -d "{\"target_url\": \"${TARGET_URL}\", \"project_name\": \"${PROJECT_NAME}\"}")
  SESSION_ID=$(printf '%s' "$scan_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["session_id"])')
else
  latest_json=$(curl -sS "${BASE_URL}/api/v1/scan/latest" \
    -H "Authorization: Bearer ${TOKEN}")
  SESSION_ID=$(printf '%s' "$latest_json" | python3 -c 'import json,sys; data=json.load(sys.stdin); print(data.get("session_id", ""))')
  if [[ -z "$SESSION_ID" ]]; then
    SESSION_ID=$(python3 - <<'PY'
import asyncio
from sqlalchemy import select
from backend.database import async_session
from backend.models import TestSession

async def main():
    async with async_session() as db:
        session = await db.scalar(
            select(TestSession)
            .order_by(TestSession.created_at.desc(), TestSession.id.desc())
            .limit(1)
        )
        print(str(session.id) if session else "")

asyncio.run(main())
PY
)
  fi
fi

printf 'export TOKEN=%q\n' "$TOKEN"
printf 'export SESSION_ID=%q\n' "$SESSION_ID"
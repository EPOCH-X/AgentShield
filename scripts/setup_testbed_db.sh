#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

CLI_TESTBED_DB_URL="${TESTBED_DB_URL-}"

if [[ -f "${ROOT_DIR}/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "${ROOT_DIR}/.env"
  set +a
fi

if [[ -n "${CLI_TESTBED_DB_URL}" ]]; then export TESTBED_DB_URL="${CLI_TESTBED_DB_URL}"; fi

PYTHON_BIN="${ROOT_DIR}/venv/bin/python"
DB_URL="${TESTBED_DB_URL:-postgresql://testbed:testbed@localhost:5433/testbed}"

if ! command -v psql >/dev/null 2>&1; then
  echo "psql is required but not installed or not in PATH" >&2
  exit 1
fi

if [[ ! -x "${PYTHON_BIN}" ]]; then
  echo "venv python is missing: ${PYTHON_BIN}" >&2
  echo "create the venv first and install requirements" >&2
  exit 1
fi

echo "[1/4] applying schema to ${DB_URL}"
psql "${DB_URL}" -v ON_ERROR_STOP=1 -f "${ROOT_DIR}/database/testbed_schema.sql"

echo "[2/4] seeding testbed data"
TESTBED_DB_URL="${DB_URL}" "${PYTHON_BIN}" "${ROOT_DIR}/scripts/seed_testbed.py"

echo "[3/4] quick row-count verification"
psql "${DB_URL}" -v ON_ERROR_STOP=1 -c "SELECT COUNT(*) AS customers FROM customers;"
psql "${DB_URL}" -v ON_ERROR_STOP=1 -c "SELECT COUNT(*) AS orders FROM orders;"
psql "${DB_URL}" -v ON_ERROR_STOP=1 -c "SELECT COUNT(*) AS support_tickets FROM support_tickets;"
psql "${DB_URL}" -v ON_ERROR_STOP=1 -c "SELECT COUNT(*) AS password_reset_requests FROM password_reset_requests;"
psql "${DB_URL}" -v ON_ERROR_STOP=1 -c "SELECT COUNT(*) AS refund_requests FROM refund_requests;"
psql "${DB_URL}" -v ON_ERROR_STOP=1 -c "SELECT COUNT(*) AS audit_logs FROM audit_logs;"

echo "[4/4] done"
echo "next: run '${ROOT_DIR}/venv/bin/python ${ROOT_DIR}/scripts/ingest_testbed_kb.py' if Chroma is up"
echo "then run '${ROOT_DIR}/scripts/testbed_local.sh up-and-smoke'"
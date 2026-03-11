#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="${OSINT_VENV_DIR:-$ROOT_DIR/.venv}"
API_BASE="${OSINT_API_BASE:-http://127.0.0.1:8000}"
API_STATUS_URL="$API_BASE/api/v1/status"

if [[ ! -x "$VENV_DIR/bin/python" ]]; then
  echo "[smoke] missing venv python: $VENV_DIR/bin/python"
  echo "[smoke] run scripts/setup_env.sh first."
  exit 1
fi

TMP_DIR="$(mktemp -d)"
SERVER_PID=""
SERVER_STARTED_BY_SCRIPT=false

cleanup() {
  if [[ "$SERVER_STARTED_BY_SCRIPT" == true && -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" >/dev/null 2>&1 || true
    wait "$SERVER_PID" >/dev/null 2>&1 || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

is_api_up() {
  local code
  code="$(curl -s -o /dev/null -w "%{http_code}" "$API_STATUS_URL" || true)"
  [[ "$code" == "200" ]]
}

if is_api_up; then
  echo "[smoke] using already running API at $API_BASE"
else
  echo "[smoke] starting API from run.py..."
  (
    cd "$ROOT_DIR"
    "$VENV_DIR/bin/python" run.py
  ) >"$TMP_DIR/api.log" 2>&1 &
  SERVER_PID="$!"
  SERVER_STARTED_BY_SCRIPT=true

  for _ in $(seq 1 30); do
    if is_api_up; then
      break
    fi
    sleep 1
  done
fi

if ! is_api_up; then
  echo "[smoke] API is not reachable: $API_STATUS_URL"
  if [[ -f "$TMP_DIR/api.log" ]]; then
    echo "[smoke] api.log (tail):"
    tail -n 80 "$TMP_DIR/api.log" || true
  fi
  exit 1
fi

echo "[smoke] checking /api/v1/status..."
status_json="$(curl -fsS "$API_STATUS_URL")"
echo "$status_json"

echo "[smoke] checking /api/v1/modules..."
modules_json="$(curl -fsS "$API_BASE/api/v1/modules")"
MODULES_JSON="$modules_json" "$VENV_DIR/bin/python" - <<'PY'
import json
import os
data = json.loads(os.environ["MODULES_JSON"])
if not isinstance(data, list) or not data:
    raise SystemExit("No modules returned by /modules")
print(f"[smoke] modules loaded: {len(data)}")
PY

echo "[smoke] creating test case..."
case_json="$(curl -fsS -X POST "$API_BASE/api/v1/cases" \
  -H "Content-Type: application/json" \
  -d '{"title":"Smoke Test Case","tags":["smoke","automation"],"priority":"normal"}')"
CASE_JSON="$case_json" "$VENV_DIR/bin/python" - <<'PY'
import json
import os
case = json.loads(os.environ["CASE_JSON"])
cid = case.get("id")
if not isinstance(cid, int) or cid <= 0:
    raise SystemExit("Case create failed")
print(f"[smoke] case id: {cid}")
PY

echo "[smoke] queueing domain scan..."
scan_json="$(curl -fsS -X POST "$API_BASE/api/v1/scan" \
  -H "Content-Type: application/json" \
  -d '{"target":"example.com","target_type":"domain"}')"
SCAN_JSON="$scan_json" "$VENV_DIR/bin/python" - <<'PY'
import json
import os
scan = json.loads(os.environ["SCAN_JSON"])
jid = scan.get("job_id")
if not isinstance(jid, str) or not jid:
    raise SystemExit("Scan did not return job_id")
print(f"[smoke] job id: {jid} status={scan.get('status')}")
PY

echo "[smoke] success."

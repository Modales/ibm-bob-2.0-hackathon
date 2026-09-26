#!/usr/bin/env bash
#
# demo.sh — IBM Bob 2.0 Hackathon live demo runner
# =================================================
# One command boots the whole system and runs a real end-to-end
# modernization pass against the seeded vulnerable repo in demo/legacy-app:
#
#   1. Seeds git history into demo/legacy-app (so churn analysis has data)
#   2. Boots the Auditor service   -> http://localhost:8001  (/scan-repo)
#   3. Boots the Orchestrator      -> http://localhost:8000  (JWT-secured)
#   4. Authenticates, triggers POST /api/v1/modernize, pretty-prints the
#      consolidated result (findings, debates, healing, ROI)
#
# Usage:
#   ./demo/demo.sh            # full run
#   ./demo/demo.sh --watch    # afterwards, attach to the live SSE log stream
#
# Prereqs: python3.11+, and each service's requirements installed:
#   pip install -r services/auditor/requirements.txt
#   pip install -r services/orchestrator/requirements.txt
#
set -euo pipefail

DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${DEMO_DIR}/.." && pwd)"
LEGACY_APP="${DEMO_DIR}/legacy-app"
AUDITOR_DIR="${REPO_ROOT}/services/auditor"
ORCH_DIR="${REPO_ROOT}/services/orchestrator"

AUDITOR_PORT=8001
ORCH_PORT=8000
DEMO_USER="${ADMIN_USERNAME:-admin}"
DEMO_PASS="${ADMIN_PASSWORD:-bob-hackathon-2026}"

info() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m  ✓\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 0. Sanity checks
# ---------------------------------------------------------------------------
command -v python3 >/dev/null || die "python3 not found"
[ -d "${AUDITOR_DIR}" ] || die "auditor service not found at ${AUDITOR_DIR} (run from a full repo checkout)"
[ -d "${ORCH_DIR}" ] || die "orchestrator service not found at ${ORCH_DIR}"
[ -d "${LEGACY_APP}" ] || die "demo target not found at ${LEGACY_APP}"

python3 - <<'PY' || die "missing deps — run: pip install -r services/orchestrator/requirements.txt -r services/auditor/requirements.txt"
import fastapi, uvicorn, httpx, pydantic  # noqa: F401
try:
    import git  # noqa: F401  (gitpython — auditor churn)
except ImportError:
    print("warning: gitpython missing, churn analysis will degrade gracefully")
PY

# ---------------------------------------------------------------------------
# 1. Seed git history into the demo target (idempotent) — feeds churn analysis
# ---------------------------------------------------------------------------
if [ ! -d "${LEGACY_APP}/.git" ]; then
  info "Seeding git history into demo/legacy-app (for churn analysis)..."
  git -C "${LEGACY_APP}" init -q -b main
  git -C "${LEGACY_APP}" config user.email "demo@hackathon.local"
  git -C "${LEGACY_APP}" config user.name "Legacy Corp"
  git -C "${LEGACY_APP}" add -A
  GIT_AUTHOR_DATE="2026-08-01T10:00:00Z" GIT_COMMITTER_DATE="2026-08-01T10:00:00Z" \
    git -C "${LEGACY_APP}" commit -q -m "legacy: initial import"
  # a few touches so auth.py tops the churn chart
  for i in 1 2 3; do
    printf '# touch %s\n' "$i" >> "${LEGACY_APP}/app/auth.py"
    git -C "${LEGACY_APP}" add app/auth.py
    GIT_AUTHOR_DATE="2026-09-0${i}T10:00:00Z" GIT_COMMITTER_DATE="2026-09-0${i}T10:00:00Z" \
      git -C "${LEGACY_APP}" commit -q -m "fix(auth): patch attempt ${i}"
  done
  ok "git history seeded (4 commits, auth.py most-churned)"
else
  ok "git history already present"
fi

# ---------------------------------------------------------------------------
# 2. Boot services
# ---------------------------------------------------------------------------
PIDS=()
cleanup() {
  info "Shutting down demo services..."
  # Kill subshells AND their orphaned uvicorn children by port — a subshell's
  # python child survives a plain kill of the subshell PID.
  kill "${PIDS[@]}" 2>/dev/null || true
  lsof -ti :"${AUDITOR_PORT}" -ti :"${ORCH_PORT}" 2>/dev/null | xargs kill 2>/dev/null || true
}
trap cleanup EXIT INT TERM

wait_for() {  # wait_for <url> <name>
  for _ in $(seq 1 30); do
    curl -sf "$1" >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  die "$2 did not become healthy at $1"
}

info "Starting Auditor (port ${AUDITOR_PORT})..."
(cd "${AUDITOR_DIR}" && python3 -c "
import uvicorn
uvicorn.run('main:app', host='127.0.0.1', port=${AUDITOR_PORT}, log_level='warning')
") >>"${DEMO_DIR}/.auditor.log" 2>&1 &
PIDS+=($!)
wait_for "http://127.0.0.1:${AUDITOR_PORT}/openapi.json" "Auditor"
ok "Auditor up (log: demo/.auditor.log)"

info "Starting Orchestrator (port ${ORCH_PORT}) — wired to the LIVE auditor..."
(cd "${ORCH_DIR}" && AUDITOR_URL="http://127.0.0.1:${AUDITOR_PORT}/scan-repo" python3 -c "
import uvicorn
uvicorn.run('main:app', host='127.0.0.1', port=${ORCH_PORT}, log_level='warning')
") >>"${DEMO_DIR}/.orchestrator.log" 2>&1 &
PIDS+=($!)
wait_for "http://127.0.0.1:${ORCH_PORT}/health" "Orchestrator"
ok "Orchestrator up (log: demo/.orchestrator.log)"

# ---------------------------------------------------------------------------
# 3. Authenticate (zero-trust) and trigger the pipeline
# ---------------------------------------------------------------------------
info "Authenticating as '${DEMO_USER}'..."
TOKEN=$(curl -sf -X POST "http://127.0.0.1:${ORCH_PORT}/token" \
  -d "username=${DEMO_USER}&password=${DEMO_PASS}" | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])")
ok "JWT acquired"

echo
info "Triggering POST /api/v1/modernize on ${LEGACY_APP} ..."
curl -sf -X POST "http://127.0.0.1:${ORCH_PORT}/api/v1/modernize" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H 'Content-Type: application/json' \
  -d "{\"repo_path\": \"${LEGACY_APP}\", \"target_version\": \"python3.12\"}" \
| python3 "${DEMO_DIR}/pretty_print.py"

ok "Demo run complete."

# ---------------------------------------------------------------------------
# 4. Optional: attach to the live SSE stream for a second run
# ---------------------------------------------------------------------------
if [ "${1:-}" = "--watch" ]; then
  info "Attaching to live SSE stream (Ctrl-C to exit)..."
  curl -sN "http://127.0.0.1:${ORCH_PORT}/api/v1/stream-logs?repo_path=${LEGACY_APP}&target_version=python3.12" \
    | while IFS= read -r line; do
        case "$line" in data:*) echo "  ${line#data: }";; esac
      done
fi

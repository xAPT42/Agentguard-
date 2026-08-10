#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FRONTEND_URL="http://localhost:9002"
GMS_URL="${DATAHUB_URL:-http://localhost:8080}"
WAIT_TIMEOUT=900

cd "$ROOT"

info() { printf '\n\033[1;36m==> %s\033[0m\n' "$1"; }
warn() { printf '\033[1;33mWARN: %s\033[0m\n' "$1"; }
fail() { printf '\033[1;31mERROR: %s\033[0m\n' "$1" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || fail "docker is required but not installed"
docker info >/dev/null 2>&1 || fail "the docker daemon is not reachable, start Docker first"
command -v datahub >/dev/null 2>&1 || fail "datahub CLI not found, run: pip install acryl-datahub"
command -v agentguard >/dev/null 2>&1 || fail "agentguard not on PATH, run: pip install -e ."

wait_for() {
  local url="$1" name="$2" elapsed=0
  info "Waiting for $name at $url (up to ${WAIT_TIMEOUT}s)"
  while ! curl -sf -o /dev/null "$url"; do
    if [ "$elapsed" -ge "$WAIT_TIMEOUT" ]; then
      fail "$name did not come up within ${WAIT_TIMEOUT}s, check: docker logs datahub-datahub-gms-quickstart-1"
    fi
    sleep 5
    elapsed=$((elapsed + 5))
    printf '.'
  done
  printf '\n'
  info "$name is up"
}

info "Starting DataHub via the official quickstart (first run pulls several GB)"
warn "DataHub expects ~8GB of RAM available to Docker."
datahub docker quickstart

wait_for "$GMS_URL/health" "DataHub GMS"
wait_for "$FRONTEND_URL" "DataHub UI"

info "Running AgentGuard against $GMS_URL"
set +e
DATAHUB_URL="$GMS_URL" agentguard --url "$GMS_URL" --output "$ROOT/scan_output.json"
SCAN_EXIT=$?
set -e

cat <<EOF

────────────────────────────────────────────────────────────
 AgentGuard demo complete
────────────────────────────────────────────────────────────

 Local report:  $ROOT/scan_output.json
 DataHub UI:    $FRONTEND_URL   (login: datahub / datahub)

 In the UI:
   1. Search for the tag  agentguard-discovered
   2. Filter by           risk-critical  or  orphaned
   3. Open any asset → Properties tab → agentguard.eu_ai_act.* fields
   4. Open the Lineage tab to see  agent → mcp_server → dataset

 Stop DataHub:  datahub docker quickstart --stop
 Remove it all: datahub docker nuke

EOF

if [ "$SCAN_EXIT" -eq 1 ]; then
  warn "Critical assets were found, agentguard exited 1 (this is the CI gate working)."
else
  info "No critical assets found."
fi

exit 0

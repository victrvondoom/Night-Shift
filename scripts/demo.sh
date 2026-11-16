#!/usr/bin/env bash
# One interface for the hackathon demo. Usage: scripts/demo.sh up|status|trigger|reset|verify|down
# DEMO_MODE=sim  (default) deterministic DEMO_SIMULATOR; nothing touches a real cluster.
# DEMO_MODE=live uses `demo/trigger.sh break-netpol` on the current kubectl context (a sandbox k3d
#                cluster from `make cluster up`). The mode chosen at `up` is remembered: trigger and
#                reset never silently switch between live and simulated.
set -uo pipefail
cd "$(dirname "$0")/.."
RUN=.demo
mkdir -p "$RUN"
PY=${PY:-.venv/bin/python}
MODE=${DEMO_MODE:-sim}
export DATABASE_URL=${DATABASE_URL:-postgresql://beacon:beacon@localhost:5433/beacon}
export NATS_URL=${NATS_URL:-nats://localhost:4222}
export OPA_URL=${OPA_URL:-http://localhost:8281}
export PASSCODE=${PASSCODE:-demo-pass} ALERT_WEBHOOK_TOKEN=${ALERT_WEBHOOK_TOKEN:-alert-token} AUDIT_WEBHOOK_TOKEN=${AUDIT_WEBHOOK_TOKEN:-audit-token}
export REMEDIABLE_NAMESPACES=demo GOLDEN_TARGETS=demo/demo-db-ingress REMEDIABLE_DEPLOYMENTS= LEGACY_TRIAGE=false
export LOG_SELECTORS='{namespace="demo"}' BEACON_K8S_IDENTITY=system:serviceaccount:beacon:beacon-remediator
export CORRELATOR_URL=http://127.0.0.1:9103 NIGHTSHIFT_API=http://127.0.0.1:8080 HEALTH_CHECK_ALLOW=localhost,127.0.0.1
if [ "$MODE" = sim ]; then
  export SIMULATOR_URL=http://127.0.0.1:8090 PROMETHEUS_URL=http://127.0.0.1:8090/prom SANDBOX_CONTEXTS=demo-simulator
  export REMEDIATION_MODE=inline VERIFY_WAIT_SECONDS=3 VERIFY_MAX_ATTEMPTS=6
fi
API=http://127.0.0.1:8080
UI=http://127.0.0.1:5173

need() { command -v "$1" >/dev/null 2>&1 || { echo "MISSING: $1 -- $2" >&2; return 1; }; }
up_port() { (exec 3<>/dev/tcp/127.0.0.1/"$1") 2>/dev/null; }
wait_http() {
  for _ in $(seq 1 60); do curl -fsS -o /dev/null "$1" 2>/dev/null && return 0; sleep 1; done
  echo "TIMEOUT waiting for $1" >&2
  return 1
}
alive() { [ -s "$RUN/$1.pid" ] && kill -0 "$(cat "$RUN/$1.pid")" 2>/dev/null; }
start() {
  local name=$1
  shift
  alive "$name" && return 0
  nohup "$@" >"$RUN/$name.log" 2>&1 &
  echo $! >"$RUN/$name.pid"
}
stop_all() {
  for f in "$RUN"/*.pid; do
    [ -s "$f" ] && kill "$(cat "$f")" 2>/dev/null
    : >"$f"
  done
}
mode_now() { cat "$RUN/mode" 2>/dev/null || echo "$MODE"; }

case "${1:-}" in
up)
  bad=0
  [ -x "$PY" ] || { echo "MISSING: $PY -- run 'make setup'" >&2; bad=1; }
  need node "install Node 20+" || bad=1
  up_port 5433 || { echo "MISSING: PostgreSQL on :5433 -- 'docker compose -f deploy/demo/docker-compose.yml up -d postgres' or start your own" >&2; bad=1; }
  if ! up_port 4222; then need nats-server "install nats-server or use deploy/demo/docker-compose.yml" && start nats nats-server -js -p 4222 || bad=1; fi
  if ! up_port 8281; then need opa "install opa or use deploy/demo/docker-compose.yml" && start opa opa run --server --addr=0.0.0.0:8281 policy || bad=1; fi
  [ $bad = 0 ] || { echo "demo-up: prerequisites missing (see above)"; exit 1; }
  wait_http "http://127.0.0.1:8281/health" || exit 1
  [ "$MODE" = sim ] && start sim "$PY" -m beacon.sim.server
  start api .venv/bin/uvicorn beacon.server:app --port 8080
  wait_http "$API/healthz" || exit 1
  start correlator "$PY" -m beacon.correlator
  start worker "$PY" -m beacon.worker
  [ -d web/node_modules ] || (cd web && npm ci)
  if ! alive web; then
    (cd web && BEACON_API=$API nohup npx vite --host 127.0.0.1 --port 5173 >"../$RUN/web.log" 2>&1 & echo $! >"../$RUN/web.pid")
  fi
  wait_http "$UI/" && wait_http "http://127.0.0.1:9103/healthz" || exit 1
  echo "$MODE" >"$RUN/mode"
  echo "mode: $MODE"
  echo "UI:   $UI/#workspace   (console passcode: $PASSCODE)"
  echo "API:  $API"
  echo "optional credentials:"
  for v in BIFROST_URL TAVILY_API_KEY OMNIDIM_API_KEY OMNIDIM_AGENT_ID; do
    if [ -n "${!v:-}" ]; then echo "  $v set"; else echo "  $v NOT_CONFIGURED (the UI reports NOT_CONFIGURED for that integration)"; fi
  done
  ;;
status)
  curl -fsS "$API/api/system/integrations" | "$PY" -c "import sys,json;[print(f\"{r['integration']:<20} {r['state']:<22} {r['mode']:<15} {r['detail'][:70]}\") for r in json.load(sys.stdin)['integrations']]"
  ;;
trigger)
  if [ "$(mode_now)" = live ]; then
    need kubectl "live mode needs a sandbox cluster (make cluster up)" || exit 1
    demo/trigger.sh break-netpol && echo "LIVE trigger sent; watch $UI/#workspace"
  else
    curl -fsS -XPOST -H "x-beacon-passcode: $PASSCODE" "$API/api/demo/trigger"
    echo
    sleep "${WAIT:-14}"
    curl -fsS "$API/api/ns/incidents" | "$PY" -c "import sys,json;d=json.load(sys.stdin)['incidents'];print('incident_id:',d[0]['incident_id'] if d else 'none yet (still correlating)')"
  fi
  ;;
reset)
  if [ "$(mode_now)" = live ]; then demo/trigger.sh restore; exit $?; fi
  curl -fsS -XPOST -H "x-beacon-passcode: $PASSCODE" "$API/api/demo/reset" # removes DEMO_SIMULATOR records only
  echo
  [ -s "$RUN/correlator.pid" ] && kill "$(cat "$RUN/correlator.pid")" 2>/dev/null
  sleep 1
  start correlator "$PY" -m beacon.correlator
  wait_http http://127.0.0.1:9103/healthz && echo "correlator restarted (clean Pathway state)"
  ;;
verify) "$PY" scripts/hackathon_verify.py ;;
down) stop_all; echo stopped ;;
*) echo "usage: $0 up|status|trigger|reset|verify|down" >&2; exit 2 ;;
esac

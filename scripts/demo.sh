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
  export VERIFY_WAIT_SECONDS=3 VERIFY_MAX_ATTEMPTS=6
fi
# DEMO_EXEC=inline (default): remediation steps run in the worker process (INLINE_DEMO_ADAPTER, NOT Temporal)
# DEMO_EXEC=temporal: a real Temporal dev server + worker execute RemediationWorkflow (TEMPORAL_LOCAL)
EXEC=${DEMO_EXEC:-inline}
if [ "$EXEC" = temporal ]; then
  export REMEDIATION_MODE=temporal TEMPORAL_ADDRESS=127.0.0.1:7233
else
  export REMEDIATION_MODE=inline
fi
SBX=${SANDBOX_DIR:-/var/tmp/nightshift-sandbox}
if [ "$MODE" = k3s ]; then
  # REAL kube-apiserver/etcd/RBAC/audit (k3s) + real Prometheus/Alertmanager + the unmodified demo app.
  # There is NO kubelet and no CNI: NetworkPolicy is enforced by beacon.sandbox.dataplane (EMULATED_DATAPLANE).
  export K8S_FLAVOUR=k3s K8S_API_URL=https://127.0.0.1:6443 PROMETHEUS_URL=http://127.0.0.1:9090 SANDBOX_CONTEXTS=nightshift-sandbox REQUIRE_SANDBOX=true BEACON_K8S_CONTEXT=nightshift-sandbox
  export VERIFY_WAIT_SECONDS=${VERIFY_WAIT_SECONDS:-6} VERIFY_MAX_ATTEMPTS=${VERIFY_MAX_ATTEMPTS:-12}
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
  setsid nohup "$@" >"$RUN/$name.log" 2>&1 </dev/null &
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
  # Never let the printed mode disagree with the processes that are actually running.
  if [ -s "$RUN/mode" ] && [ -s "$RUN/exec" ] && { alive api || alive worker; }; then
    if [ "$(cat "$RUN/mode")" != "$MODE" ] || [ "$(cat "$RUN/exec")" != "$EXEC" ]; then
      echo "REFUSED: demo already running as mode=$(cat "$RUN/mode") exec=$(cat "$RUN/exec"); run 'make demo-down' before switching to mode=$MODE exec=$EXEC" >&2
      exit 1
    fi
  fi
  [ -x "$PY" ] || { echo "MISSING: $PY -- run 'make setup'" >&2; bad=1; }
  need node "install Node 20+" || bad=1
  up_port 5433 || { echo "MISSING: PostgreSQL on :5433 -- 'docker compose -f deploy/demo/docker-compose.yml up -d postgres' or start your own" >&2; bad=1; }
  if ! up_port 4222; then need nats-server "install nats-server or use deploy/demo/docker-compose.yml" && start nats nats-server -js -p 4222 || bad=1; fi
  if ! up_port 8281; then need opa "install opa or use deploy/demo/docker-compose.yml" && start opa opa run --server --addr=0.0.0.0:8281 policy || bad=1; fi
  [ $bad = 0 ] || { echo "demo-up: prerequisites missing (see above)"; exit 1; }
  wait_http "http://127.0.0.1:8281/health" || exit 1
  if [ "$EXEC" = temporal ]; then
    up_port 7233 || { need temporal "install the Temporal CLI (temporal server start-dev)" && start temporal temporal server start-dev --headless --port 7233 --db-filename "$RUN/temporal.db" || exit 1; }
    for _ in $(seq 1 60); do up_port 7233 && break; sleep 1; done
    up_port 7233 || { echo "TIMEOUT waiting for Temporal on :7233" >&2; exit 1; }
  fi
  [ "$MODE" = sim ] && start sim "$PY" -m beacon.sim.server
  start api .venv/bin/uvicorn beacon.server:app --port 8080
  wait_http "$API/healthz" || exit 1
  start correlator "$PY" -m beacon.correlator
  # only the worker holds cluster credentials (the restricted beacon-remediator ServiceAccount in k3s mode)
  if [ "$MODE" = k3s ]; then KUBECONFIG="$SBX/remediator.yaml" start worker "$PY" -m beacon.worker; else start worker "$PY" -m beacon.worker; fi
  [ -d web/node_modules ] || (cd web && npm ci)
  BEACON_API=$API start web bash -c 'cd web && exec npx vite --host 127.0.0.1 --port 5173'
  wait_http "$UI/" && wait_http "http://127.0.0.1:9103/healthz" || exit 1
  if [ "$MODE" = k3s ]; then
    scripts/k3s_sandbox.sh up || exit 1
    # the worker was started before the remediator kubeconfig existed on a first run: restart it with credentials
    [ -s "$RUN/worker.pid" ] && kill "$(cat "$RUN/worker.pid")" 2>/dev/null; sleep 1
    KUBECONFIG="$SBX/remediator.yaml" start worker "$PY" -m beacon.worker
    scripts/sandbox_stack.sh up || exit 1
  fi
  echo "$MODE" >"$RUN/mode"
  echo "$EXEC" >"$RUN/exec"
  echo "mode: $MODE$([ "$MODE" = k3s ] && echo " (REAL_CONTROL_PLANE + EMULATED_DATAPLANE)")   execution: $([ "$EXEC" = temporal ] && echo TEMPORAL_LOCAL || echo INLINE_DEMO_ADAPTER)"
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
  if [ "$(mode_now)" = k3s ]; then
    scripts/k3s_sandbox.sh break && echo "REAL NetworkPolicy edit applied to the k3s control plane; the audit event, app errors and Prometheus alert follow" && sleep "${WAIT:-25}"
    curl -fsS -H "x-beacon-passcode: $PASSCODE" "$API/api/ns/incidents" | "$PY" -c "import sys,json;d=json.load(sys.stdin)['incidents'];print('incident_id:',d[0]['incident_id'] if d else 'none yet (still correlating)')"
  elif [ "$(mode_now)" = live ]; then
    need kubectl "live mode needs a sandbox cluster (make cluster up)" || exit 1
    demo/trigger.sh break-netpol && echo "LIVE trigger sent; watch $UI/#workspace"
  else
    curl -fsS -XPOST -H "x-beacon-passcode: $PASSCODE" "$API/api/demo/trigger"
    echo
    sleep "${WAIT:-14}"
    curl -fsS -H "x-beacon-passcode: $PASSCODE" "$API/api/ns/incidents" | "$PY" -c "import sys,json;d=json.load(sys.stdin)['incidents'];print('incident_id:',d[0]['incident_id'] if d else 'none yet (still correlating)')"
  fi
  ;;
reset)
  if [ "$(mode_now)" = k3s ]; then scripts/k3s_sandbox.sh restore; exit $?; fi
  if [ "$(mode_now)" = live ]; then demo/trigger.sh restore; exit $?; fi
  curl -fsS -XPOST -H "x-beacon-passcode: $PASSCODE" "$API/api/demo/reset" # removes DEMO_SIMULATOR records only
  echo
  # Pathway needs no restart: events are scoped by run_id, so an old run can never join a new one.
  [ "${RESET_CORRELATOR:-0}" = 1 ] && { [ -s "$RUN/correlator.pid" ] && kill "$(cat "$RUN/correlator.pid")" 2>/dev/null; sleep 1; start correlator "$PY" -m beacon.correlator; wait_http http://127.0.0.1:9103/healthz && echo "correlator restarted (RESET_CORRELATOR=1)"; }
  ;;
verify) "$PY" scripts/hackathon_verify.py ;;
down) stop_all; [ "$(mode_now)" = k3s ] && scripts/sandbox_stack.sh down; echo stopped ;;
*) echo "usage: $0 up|status|trigger|reset|verify|down" >&2; exit 2 ;;
esac

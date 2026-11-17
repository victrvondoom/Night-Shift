#!/usr/bin/env bash
# Real Prometheus + Alertmanager + the (emulated) data plane for the k3s control-plane sandbox.
#   scripts/sandbox_stack.sh up | down | status
# Prometheus and Alertmanager are the real upstream binaries.  They scrape the real demo app and evaluate the real
# DemoDbErrors rule; Alertmanager posts the real alert to Night Shift's /alerts webhook.
set -uo pipefail
cd "$(dirname "$0")/.."
DIR=${SANDBOX_DIR:-/var/tmp/nightshift-sandbox}
MON=${MON_BIN:-/var/tmp/mon-bin}
PROM=$(ls -d "$MON"/prometheus-*/ 2>/dev/null | head -1)
AM=$(ls -d "$MON"/alertmanager-*/ 2>/dev/null | head -1)
API_URL=${NIGHTSHIFT_API:-http://127.0.0.1:8080}
ALERT_TOKEN=${ALERT_WEBHOOK_TOKEN:-alert-token}
PY=${PY:-.venv/bin/python}
die() { echo "REFUSED: $*" >&2; exit 2; }
alive() { [ -s "$DIR/$1.pid" ] && kill -0 "$(cat "$DIR/$1.pid")" 2>/dev/null; }
start() { local n=$1; shift; alive "$n" && return 0; setsid nohup "$@" >"$DIR/$n.log" 2>&1 </dev/null & echo $! >"$DIR/$n.pid"; }
wait_http() { for _ in $(seq 1 40); do curl -fsS -o /dev/null "$1" 2>/dev/null && return 0; sleep 1; done; echo "TIMEOUT $1" >&2; return 1; }

case "${1:-}" in
up)
  [ -f "$DIR/admin.yaml" ] || die "run scripts/k3s_sandbox.sh up first"
  [ -n "$PROM" ] && [ -n "$AM" ] || die "Prometheus/Alertmanager binaries not found under $MON (download from https://github.com/prometheus/prometheus/releases and /alertmanager/releases)"
  mkdir -p "$DIR/mon"
  cat >"$DIR/mon/rules.yml" <<'YAML'
groups:
  - name: demo
    rules:
      - alert: DemoDbErrors
        expr: sum by (namespace) (rate(demo_db_requests_total{result="error"}[10s])) > 0
        for: 4s
        labels: {severity: page, namespace: demo, service: demo-api}
        annotations:
          summary: demo-api cannot reach demo-db
          description: database connection errors > 0 over 10s in namespace demo
          beacon_health_url: http://127.0.0.1:8081/ready
YAML
  cat >"$DIR/mon/prometheus.yml" <<YAML
global: {scrape_interval: 2s, evaluation_interval: 2s}
rule_files: [$DIR/mon/rules.yml]
alerting: {alertmanagers: [{static_configs: [{targets: ["127.0.0.1:9093"]}]}]}
scrape_configs:
  - job_name: demo-api
    static_configs: [{targets: ["127.0.0.1:8081"], labels: {namespace: demo, service: demo-api}}]
YAML
  cat >"$DIR/mon/alertmanager.yml" <<YAML
route: {receiver: nightshift, group_by: [alertname, namespace], group_wait: 0s, group_interval: 5s, repeat_interval: 1h}
receivers:
  - name: nightshift
    webhook_configs:
      - url: $API_URL/alerts
        send_resolved: false
        http_config: {authorization: {type: Bearer, credentials: "$ALERT_TOKEN"}}
YAML
  start alertmanager "${AM}alertmanager" --config.file="$DIR/mon/alertmanager.yml" --storage.path="$DIR/mon/am-data" --web.listen-address=127.0.0.1:9093
  start prometheus "${PROM}prometheus" --config.file="$DIR/mon/prometheus.yml" --storage.tsdb.path="$DIR/mon/prom-data" --web.listen-address=127.0.0.1:9090 --storage.tsdb.retention.time=2h
  DATAPLANE_KUBECONFIG="$DIR/admin.yaml" start dataplane "$PY" -m beacon.sandbox.dataplane
  wait_http http://127.0.0.1:9093/-/ready && wait_http http://127.0.0.1:9090/-/ready && wait_http http://127.0.0.1:8081/ready || exit 1
  echo "monitoring + EMULATED_DATAPLANE up: prometheus :9090  alertmanager :9093  app :8081"
  ;;
status)
  for n in alertmanager prometheus dataplane; do alive $n && echo "$n up" || echo "$n down"; done
  curl -fsS http://127.0.0.1:8081/ready 2>&1 | head -c 100; echo
  curl -fsS "http://127.0.0.1:9090/api/v1/query?query=ALERTS" 2>/dev/null | head -c 300; echo
  ;;
down)
  for n in dataplane prometheus alertmanager; do [ -s "$DIR/$n.pid" ] && kill "$(cat "$DIR/$n.pid")" 2>/dev/null; : >"$DIR/$n.pid"; done
  pkill -f beacon.sandbox.dataplane 2>/dev/null
  pkill -f "demo/app.py" 2>/dev/null
  echo stopped
  ;;
*) echo "usage: $0 up|down|status" >&2; exit 2 ;;
esac

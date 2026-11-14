#!/usr/bin/env bash
# Bring the whole Night Shift stack up on the current kubectl context.
#   deploy/up.sh           build images, create secrets from .env, apply everything
# Works on k3d (make cluster) or any cluster whose nodes can see locally built images.
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "copy .env.example to .env first" >&2; exit 1; }
set -a; . ./.env; set +a
K="kubectl"
IMPORT="${K3D_CLUSTER:+k3d image import -c $K3D_CLUSTER}"

if [ -z "${SKIP_BUILD:-}" ]; then
  echo "== images"
  docker build -q -t beacon:local .
  docker build -q -t beacon-web:local web
  docker build -q -t beacon-demo:local -f demo/Dockerfile.demo demo
fi
if [ -n "$IMPORT" ]; then $IMPORT beacon:local beacon-web:local beacon-demo:local; fi

echo "== namespaces and secrets"
$K apply -f deploy/k8s/demo/demo.yaml
$K create namespace beacon --dry-run=client -o yaml | $K apply -f -
PG="${POSTGRES_PASSWORD:-beacon}"
$K -n beacon create secret generic beacon-bootstrap --dry-run=client -o yaml \
  --from-literal=POSTGRES_PASSWORD="$PG" \
  --from-literal=DATABASE_URL="postgresql://beacon:$PG@postgres:5432/beacon" \
  --from-literal=VAULT_TOKEN="${VAULT_TOKEN:?set VAULT_TOKEN in .env}" \
  --from-literal=MINIO_SECRET_KEY="${MINIO_SECRET_KEY:?set MINIO_SECRET_KEY in .env}" | $K apply -f -
# Application secrets: seeded into Vault by the vault-seed Job; Night Shift reads them there.
args=()
for name in PASSCODE ALERT_WEBHOOK_TOKEN AUDIT_WEBHOOK_TOKEN BOLNA_API_KEY BOLNA_AGENT_ID \
  BOLNA_TOOL_TOKEN BOLNA_WEBHOOK_SECRET GITHUB_PR_TOKEN GITHUB_WEBHOOK_SECRET \
  TELEGRAM_BOT_TOKEN SLACK_WEBHOOK_URL PAGERDUTY_ROUTING_KEY; do
  value="${!name:-}"
  [ -n "$value" ] && args+=(--from-literal="$name=$value")
done
$K -n beacon create secret generic beacon-app-secrets --dry-run=client -o yaml "${args[@]}" | $K apply -f -
$K -n beacon create configmap beacon-policy --from-file=policy/ --dry-run=client -o yaml | $K apply -f -
# Only needed behind an egress proxy (CI sandboxes); harmless when unset.
if [ -n "${CLUSTER_HTTPS_PROXY:-}" ]; then
  $K -n beacon create configmap beacon-proxy --dry-run=client -o yaml \
    --from-literal=HTTPS_PROXY="$CLUSTER_HTTPS_PROXY" --from-literal=HTTP_PROXY="$CLUSTER_HTTPS_PROXY" | $K apply -f -
fi

echo "== platform and Night Shift"
$K apply -f deploy/k8s/platform/ -f deploy/k8s/beacon/
[ -n "${LOG_FORMAT:-}" ] && $K -n beacon patch configmap beacon-env --type merge -p "{\"data\":{\"LOG_FORMAT\":\"$LOG_FORMAT\"}}"
[ -n "${TELEGRAM_CHAT_ID:-}" ] && $K -n beacon patch configmap beacon-env --type merge -p "{\"data\":{\"TELEGRAM_CHAT_ID\":\"$TELEGRAM_CHAT_ID\"}}"
$K -n beacon delete job vault-seed --ignore-not-found >/dev/null
$K apply -f deploy/k8s/platform/data.yaml >/dev/null

echo "== waiting"
$K -n demo rollout status deploy/demo-api deploy/demo-db --timeout=300s
for d in postgres nats opa vault temporal prometheus alertmanager loki beacon-api beacon-worker beacon-web; do
  $K -n beacon rollout status "deploy/$d" --timeout=600s
done
$K -n beacon rollout restart deploy/beacon-api deploy/beacon-worker >/dev/null
$K -n beacon rollout status deploy/beacon-worker --timeout=300s
echo "== golden snapshot (taken now, while the demo is healthy)"
$K -n beacon exec deploy/beacon-worker -- python -m beacon.snapshot
echo "Console: http://localhost:30080   Grafana: http://localhost:30300"

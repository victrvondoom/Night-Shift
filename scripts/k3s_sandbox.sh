#!/usr/bin/env bash
# Disposable REAL Kubernetes control plane for Night Shift (k3s, no Docker needed).
#   scripts/k3s_sandbox.sh up | status | break | restore | down
#
# What is real:      kube-apiserver, etcd, controller-manager, scheduler, RBAC, admission, server-side dry-run,
#                    optimistic concurrency, and the API-server AUDIT WEBHOOK that feeds Night Shift.
# What is NOT real:  there is no kubelet (`--disable-agent`): this VM cannot start pod sandboxes (runc fails on every
#                    CRI sandbox here), so no pod ever runs and NetworkPolicy is not enforced by a CNI.  The data
#                    plane is emulated by `python -m beacon.sandbox.dataplane`, which READS the real NetworkPolicy
#                    from the real API server and gates the app->db connection accordingly.  Label: REAL_CONTROL_PLANE
#                    + EMULATED_DATAPLANE.  Never present this as a full cluster.
set -uo pipefail
cd "$(dirname "$0")/.."
K3S=${K3S_BIN:-/var/tmp/k3s-bin/k3s}
DIR=${SANDBOX_DIR:-/var/tmp/nightshift-sandbox}
DATA=${SANDBOX_DATA:-/var/tmp/nightshift-sandbox-data}
CTX=${SANDBOX_KUBE_CONTEXT:-nightshift-sandbox}
ADMIN=$DIR/admin.yaml
REMEDIATOR=$DIR/remediator.yaml
AUDIT_TOKEN=${AUDIT_WEBHOOK_TOKEN:-audit-token}
API_URL=${NIGHTSHIFT_API:-http://127.0.0.1:8080}
kc() { "$K3S" kubectl --kubeconfig "$ADMIN" "$@"; }
die() { echo "REFUSED: $*" >&2; exit 2; }
[ -x "$K3S" ] || die "k3s binary not found at $K3S (set K3S_BIN; download from https://github.com/k3s-io/k3s/releases)"

case "${1:-}" in
up)
  mkdir -p "$DIR" "$DATA"
  cp deploy/k3s/audit-policy.yaml "$DIR/audit-policy.yaml"
  cat >"$DIR/audit-webhook.yaml" <<YAML
apiVersion: v1
kind: Config
clusters:
  - name: nightshift
    cluster: {server: "$API_URL/k8s/audit/$AUDIT_TOKEN"}
users:
  - name: apiserver
    user: {}
contexts:
  - name: default
    context: {cluster: nightshift, user: apiserver}
current-context: default
YAML
  if ! "$K3S" kubectl --kubeconfig "$DIR/k3s.yaml" get ns >/dev/null 2>&1; then
    setsid nohup "$K3S" server --data-dir "$DATA" --write-kubeconfig "$DIR/k3s.yaml" --write-kubeconfig-mode 600 \
      --disable-agent --disable traefik --disable servicelb --disable metrics-server --disable coredns --disable local-storage --disable-cloud-controller \
      --kube-apiserver-arg=audit-policy-file="$DIR/audit-policy.yaml" --kube-apiserver-arg=audit-webhook-config-file="$DIR/audit-webhook.yaml" \
      --kube-apiserver-arg=audit-webhook-batch-max-wait=2s >"$DIR/k3s.log" 2>&1 </dev/null &
    for _ in $(seq 1 60); do "$K3S" kubectl --kubeconfig "$DIR/k3s.yaml" get ns >/dev/null 2>&1 && break; sleep 2; done
  fi
  "$K3S" kubectl --kubeconfig "$DIR/k3s.yaml" get ns >/dev/null 2>&1 || die "control plane did not become ready (see $DIR/k3s.log)"
  # a dedicated, explicitly named context: never the user's default kubeconfig
  sed "s/: default/: $CTX/g; s/name: default/name: $CTX/g" "$DIR/k3s.yaml" >"$ADMIN"
  chmod 600 "$ADMIN"
  kc create namespace demo --dry-run=client -o yaml | kc apply -f - >/dev/null
  kc create namespace beacon --dry-run=client -o yaml | kc apply -f - >/dev/null
  kc apply -f - >/dev/null <<'YAML'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: demo-db-ingress, namespace: demo}
spec:
  podSelector: {matchLabels: {app: demo-db}}
  policyTypes: [Ingress]
  ingress:
    - from: [{podSelector: {matchLabels: {app: demo-api}}}]
      ports: [{protocol: TCP, port: 6379}]
YAML
  kc apply -f deploy/k8s/beacon/rbac.yaml >/dev/null || die "could not apply RBAC"
  # the worker's identity: the real beacon-remediator ServiceAccount, with its real (restricted) RBAC
  TOKEN=$(kc -n beacon create token beacon-remediator --duration=24h) || die "could not mint the remediator token"
  SERVER=$(grep -m1 'server:' "$ADMIN" | awk '{print $2}')
  CA=$(grep -m1 'certificate-authority-data:' "$ADMIN" | awk '{print $2}')
  cat >"$REMEDIATOR" <<YAML
apiVersion: v1
kind: Config
clusters: [{name: $CTX, cluster: {server: $SERVER, certificate-authority-data: $CA}}]
users: [{name: beacon-remediator, user: {token: "$TOKEN"}}]
contexts: [{name: $CTX, context: {cluster: $CTX, user: beacon-remediator, namespace: demo}}]
current-context: $CTX
YAML
  chmod 600 "$REMEDIATOR"
  KUBECONFIG="$ADMIN" GOLDEN_TARGETS=demo/demo-db-ingress .venv/bin/python -m beacon.snapshot || die "golden snapshot failed"
  echo "sandbox ready: context=$CTX  admin=$ADMIN  remediator(SA)=$REMEDIATOR"
  echo "label: REAL_CONTROL_PLANE + EMULATED_DATAPLANE (no kubelet; NetworkPolicy enforced by beacon.sandbox.dataplane)"
  ;;
status)
  kc get ns 2>&1 | head -8
  kc -n demo get networkpolicy demo-db-ingress -o jsonpath='ingress rules: {.spec.ingress}{"\n"}' 2>&1
  ;;
break)
  kc -n demo patch networkpolicy demo-db-ingress --type=json -p='[{"op":"replace","path":"/spec/ingress","value":[]}]' ;;
restore)
  kc apply -f - <<'YAML'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: demo-db-ingress, namespace: demo}
spec:
  podSelector: {matchLabels: {app: demo-db}}
  policyTypes: [Ingress]
  ingress:
    - from: [{podSelector: {matchLabels: {app: demo-api}}}]
      ports: [{protocol: TCP, port: 6379}]
YAML
  ;;
down)
  pkill -f "$K3S server" 2>/dev/null
  sleep 3
  pkill -f k3s 2>/dev/null
  [ -n "${DIR:?}" ] && [ -n "${DATA:?}" ] && rm -rf "${DIR:?}" "${DATA:?}"
  echo "sandbox torn down"
  ;;
*) echo "usage: $0 up|status|break|restore|down" >&2; exit 2 ;;
esac

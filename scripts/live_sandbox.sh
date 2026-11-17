#!/usr/bin/env bash
# Isolated live-cluster profile. Usage: scripts/live_sandbox.sh up|verify
# Fails closed. It never uses "whatever kubectl context happens to be current":
#   SANDBOX_KUBE_CONTEXT must be set explicitly, must equal the current context, and must be a
#   local k3d/kind/minikube-style context (or be named in SANDBOX_CONTEXTS_ALLOW). Anything else is refused.
# NOT exercised in the authoring environment (no Docker daemon, kubectl or k3d); see docs/HACKATHON.md.
set -uo pipefail
cd "$(dirname "$0")/.."
die() { echo "REFUSED: $*" >&2; exit 2; }

command -v kubectl >/dev/null 2>&1 || die "kubectl is not installed (BLOCKED: live sandbox needs kubectl, k3d and a Docker daemon)"
[ -n "${SANDBOX_KUBE_CONTEXT:-}" ] || die "SANDBOX_KUBE_CONTEXT is not set; refusing to pick a cluster for you"
current=$(kubectl config current-context 2>/dev/null) || die "no current kubectl context"
[ "$current" = "$SANDBOX_KUBE_CONTEXT" ] || die "current context '$current' != SANDBOX_KUBE_CONTEXT '$SANDBOX_KUBE_CONTEXT'"
case "$current" in
  k3d-*|kind-*|minikube|docker-desktop) ;;
  *) case ",${SANDBOX_CONTEXTS_ALLOW:-}," in *",$current,"*) ;; *) die "context '$current' is not a recognised local sandbox context (set SANDBOX_CONTEXTS_ALLOW to name it explicitly)";; esac ;;
esac
case ",${PROTECTED_CONTEXTS:-prod,production}," in *",$current,"*) die "context '$current' is listed as protected" ;; esac
export SANDBOX_CONTEXTS=$current REQUIRE_SANDBOX=true BEACON_K8S_CONTEXT=$current

case "${1:-}" in
up)
  echo "sandbox context: $current"
  kubectl get ns >/dev/null || die "cannot reach the sandbox cluster"
  make up && echo "deployed to '$current'; run: DEMO_MODE=live scripts/demo.sh up"
  ;;
verify)
  kubectl -n demo get networkpolicy demo-db-ingress >/dev/null || die "demo namespace/policy missing; run 'live_sandbox.sh up'"
  BEACON_E2E=1 .venv/bin/python -m pytest tests/test_integration.py -m integration -q
  ;;
*) echo "usage: $0 up|verify" >&2; exit 2 ;;
esac

#!/usr/bin/env bash
# Break and restore the demo for real. Usage: demo/trigger.sh <command>
#   break-netpol   remove the NetworkPolicy ingress rule (Demo 1)
#   bad-deploy     roll out a version that crashes on start (Demo 2)
#   restore        put both back by hand
set -euo pipefail
NS=demo
case "${1:-}" in
  break-netpol)
    kubectl -n "$NS" patch networkpolicy demo-db-ingress --type=json \
      -p='[{"op":"replace","path":"/spec/ingress","value":[]}]' ;;
  bad-deploy)
    kubectl -n "$NS" set env deployment/demo-api FAIL_MODE=crash APP_VERSION=v2-bad ;;
  restore)
    kubectl apply -f deploy/k8s/demo/demo.yaml
    kubectl -n "$NS" set env deployment/demo-api FAIL_MODE- APP_VERSION=v1 ;;
  *) echo "usage: $0 break-netpol|bad-deploy|restore" >&2; exit 2 ;;
esac

#!/usr/bin/env bash
# Writes deploy/k3s/audit-webhook.yaml (git-ignored: it carries AUDIT_WEBHOOK_TOKEN).
# The API server posts audit events to Night Shift through its NodePort on the node itself.
set -euo pipefail
cd "$(dirname "$0")/../.."
set -a; . ./.env; set +a
cat > deploy/k3s/audit-webhook.yaml <<YAML
apiVersion: v1
kind: Config
clusters:
  - name: beacon
    cluster: {server: "http://127.0.0.1:30081/k8s/audit/${AUDIT_WEBHOOK_TOKEN:?set AUDIT_WEBHOOK_TOKEN in .env}"}
users:
  - name: apiserver
    user: {}
contexts:
  - name: default
    context: {cluster: beacon, user: apiserver}
current-context: default
YAML
echo "wrote deploy/k3s/audit-webhook.yaml"

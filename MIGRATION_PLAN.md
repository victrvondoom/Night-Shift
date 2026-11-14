# Migration plan: off AWS, AssemblyAI to Bolna

This records what the migration changed and why. The product, the console and
the safety model are the same; the infrastructure and voice provider underneath
are not.

## Audit of the original

| Area | What it was |
|---|---|
| Backend | Python Lambdas (triage, voice turn, remediate, dashboard, change ledger) behind Function URLs, SAM/CloudFormation templates |
| Storage | DynamoDB (incidents, approvals, contracts, changes), SSM parameters, S3 site |
| Detection / evidence | CloudWatch alarms and logs, CloudTrail via EventBridge |
| Workflow | Step Functions loop (dry run, approval, execute, verify, resolve/escalate) |
| Model | Bedrock (Nova) through litellm / Strands; Nova embeddings for log reduction |
| Remediation | `sg.restore_ingress`, `sg.revoke_ingress`, `ecs.force_redeploy` under an IAM remediator role |
| Voice | AssemblyAI Voice Agent WebSocket in the browser; Transcribe + Polly cascade; Twilio phone bridge; Telegram voice notes |
| Frontend | React + Vite console (Night Board, Analytics, Talk, Contracts, Audit, Safety, replay, reports) |

## Capability map

| Original | Replacement | Where |
|---|---|---|
| Lambda + Function URLs | FastAPI app + worker process | `src/beacon/server.py`, `worker.py` |
| DynamoDB | PostgreSQL JSONB | `db.py`, `store.py`, `approvals.py`, `contracts.py`, `changes.py` |
| CloudWatch alarms | Prometheus rules + Alertmanager webhook | `deploy/k8s/platform/observability.yaml`, `events.py` |
| CloudWatch Logs | Grafana Loki (Promtail) | `logs.py` |
| CloudTrail | Kubernetes audit webhook + GitHub webhooks | `changes.py`, `server.py` |
| EventBridge | NATS JetStream | `eventbus.py` |
| Step Functions | Temporal workflow | `workflows.py` |
| Bedrock | Ollama (local model, JSON mode for the structured block) | `triage.py`, `voice_loop.py`, `config.py` |
| IAM roles | Kubernetes RBAC (two service accounts) + OPA policy | `deploy/k8s/beacon/rbac.yaml`, `policy/remediation.rego`, `policy.py` |
| SSM / Secrets Manager | HashiCorp Vault (env fallback) | `secrets.py` |
| S3 / CloudFront | MinIO for audit artifacts; Caddy serves the console | `artifacts.py`, `web/Caddyfile` |
| SNS | Slack, Telegram, PagerDuty | `channels.py`, `notifier.py` |
| Security-group and ECS actions | `networkpolicy.restore_ingress` / `revoke_ingress`, `deployment.restart`, `deployment.rollback` with server-side dry run | `remediation/` |
| CloudWatch verification | Prometheus alert state + expression, Kubernetes post-condition, HTTP health check | `remediation/verify.py` |
| AssemblyAI Voice Agent | Bolna Web Call SDK + custom functions + webhooks | `bolna.py`, `voice_turn.py`, `web/src/voice/bolna.ts` |
| Amazon Connect / Twilio bridge | Bolna telephony (`POST /call`) | `caller.py` |
| Fargate demo | Demo app + NetworkPolicy on local Kubernetes | `demo/`, `deploy/k8s/demo/` |

## The one behaviour that changed: voice consent

The original checked the approval phrase against a transcript the browser
received from AssemblyAI, with word confidence. Bolna does not give that:

- The Web Call SDK (`@bolna/web-call` 3.0.1) exposes call state, agent volume,
  errors and the execution id. It has no transcript, speaker or interruption events.
- A custom function call carries only the arguments the agent's LLM wrote.
- The transcript arrives after the call, through the execution API or webhook.

So a Bolna function call cannot prove the engineer said anything. Night Shift treats
it as a request: `approve_fix`, `undo_fix`, `grant_sleep_contract` and
`open_fix_pr` arriving from Bolna are validated, recorded and **held**; the
proposal stays pending. The change runs only when the engineer types the exact
phrase in the passcode-authenticated console (or the allowlisted Telegram
chat). Webhook transcripts are stored and never authorise anything. No
confidence score is shown, because none exists.

Kept as before: the agent reads back the fix and blast radius; "yes" / "do it"
is refused; cancelling or interrupting the read-back withdraws the proposal
(the console detects the interruption from live audio levels); a cancelled
approval is invalidated immediately. Added: a proposal can be approved once.

## Removed

CloudFormation/SAM templates, the Lambda agent image, AWS/AssemblyAI/Twilio
scripts, the phone bridge package, the Transcribe/AssemblyAI browser transports,
moto-based tests, and the AssemblyAI and phone documentation.

## Not changed

Console components, styles, layout and navigation; only the voice transports,
API client, config and on-screen wording that named the old stack were edited.
The archived replay under `web/public/replay/` is a recording of an original
run and still shows that run's AWS resources.

from __future__ import annotations

import os
import uuid
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest

# Test services: a throwaway PostgreSQL and OPA (see `make test-services`).
os.environ.setdefault(
    "DATABASE_URL", "postgresql://beacon:beacon@localhost:5433/beacon"
)
os.environ.setdefault("OPA_URL", "http://localhost:8281")
os.environ["REMEDIATION_MODE"] = "inline"
os.environ["VERIFY_WAIT_SECONDS"] = "0"
os.environ["VERIFY_MAX_ATTEMPTS"] = "2"
os.environ["PASSCODE"] = "test-pass"
os.environ["BOLNA_TOOL_TOKEN"] = "tool-token"
os.environ["BOLNA_WEBHOOK_SECRET"] = "hook-secret"
os.environ["ALERT_WEBHOOK_TOKEN"] = "alert-token"
os.environ["AUDIT_WEBHOOK_TOKEN"] = "audit-token"
os.environ["GITHUB_WEBHOOK_SECRET"] = "gh-secret"
os.environ["REMEDIABLE_NAMESPACES"] = "demo"
os.environ["REMEDIABLE_DEPLOYMENTS"] = "demo/demo-api"
os.environ["LOG_SELECTORS"] = '{namespace="demo"}'
for _name in ("NATS_URL", "VAULT_ADDR", "MINIO_ENDPOINT", "SLACK_WEBHOOK_URL"):
    os.environ.pop(_name, None)

from beacon.config import NightShiftConfig  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"


def _db_up() -> bool:
    from beacon import db

    return db.ping()


@pytest.fixture()
def tables(monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """Fresh ledgers for one test in the real PostgreSQL."""
    if not _db_up():
        pytest.skip("PostgreSQL is not reachable (make test-services)")
    suffix = uuid.uuid4().hex[:10]
    names = {
        "INCIDENTS_TABLE_NAME": f"t_incidents_{suffix}",
        "APPROVALS_TABLE_NAME": f"t_approvals_{suffix}",
        "CONTRACTS_TABLE_NAME": f"t_contracts_{suffix}",
        "CHANGES_TABLE_NAME": f"t_changes_{suffix}",
    }
    for key, value in names.items():
        monkeypatch.setenv(key, value)
    return names


@pytest.fixture()
def beacon_config() -> NightShiftConfig:
    return NightShiftConfig(
        log_group_patterns=['{namespace="demo"}'],
        lookback_minutes=30,
        cordon_window_size=4,
        cordon_k_neighbors=5,
        llm_model_id="ollama_chat/test-model",
        token_budget=100_000,
        max_output_tokens=4096,
    )


RESTART = {"namespace": "demo", "name": "demo-api"}


@pytest.fixture()
def cluster(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Stand-in for the cluster in unit tests: one Deployment that can be restarted.

    The allowlist, schema validation, approvals, idempotency and consent paths
    all run for real; only the Kubernetes/OPA/Prometheus calls are replaced.
    The real ones are exercised by the integration tests.
    """
    from dataclasses import replace

    from beacon import policy, remediate
    from beacon.remediation import registry
    from beacon.remediation.base import ActionResult
    from beacon.remediation.verify import VerifyCheck, VerifyResult

    state: dict[str, Any] = {"restarts": 0, "dry_runs": 0, "verify_ok": True}

    def execute(params: dict[str, Any]) -> ActionResult:
        state["restarts"] += 1
        return ActionResult(True, "Restarted", "applied")

    def dry_run(params: dict[str, Any]) -> ActionResult:
        state["dry_runs"] += 1
        return ActionResult(True, "DryRun", "server dry-run accepted")

    spec = replace(
        registry.REGISTRY["deployment.restart"],
        precondition=lambda params: None,
        dry_run=dry_run,
        execute=execute,
        postcondition=lambda params: True,
    )
    monkeypatch.setitem(registry.REGISTRY, "deployment.restart", spec)
    monkeypatch.setattr(policy, "evaluate", lambda *a, **k: (True, []))
    monkeypatch.setattr(remediate, "_caller_arn", lambda: "sa/test")
    monkeypatch.setattr(
        remediate,
        "verify_all",
        lambda *a, **k: VerifyResult(
            ok=state["verify_ok"], checks=[VerifyCheck("stub", state["verify_ok"])]
        ),
    )
    return state


@pytest.fixture()
def incident(tables: dict[str, str]) -> dict[str, Any]:
    """A stored incident whose diagnostics named ``deployment.restart``."""
    from beacon import store
    from beacon.events import TriggerInfo, TriggerType

    incident_id = store.put_incident(
        "STATUS: High\nSUMMARY: demo-api is down.",
        TriggerInfo(TriggerType.ALARM, alarm_name="DemoApiDown"),
        table_name=tables["INCIDENTS_TABLE_NAME"],
        rca_json={
            "status": "High",
            "summary": "demo-api is down.",
            "beacon_json": {
                "suggested_action": "deployment.restart",
                "action_params": dict(RESTART),
                "action_source": "diagnostics",
            },
        },
    )
    return store.get_incident(incident_id, table_name=tables["INCIDENTS_TABLE_NAME"])


@pytest.fixture()
def client() -> Any:
    from fastapi.testclient import TestClient

    from beacon.server import app

    return TestClient(app)


PASS = {"x-beacon-passcode": "test-pass"}


@pytest.fixture()
def sample_incident() -> dict[str, Any]:
    return {
        "incident_id": "test-incident-123",
        "rca": (
            "STATUS: High\nSUMMARY: Connection pool exhaustion on auth-db.\n"
            "AFFECTED COMPONENTS: auth-service, api-gateway\n"
            "EVIDENCE:\n- Connection refused errors\n"
            "NEXT STEPS:\n1. Check RDS connections\n2. Restart auth-service\n"
            "SPOKEN SUMMARY: The auth database connection pool is exhausted."
            " Error rates spiked on the API gateway about 8 minutes ago and"
            " the auth service logs show repeated connection refused errors."
        ),
        "alarm_name": "HighErrorRate-APIGateway",
        "alarm_reason": "Threshold crossed: ErrorRate > 10%",
        "trigger_type": "alarm",
        "timestamp": "2026-02-26T12:00:00+00:00",
        "prefetch_status": "complete",
        "cached_data": {
            "metrics": [
                {
                    "query_key": "RDS DatabaseConnections for auth-db",
                    "namespace": "AWS/RDS",
                    "metric_name": "DatabaseConnections",
                    "dimensions": {"DBInstanceIdentifier": "auth-db"},
                    "stat": "Average",
                    "datapoints": [
                        {
                            "timestamp": "2026-02-26T11:50:00+00:00",
                            "value": 95,
                            "unit": "Count",
                        },
                        {
                            "timestamp": "2026-02-26T11:55:00+00:00",
                            "value": 98,
                            "unit": "Count",
                        },
                    ],
                }
            ],
            "logs": [
                {
                    "query_key": "auth-service errors",
                    "log_group": "/aws/lambda/auth-service",
                    "filter_pattern": "ERROR",
                    "event_count": 15,
                    "sample_lines": [
                        "2026-02-26T11:52:00+00:00 ERROR "
                        "Connection refused from db pool",
                        "2026-02-26T11:53:00+00:00 ERROR Connection pool exhausted",
                    ],
                }
            ],
            "status": [],
        },
    }


@pytest.fixture()
def prefetch_plan() -> dict[str, Any]:
    return {
        "metrics": [
            {
                "query_key": "RDS DatabaseConnections for auth-db",
                "namespace": "AWS/RDS",
                "metric_name": "DatabaseConnections",
                "dimensions": {"DBInstanceIdentifier": "auth-db"},
                "stat": "Average",
                "period_minutes": 60,
            }
        ],
        "log_queries": [
            {
                "query_key": "auth-service errors",
                "log_group": "/aws/lambda/auth-service",
                "filter_pattern": "ERROR",
                "lookback_minutes": 60,
            }
        ],
        "status_checks": [],
    }


@pytest.fixture()
def lex_fulfillment_event() -> dict[str, Any]:
    return {
        "sessionState": {
            "intent": {
                "name": "CheckMetrics",
                "state": "InProgress",
                "slots": {
                    "metric": {"value": {"interpretedValue": "connections"}},
                    "resource": {"value": {"interpretedValue": "auth-db"}},
                },
            },
            "sessionAttributes": {"incident_id": "test-incident-123"},
        },
        "inputTranscript": "Can you check the database connections for auth-db?",
    }


@pytest.fixture()
def connect_briefing_event() -> dict[str, Any]:
    return {
        "Details": {
            "ContactData": {
                "Attributes": {"incident_id": "test-incident-123"},
                "ContactId": "contact-abc-123",
            }
        }
    }


@pytest.fixture()
def sample_logs() -> str:
    return (FIXTURES / "sample_logs.txt").read_text()


@pytest.fixture()
def cordon_output() -> str:
    return (FIXTURES / "cordon_output.xml").read_text()


@pytest.fixture()
def nova_response() -> str:
    return 'STATUS: High\nSUMMARY: demo-api cannot reach its database.\nBEACON_JSON:\n```json\n{"suggested_action": null}\n```'


@pytest.fixture()
def mock_litellm_completion(mocker: Mock, nova_response: str) -> Mock:
    mock_resp = Mock()
    mock_resp.choices = [Mock(message=Mock(content=nova_response))]
    return mocker.patch("litellm.completion", return_value=mock_resp)


@pytest.fixture(scope="session", autouse=True)
def _close_pool() -> Any:
    yield
    from beacon import db

    db.reset()


class FakeBolna:
    """A local HTTP server speaking the Bolna endpoints Night Shift calls.

    The real API needs an account and a public callback URL, so the client is
    exercised against this instead; requests are recorded for assertions.
    """

    def __init__(self) -> None:
        import json
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        self.requests: list[dict[str, Any]] = []
        self.executions: dict[str, dict[str, Any]] = {}
        self.fail_mint: int | None = None
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def _reply(self, code: int, body: Any) -> None:
                raw = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(raw)

            def _handle(self, method: str) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length) or b"{}") if length else {}
                outer.requests.append(
                    {
                        "method": method,
                        "path": self.path,
                        "auth": self.headers.get("Authorization"),
                        "body": body,
                    }
                )
                if self.headers.get("Authorization") != "Bearer bn-test-key":
                    return self._reply(401, {"message": "Access denied"})
                if self.path == "/web-call/session" and method == "POST":
                    if outer.fail_mint:
                        return self._reply(outer.fail_mint, {"message": "at capacity"})
                    run_id = f"run-{uuid.uuid4().hex[:12]}"
                    outer.executions[run_id] = {"id": run_id, "status": "in-progress"}
                    return self._reply(
                        200,
                        {
                            "run_id": run_id,
                            "agent_id": body.get("agent_id"),
                            "sip_username": "u",
                            "sip_password": "p",
                            "sip_domain": "d",
                            "wss_url": "wss://x",
                            "sip_register": False,
                            "expires_in": 120,
                            "ice_servers": [],
                        },
                    )
                if self.path.startswith("/executions/") and method == "GET":
                    found = outer.executions.get(self.path.split("/")[2])
                    return self._reply(
                        200 if found else 404, found or {"message": "nf"}
                    )
                if self.path == "/v2/agent" and method == "POST":
                    return self._reply(
                        201, {"agent_id": "agent-new", "state": "created"}
                    )
                if self.path.startswith("/v2/agent/") and method == "GET":
                    return self._reply(
                        200,
                        {
                            "agent_name": "Night Shift on-call",
                            "webhook_url": "https://x/voice/bolna/webhook?secret=s",
                            "tools_params": {"propose_fix": {"api_token": "Bearer t"}},
                        },
                    )
                return self._reply(404, {"message": "not found"})

            def do_GET(self) -> None:  # noqa: N802
                self._handle("GET")

            def do_POST(self) -> None:  # noqa: N802
                self._handle("POST")

            def log_message(self, *args: Any) -> None:
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()


@pytest.fixture()
def bolna_api(monkeypatch: pytest.MonkeyPatch) -> Any:
    fake = FakeBolna()
    monkeypatch.setenv("BOLNA_API_BASE", fake.url)
    monkeypatch.setenv("BOLNA_API_KEY", "bn-test-key")
    monkeypatch.setenv("BOLNA_AGENT_ID", "agent-1")
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    yield fake
    fake.close()

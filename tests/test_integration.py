"""Against a live cluster (``make up``): real Kubernetes, Prometheus, Loki, OPA,
Temporal, NATS and PostgreSQL. Nothing here is stubbed.

    BEACON_E2E=1 KUBECONFIG=... pytest -m integration

Each demo breaks the cluster for real, waits for Night Shift to notice, approves the
proposed fix with the typed phrase, and requires independently verified recovery.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
import urllib.request
from pathlib import Path
from typing import Any

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("BEACON_E2E"), reason="set BEACON_E2E=1"),
]
ROOT = Path(__file__).parent.parent
BASE = os.environ.get("BEACON_URL", "http://127.0.0.1:30080")
PASSCODE = os.environ.get("BEACON_PASSCODE", "local-pass")
NETPOL = {
    "namespace": "demo",
    "name": "demo-db-ingress",
    "from_app": "demo-api",
    "port": 6379,
    "protocol": "TCP",
}
DEPLOY = {"namespace": "demo", "name": "demo-api"}


def _http(method: str, path: str, body: Any = None) -> Any:
    req = urllib.request.Request(  # noqa: S310
        BASE + path,
        data=json.dumps(body).encode() if body is not None else None,
        method=method,
        headers={"content-type": "application/json", "x-beacon-passcode": PASSCODE},
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=120) as resp:
        return json.loads(resp.read().decode())


def _kubectl(*args: str) -> str:
    return subprocess.run(
        ["kubectl", *args], check=True, capture_output=True, text=True
    ).stdout


def _wait(what: str, check: Any, timeout: int = 300) -> Any:
    deadline = time.time() + timeout
    while time.time() < deadline:
        got = check()
        if got:
            return got
        time.sleep(4)
    raise AssertionError(f"timed out waiting for {what}")


def _open_incident(alarm: str) -> dict[str, Any] | None:
    for inc in _http("GET", "/api/incidents")["incidents"]:
        if inc.get("alarm_name") == alarm and inc["status"] == "awaiting_engineer":
            return inc
    return None


def _ingress() -> list[Any]:
    return (
        json.loads(
            _kubectl("-n", "demo", "get", "netpol", "demo-db-ingress", "-o", "json")
        )["spec"].get("ingress")
        or []
    )


@pytest.fixture()
def healthy() -> Any:
    """Start from, and return to, a healthy demo with no open incident."""

    def restore() -> None:
        subprocess.run(
            [str(ROOT / "demo/trigger.sh"), "restore"],
            check=True,
            capture_output=True,
            cwd=ROOT,
        )
        _kubectl("-n", "demo", "rollout", "status", "deploy/demo-api", "--timeout=180s")

    restore()
    # let alerts clear and the dedup window for the previous run pass
    _wait(
        "no open incident",
        lambda: not (_open_incident("DemoDbErrors") or _open_incident("DemoApiDown")),
        30,
    ) if False else None
    yield
    restore()


def _approve_and_wait(incident: dict[str, Any]) -> dict[str, Any]:
    iid = incident["incident_id"]
    proposal = _http(
        "POST",
        "/voice/tools/propose_fix",
        {"incident_id": iid, "args": {}, "channel": "console"},
    )["result"]
    assert proposal["dry_run"]["ok"], proposal
    assert proposal["dry_run"]["role"].endswith("beacon-remediator")
    fix = proposal["fix_id"]
    # agreement is not consent, and the console event channel cannot approve
    held = _http(
        "POST",
        "/voice/tools/approve_fix",
        {
            "incident_id": iid,
            "channel": "bolna",
            "transcript": f"approve fix {fix}",
            "args": {"fix_id": fix, "confirmation_phrase": f"approve fix {fix}"},
        },
    )["result"]
    assert held["approved"] is False and held.get("pending_confirmation")
    reply = _http(
        "POST",
        "/voice/turn",
        {
            "incident_id": iid,
            "session_id": "e2e",
            "text": f"approve fix {fix}",
            "channel": "typed",
        },
    )
    assert "Approved" in reply["reply_text"], reply
    done = _wait(
        "resolution",
        lambda: (lambda i: i if i["status"] in ("resolved", "escalated") else None)(
            _http("GET", f"/api/incidents/{iid}")["incident"]
        ),
        600,
    )
    assert done["status"] == "resolved", [
        e for e in done["timeline"] if e["event"] == "verify_attempt"
    ][-1:]
    last = [e["detail"] for e in done["timeline"] if e["event"] == "verify_attempt"][-1]
    assert {c["name"] for c in last["checks"]} == {
        "alarm_ok_after_fix",
        "metric_zero",
        "postcondition",
        "app_health",
    }
    assert all(c["ok"] for c in last["checks"])
    assert done["execution_arn"].startswith("remediate-")  # the Temporal workflow id
    assert any(e["event"] == "certificate_issued" for e in done["timeline"])
    assert (
        "## "
        in urllib.request.build_opener(urllib.request.ProxyHandler({}))
        .open(f"{BASE}/api/incidents/{iid}/postmortem")
        .read()
        .decode()
    )
    audit = [
        r for r in _http("GET", "/api/audit")["rows"] if r.get("incident_id") == iid
    ]
    assert audit and audit[0].get("attestation", {}).get("evidence") == "typed_console"
    return done


def test_demo_1_network_policy_failure(healthy: None) -> None:
    _kubectl(
        "-n",
        "beacon",
        "exec",
        "deploy/beacon-worker",
        "--",
        "python",
        "-m",
        "beacon.snapshot",
    )
    time.sleep(660 if os.environ.get("BEACON_E2E_WAIT_DEDUP") else 0)
    subprocess.run(
        [str(ROOT / "demo/trigger.sh"), "break-netpol"],
        check=True,
        capture_output=True,
        cwd=ROOT,
    )
    assert _ingress() == []
    incident = _wait(
        "the DemoDbErrors incident", lambda: _open_incident("DemoDbErrors")
    )
    action = incident["rca_json"]["beacon_json"]
    assert action["suggested_action"] == "networkpolicy.restore_ingress"
    assert (
        action["action_params"] == NETPOL and action["action_source"] == "diagnostics"
    )
    change = incident["changes"][0]
    assert change["event_name"] == "patch networkpolicies" and change[
        "resource_ids"
    ] == ["demo/demo-db-ingress"]
    assert "logs_fetched" in [e["event"] for e in incident["timeline"]]
    _approve_and_wait(incident)
    assert len(_ingress()) == 1


def test_demo_2_failed_deployment(healthy: None) -> None:
    subprocess.run(
        [str(ROOT / "demo/trigger.sh"), "bad-deploy"],
        check=True,
        capture_output=True,
        cwd=ROOT,
    )
    incident = _wait("the DemoApiDown incident", lambda: _open_incident("DemoApiDown"))
    action = incident["rca_json"]["beacon_json"]
    assert (
        action["suggested_action"] == "deployment.rollback"
        and action["action_params"] == DEPLOY
    )
    assert any(c["event_name"] == "patch deployments" for c in incident["changes"])
    _approve_and_wait(incident)
    env = json.loads(_kubectl("-n", "demo", "get", "deploy", "demo-api", "-o", "json"))[
        "spec"
    ]["template"]["spec"]["containers"][0].get("env")
    assert {"name": "FAIL_MODE", "value": "crash"} not in (env or [])


# -- the actions themselves, straight against the API server ---------------------


def test_dry_run_changes_nothing_and_restore_then_revoke_round_trips(
    healthy: None,
) -> None:
    from beacon.remediation import actions_netpol

    actions_netpol.save_snapshot(actions_netpol.snapshot(["demo/demo-db-ingress"]))
    assert actions_netpol.postcondition(NETPOL)
    out = actions_netpol.revoke_dry_run(NETPOL)
    assert (
        out.ok and out.code == "DryRun" and actions_netpol.postcondition(NETPOL)
    )  # still there
    assert actions_netpol.revoke_execute(NETPOL).code == "Revoked"
    assert not actions_netpol.postcondition(NETPOL)
    dry = actions_netpol.dry_run(NETPOL)
    assert (
        dry.ok and "0 -> 1" in dry.detail and not actions_netpol.postcondition(NETPOL)
    )
    assert actions_netpol.execute(NETPOL).code == "Restored"
    assert actions_netpol.execute(NETPOL).code == "AlreadyPresent"  # idempotent


def test_dryrun_rejects_rule_outside_golden_snapshot(healthy: None) -> None:
    from beacon.remediation import actions_netpol

    actions_netpol.save_snapshot(actions_netpol.snapshot(["demo/demo-db-ingress"]))
    assert actions_netpol.precondition(NETPOL) is None
    assert "not in the golden snapshot" in actions_netpol.precondition(
        {**NETPOL, "port": 22}
    )
    assert "not in the golden snapshot" in actions_netpol.precondition(
        {**NETPOL, "from_app": "attacker"}
    )


def test_deployment_actions_dry_run_without_rolling(
    healthy: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    from beacon.remediation import actions_deploy

    monkeypatch.setenv("REMEDIABLE_DEPLOYMENTS", "demo/demo-api")
    before = actions_deploy.read(DEPLOY)["metadata"]["generation"]
    assert actions_deploy.dry_run(DEPLOY).ok
    assert actions_deploy.read(DEPLOY)["metadata"]["generation"] == before
    assert (
        actions_deploy.precondition({"namespace": "demo", "name": "demo-db"})
        is not None
    )
    assert actions_deploy.rollout_healthy(actions_deploy.read(DEPLOY))


def test_api_identity_cannot_write_and_worker_cannot_leave_its_lane() -> None:
    def can(sa: str, verb: str, resource: str, ns: str = "demo") -> bool:
        out = subprocess.run(
            [
                "kubectl",
                "auth",
                "can-i",
                verb,
                resource,
                "-n",
                ns,
                f"--as=system:serviceaccount:beacon:{sa}",
            ],
            capture_output=True,
            text=True,
        )
        return out.stdout.strip() == "yes"

    assert not can("beacon-api", "patch", "networkpolicies")
    assert not can("beacon-api", "patch", "deployments")
    assert can("beacon-remediator", "patch", "networkpolicies")
    assert can("beacon-remediator", "patch", "deployments")
    assert not can("beacon-remediator", "delete", "deployments")
    assert not can("beacon-remediator", "get", "secrets")
    assert not can("beacon-remediator", "patch", "deployments", "kube-system")
    assert not can("beacon-remediator", "create", "pods")

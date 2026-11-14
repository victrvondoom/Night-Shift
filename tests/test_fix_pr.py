"""Fix at source: the pull request is computed by code from the dry-run params."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from beacon import fix_pr

PARAMS = {
    "namespace": "demo",
    "name": "demo-db-ingress",
    "from_app": "demo-api",
    "port": 6379,
    "protocol": "TCP",
}
MANIFEST = (Path(__file__).parent.parent / "deploy/k8s/demo/demo.yaml").read_text()


def _without_rule(text: str) -> str:
    docs = list(yaml.safe_load_all(text))
    for doc in docs:
        if doc and doc["kind"] == "NetworkPolicy":
            doc["spec"]["ingress"] = []
    return yaml.safe_dump_all(docs, sort_keys=False)


@pytest.fixture(autouse=True)
def _no_cluster(monkeypatch: pytest.MonkeyPatch) -> None:
    from beacon.remediation import actions_netpol

    monkeypatch.setattr(actions_netpol, "load_golden_snapshot", lambda: None)


def test_manifest_declares_rule() -> None:
    assert fix_pr.manifest_declares_rule(MANIFEST, PARAMS) is True
    assert fix_pr.manifest_declares_rule(_without_rule(MANIFEST), PARAMS) is False
    assert fix_pr.manifest_declares_rule(MANIFEST, {**PARAMS, "name": "other"}) is None


def test_drift_from_git_gets_a_postmortem_only_pr() -> None:
    plan = fix_pr.plan_patch(
        action="networkpolicy.restore_ingress",
        params=PARAMS,
        incident_id="i1",
        template_text=MANIFEST,
    )
    assert plan["kind"] == "postmortem_only" and "out of band" in plan["reason"]


def test_missing_rule_is_added_to_that_policy_only() -> None:
    broken = _without_rule(MANIFEST)
    plan = fix_pr.plan_patch(
        action="networkpolicy.restore_ingress",
        params=PARAMS,
        incident_id="i1",
        template_text=broken,
    )
    assert plan["kind"] == "template_patch"
    assert fix_pr.manifest_declares_rule(plan["patched"], PARAMS) is True
    before = [d["kind"] for d in yaml.safe_load_all(broken) if d]
    after = [d["kind"] for d in yaml.safe_load_all(plan["patched"]) if d]
    assert before == after  # nothing else added or dropped


def test_deployment_actions_have_no_code_change() -> None:
    plan = fix_pr.plan_patch(
        action="deployment.rollback",
        params={"namespace": "demo", "name": "demo-api"},
        incident_id="i1",
        template_text=MANIFEST,
    )
    assert plan["kind"] == "postmortem_only"


def test_said_phrase() -> None:
    assert fix_pr.said_phrase("Open the pull request, please.")
    assert not fix_pr.said_phrase("yes do it")


def test_open_pr_refuses_when_unconfigured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FIX_PR_REPO", raising=False)
    with pytest.raises(RuntimeError, match="not configured"):
        fix_pr.open_pr(
            {}, action="x", params={}, postmortem_md="", approval=None, link=""
        )

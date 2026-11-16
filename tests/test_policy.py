"""Rego policy evaluated by a real OPA server (make test-services)."""

import urllib.request

import pytest

from beacon import policy

RESTART = {"namespace": "demo", "name": "demo-api"}
APPROVAL = {
    "kind": "approval",
    "source": "voice",
    "channel": "typed",
    "used_at": None,
    "attestation": {"evidence": "typed_console"},
}


@pytest.fixture(autouse=True)
def _opa(monkeypatch):
    monkeypatch.setenv("OPA_URL", "http://localhost:8281")
    monkeypatch.setenv("NO_PROXY", "localhost,127.0.0.1")
    try:
        urllib.request.urlopen("http://localhost:8281/health", timeout=2)  # noqa: S310
    except Exception:
        pytest.skip("OPA is not reachable (make test-services)")


def test_allowlisted_action_in_allowed_namespace_passes_dry_run():
    assert policy.evaluate("dryrun", "deployment.restart", RESTART) == (True, [])


def test_action_outside_the_allowlist_is_denied():
    ok, why = policy.evaluate("dryrun", "pod.exec", RESTART)
    assert not ok and "not allowlisted" in why[0]


def test_protected_namespace_is_denied(monkeypatch):
    monkeypatch.setenv("REMEDIABLE_NAMESPACES", "demo,kube-system")
    ok, why = policy.evaluate(
        "dryrun", "deployment.restart", {"namespace": "kube-system", "name": "coredns"}
    )
    assert not ok and any("protected" in w for w in why)


def test_namespace_must_be_configured_as_remediable():
    ok, why = policy.evaluate(
        "dryrun", "deployment.restart", {"namespace": "prod", "name": "api"}
    )
    assert not ok and any("REMEDIABLE_NAMESPACES" in w for w in why)


def test_execute_needs_a_verified_unused_approval():
    assert policy.evaluate("execute", "deployment.restart", RESTART, approval=APPROVAL)[
        0
    ]
    assert not policy.evaluate("execute", "deployment.restart", RESTART)[0]
    used = {**APPROVAL, "used_at": "2026-11-14T03:00:00+00:00"}
    assert not policy.evaluate("execute", "deployment.restart", RESTART, approval=used)[
        0
    ]


def test_an_omnidim_function_call_is_not_verified_consent():
    voice = {**APPROVAL, "attestation": {"evidence": "omnidim_llm_function_call"}}
    ok, why = policy.evaluate("execute", "deployment.restart", RESTART, approval=voice)
    assert not ok and any("not verified human consent" in w for w in why)


def test_contract_approvals_are_accepted():
    contract = {
        **APPROVAL,
        "source": "contract",
        "attestation": {"evidence": "contract"},
    }
    assert policy.evaluate("execute", "deployment.restart", RESTART, approval=contract)[
        0
    ]


def test_no_policy_engine_means_no_change(monkeypatch):
    monkeypatch.setenv("OPA_URL", "http://127.0.0.1:1")
    ok, why = policy.evaluate("dryrun", "deployment.restart", RESTART)
    assert not ok and "unreachable" in why[0]
    monkeypatch.delenv("OPA_URL")
    assert policy.evaluate("dryrun", "deployment.restart", RESTART)[0] is False

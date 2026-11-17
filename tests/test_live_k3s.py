"""LIVE-CLUSTER tests against the REAL k3s control plane started by `scripts/k3s_sandbox.sh up`.

Real: kube-apiserver, etcd, RBAC, server-side dry-run, optimistic concurrency, the golden-snapshot ConfigMap.
Not real: there is no kubelet/CNI (pods cannot start in this VM); the data plane is emulated (see the script header).
These tests SKIP, loudly, when the sandbox is not running.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from kubernetes import client, config
from kubernetes.client.exceptions import ApiException

from beacon import k8s
from beacon.remediation import actions_netpol, guard

SBX = Path(os.environ.get("SANDBOX_DIR", "/var/tmp/nightshift-sandbox"))
ADMIN, REM = SBX / "admin.yaml", SBX / "remediator.yaml"
PARAMS = {"namespace": "demo", "name": "demo-db-ingress", "from_app": "demo-api", "port": 6379, "protocol": "TCP"}


def _up() -> bool:
    if not (ADMIN.exists() and REM.exists()):
        return False
    try:
        client.CoreV1Api(config.new_client_from_config(str(ADMIN))).list_namespace(_request_timeout=3)
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _up(), reason="BLOCKED: no k3s sandbox running (scripts/k3s_sandbox.sh up)")


def api(kubeconfig: Path) -> client.ApiClient:
    return config.new_client_from_config(str(kubeconfig))


def can_i(verb: str, resource: str, ns: str, group: str = "") -> bool:
    review = client.V1SelfSubjectAccessReview(spec=client.V1SelfSubjectAccessReviewSpec(resource_attributes=client.V1ResourceAttributes(verb=verb, resource=resource, namespace=ns, group=group)))
    return bool(client.AuthorizationV1Api(api(REM)).create_self_subject_access_review(review).status.allowed)


@pytest.mark.parametrize("verb,resource,group,ns,allowed", [
    ("get", "networkpolicies", "networking.k8s.io", "demo", True),
    ("patch", "networkpolicies", "networking.k8s.io", "demo", True),
    ("delete", "networkpolicies", "networking.k8s.io", "demo", False),
    ("create", "networkpolicies", "networking.k8s.io", "demo", False),
    ("patch", "networkpolicies", "networking.k8s.io", "kube-system", False),
    ("get", "secrets", "", "demo", False),
    ("create", "pods", "", "demo", False),
    ("delete", "deployments", "apps", "demo", False),
])
def test_remediator_has_exactly_the_minimum_permissions(verb, resource, group, ns, allowed):
    assert can_i(verb, resource, ns, group) is allowed


def test_real_api_server_refuses_the_remediator_outside_its_role():
    net = client.NetworkingV1Api(api(REM))
    with pytest.raises(ApiException) as e:
        net.list_namespaced_network_policy("kube-system")
    assert e.value.status == 403  # a real Forbidden from the real API server
    with pytest.raises(ApiException) as e2:
        client.CoreV1Api(api(REM)).list_namespaced_secret("demo")
    assert e2.value.status == 403


def test_admin_credentials_are_not_in_the_worker_kubeconfig():
    rem = REM.read_text()
    assert "client-key-data" not in rem and "client-certificate-data" not in rem and "token:" in rem


def test_real_server_side_dry_run_as_the_remediator(monkeypatch):
    monkeypatch.setattr(k8s, "api", lambda: api(REM))
    k8s.api.cache_clear = lambda: None  # type: ignore[attr-defined]
    res = actions_netpol.dry_run(PARAMS)
    assert res.ok and res.code in ("DryRun", "AlreadyPresent")


def test_optimistic_concurrency_conflict_is_real():
    net_admin = client.NetworkingV1Api(api(ADMIN))
    pol = net_admin.read_namespaced_network_policy("demo-db-ingress", "demo")
    stale_rv = pol.metadata.resource_version
    net_admin.patch_namespaced_network_policy("demo-db-ingress", "demo", {"metadata": {"annotations": {"touch": os.urandom(4).hex()}}})
    patch = [{"op": "test", "path": "/metadata/resourceVersion", "value": stale_rv}, {"op": "add", "path": "/spec/ingress", "value": []}]
    with pytest.raises(ApiException) as e:
        client.NetworkingV1Api(api(REM)).patch_namespaced_network_policy("demo-db-ingress", "demo", patch)
    assert e.value.status in (409, 422)  # a stale resourceVersion is refused; nothing was changed
    assert client.NetworkingV1Api(api(ADMIN)).read_namespaced_network_policy("demo-db-ingress", "demo").spec.ingress


def test_invalid_golden_snapshot_refuses_the_restore(monkeypatch):
    core = client.CoreV1Api(api(ADMIN))
    cm = core.read_namespaced_config_map("beacon-golden-netpol", "beacon")
    original = cm.data["snapshot.json"]
    monkeypatch.setattr(k8s, "api", lambda: api(REM))
    try:
        for bad in ("{not json", json.dumps({"demo/demo-db-ingress": [{"from": [{"podSelector": {"matchLabels": {"app": "attacker"}}}], "ports": [{"protocol": "TCP", "port": 22}]}]})):
            core.patch_namespaced_config_map("beacon-golden-netpol", "beacon", {"data": {"snapshot.json": bad}})
            err = actions_netpol.precondition(PARAMS)
            assert err and ("snapshot" in err)  # an unusable or non-matching snapshot blocks the action; nothing is restored from it
    finally:
        core.patch_namespaced_config_map("beacon-golden-netpol", "beacon", {"data": {"snapshot.json": original}})
    assert actions_netpol.precondition(PARAMS) is None


def test_wrong_context_and_wrong_namespace_are_refused_before_any_api_call(monkeypatch):
    monkeypatch.setenv("SANDBOX_CONTEXTS", "nightshift-sandbox")
    monkeypatch.setenv("BEACON_K8S_CONTEXT", "some-production-context")
    monkeypatch.delenv("SIMULATOR_URL", raising=False)
    assert "not in SANDBOX_CONTEXTS" in (guard.sandbox_error(PARAMS) or "")
    monkeypatch.setenv("BEACON_K8S_CONTEXT", "nightshift-sandbox")
    monkeypatch.setenv("REMEDIABLE_NAMESPACES", "demo")
    assert guard.sandbox_error(PARAMS) is None
    assert "outside the sandbox" in (guard.sandbox_error({**PARAMS, "namespace": "kube-system"}) or "")

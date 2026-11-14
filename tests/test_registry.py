import pytest

from beacon.remediation.registry import (
    REGISTRY,
    ParamError,
    confirmation_phrase,
    rbac_rules,
    undo_phrase,
    validate_params,
)

NETPOL = {
    "namespace": "demo",
    "name": "demo-db-ingress",
    "from_app": "demo-api",
    "port": 6379,
    "protocol": "TCP",
}


def test_registry_has_exactly_the_allowlisted_actions():
    assert set(REGISTRY) == {
        "networkpolicy.restore_ingress",
        "networkpolicy.revoke_ingress",
        "deployment.restart",
        "deployment.rollback",
    }


def test_no_aws_action_survives():
    assert not [a for a in REGISTRY if a.startswith(("sg.", "ecs."))]


def test_restore_has_an_inverse_that_is_itself_allowlisted():
    spec = REGISTRY["networkpolicy.restore_ingress"]
    assert spec.inverse in REGISTRY


def test_unknown_action_is_rejected():
    with pytest.raises(ParamError, match="not allowlisted"):
        validate_params("pod.exec", {"cmd": "rm -rf /"})


@pytest.mark.parametrize(
    "params",
    [
        {**NETPOL, "extra": "x"},
        {k: v for k, v in NETPOL.items() if k != "port"},
        {**NETPOL, "port": "6379"},
        {**NETPOL, "port": True},
    ],
)
def test_params_must_match_the_schema_exactly(params):
    with pytest.raises(ParamError):
        validate_params("networkpolicy.restore_ingress", params)


def test_valid_params_pass():
    assert validate_params("networkpolicy.restore_ingress", NETPOL) == NETPOL


def test_rbac_needs_only_patch_on_two_resource_kinds():
    rules = rbac_rules()
    assert all("delete" not in r and "create" not in r for r in rules)
    assert {r.split(":")[0] for r in rules} == {
        "networking.k8s.io/networkpolicies",
        "apps/deployments",
        "apps/replicasets",
    }


def test_phrases():
    assert confirmation_phrase(2) == "approve fix 2"
    assert undo_phrase(1) == "undo fix 1"

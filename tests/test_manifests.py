"""The deployment manifests are part of the safety model, so they are tested."""

from pathlib import Path

import yaml

ROOT = Path(__file__).parent.parent
WRITE = {"create", "update", "patch", "delete", "deletecollection", "*"}


def _docs(path):
    return [d for d in yaml.safe_load_all((ROOT / path).read_text()) if d]


def _rules(role_name):
    for doc in _docs("deploy/k8s/beacon/rbac.yaml"):
        if (
            doc["kind"] in ("Role", "ClusterRole")
            and doc["metadata"]["name"] == role_name
        ):
            return doc["rules"], doc["metadata"].get("namespace")
    raise AssertionError(role_name)


def _bound_roles(sa):
    return [
        d["roleRef"]["name"]
        for d in _docs("deploy/k8s/beacon/rbac.yaml")
        if d["kind"].endswith("Binding") and any(s["name"] == sa for s in d["subjects"])
    ]


def test_api_service_account_has_no_write_verbs():
    for role in _bound_roles("beacon-api"):
        rules, _ = _rules(role)
        assert not WRITE & {v for r in rules for v in r["verbs"]}


def test_remediator_can_only_patch_netpols_and_deployments_in_demo():
    rules, namespace = _rules("beacon-remediator")
    assert namespace == "demo"
    writable = {res for r in rules if WRITE & set(r["verbs"]) for res in r["resources"]}
    assert writable == {"deployments", "networkpolicies"}
    assert all(WRITE & set(r["verbs"]) <= {"patch"} for r in rules)


def test_no_cluster_wide_write_role_and_no_secrets_access():
    for doc in _docs("deploy/k8s/beacon/rbac.yaml"):
        assert doc["kind"] not in ("ClusterRole", "ClusterRoleBinding")
        for rule in doc.get("rules", []):
            assert "secrets" not in rule["resources"] and "*" not in rule["resources"]


def test_worker_runs_as_the_remediator_and_api_does_not():
    by_name = {
        d["metadata"]["name"]: d
        for d in _docs("deploy/k8s/beacon/beacon.yaml")
        if d["kind"] == "Deployment"
    }
    assert (
        by_name["beacon-worker"]["spec"]["template"]["spec"]["serviceAccountName"]
        == "beacon-remediator"
    )
    assert (
        by_name["beacon-api"]["spec"]["template"]["spec"]["serviceAccountName"]
        == "beacon-api"
    )


def test_no_aws_or_assemblyai_anywhere_in_the_deployment():
    text = "".join(p.read_text() for p in (ROOT / "deploy").rglob("*.yaml")).lower()
    for word in (
        "amazonaws",
        "assemblyai",
        "aws_access",
        "polly",
        "bedrock",
        "dynamodb",
    ):
        assert word not in text


def test_demo_policy_is_the_rule_the_golden_snapshot_guards():
    (policy,) = [
        d for d in _docs("deploy/k8s/demo/demo.yaml") if d["kind"] == "NetworkPolicy"
    ]
    rule = policy["spec"]["ingress"][0]
    assert rule["from"][0]["podSelector"]["matchLabels"] == {"app": "demo-api"}
    assert rule["ports"] == [{"protocol": "TCP", "port": 6379}]


def test_alert_rules_carry_a_health_url_for_verification():
    (cm,) = [
        d
        for d in _docs("deploy/k8s/platform/observability.yaml")
        if d["kind"] == "ConfigMap" and d["metadata"]["name"] == "prometheus"
    ]
    rules = yaml.safe_load(cm["data"]["rules.yml"])["groups"][0]["rules"]
    assert {r["alert"] for r in rules} == {"DemoDbErrors", "DemoApiDown"}
    assert all(
        r["annotations"]["beacon_health_url"].startswith("http://demo-api.demo.svc")
        for r in rules
    )


def test_python_package_has_no_aws_or_assemblyai_dependency():
    text = (ROOT / "pyproject.toml").read_text().lower()
    for word in ("boto", "moto", "aws", "assemblyai", "strands"):
        assert word not in text
    web = (ROOT / "web/package.json").read_text().lower()
    assert "aws" not in web and "assemblyai" not in web and "@bolna/web-call" in web

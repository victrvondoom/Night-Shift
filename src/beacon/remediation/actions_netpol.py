"""``networkpolicy.restore_ingress``: put back one NetworkPolicy ingress rule.

The inverse of ``demo/trigger.sh break-netpol``. Every call is scoped to one
rule on one NetworkPolicy, and the rule must exist in the golden snapshot taken
on a healthy cluster (``make snapshot``), so the action can only restore what an
operator already blessed. The rule that gets written is the snapshot's own
object, never anything a model produced.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

from beacon import k8s
from beacon.remediation.base import ActionResult

logger = logging.getLogger(__name__)

SNAPSHOT_KEY = "snapshot.json"


def _configmap() -> str:
    return os.environ.get("GOLDEN_NETPOL_CONFIGMAP", "beacon-golden-netpol")


def target(params: dict[str, Any]) -> str:
    return f"{params['namespace']}/{params['name']}"


def _matches(rule: dict[str, Any], params: dict[str, Any]) -> bool:
    """True when *rule* admits ``app=<from_app>`` pods on ``protocol/port``."""
    port_ok = any(
        p.get("port") == params["port"]
        and str(p.get("protocol") or "TCP").upper() == str(params["protocol"]).upper()
        for p in rule.get("ports") or []
    )
    peer_ok = any(
        ((peer.get("podSelector") or {}).get("matchLabels") or {}).get("app")
        == params["from_app"]
        for peer in rule.get("from") or []
    )
    return port_ok and peer_ok


def _read(params: dict[str, Any]) -> dict[str, Any]:
    return k8s.raw(
        k8s.net().read_namespaced_network_policy(
            params["name"], params["namespace"], _preload_content=False
        )
    )


def _ingress(policy: dict[str, Any]) -> list[dict[str, Any]]:
    return list((policy.get("spec") or {}).get("ingress") or [])


def blast_radius(params: dict[str, Any]) -> str:
    return (
        f"1 ingress rule on 1 NetworkPolicy: allow {params['protocol']}/"
        f"{params['port']} from pods labelled app={params['from_app']} into "
        f"{target(params)}. Nothing else changes."
    )


def revoke_blast_radius(params: dict[str, Any]) -> str:
    return (
        f"1 ingress rule removed from 1 NetworkPolicy: {params['protocol']}/"
        f"{params['port']} from app={params['from_app']} on {target(params)}. "
        "The fault it fixed will return."
    )


def load_golden_snapshot() -> dict[str, Any] | None:
    """``{"ns/name": [ingress rules]}`` from the golden ConfigMap; None if absent."""
    try:
        cm = k8s.raw(
            k8s.core().read_namespaced_config_map(
                _configmap(), k8s.beacon_namespace(), _preload_content=False
            )
        )
        parsed = json.loads((cm.get("data") or {}).get(SNAPSHOT_KEY) or "")
    except Exception as exc:
        logger.warning("golden snapshot %s unavailable: %s", _configmap(), exc)
        return None
    return parsed if isinstance(parsed, dict) else None


def golden_rule(
    params: dict[str, Any], snapshot_data: dict[str, Any]
) -> dict[str, Any] | None:
    for rule in snapshot_data.get(target(params)) or []:
        if _matches(rule, params):
            return dict(rule)
    return None


def in_golden_snapshot(params: dict[str, Any], snapshot_data: dict[str, Any]) -> bool:
    return golden_rule(params, snapshot_data) is not None


def snapshot(targets: list[str]) -> dict[str, Any]:
    """Capture the current ingress rules of *targets* (the golden snapshot)."""
    out: dict[str, Any] = {}
    for t in targets:
        ns, name = k8s.split(t)
        out[t] = _ingress(_read({"namespace": ns, "name": name}))
    return out


def save_snapshot(data: dict[str, Any]) -> None:
    body = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": _configmap(), "namespace": k8s.beacon_namespace()},
        "data": {SNAPSHOT_KEY: json.dumps(data, sort_keys=True)},
    }
    try:
        k8s.core().replace_namespaced_config_map(
            _configmap(), k8s.beacon_namespace(), body
        )
    except k8s.ApiException as exc:
        if exc.status != 404:
            raise
        k8s.core().create_namespaced_config_map(k8s.beacon_namespace(), body)


def precondition(params: dict[str, Any]) -> str | None:
    """Return an error message when the rule may not be restored, else None."""
    snapshot_data = load_golden_snapshot()
    if snapshot_data is None:
        return "golden snapshot unavailable (run make snapshot on a healthy cluster)"
    if not in_golden_snapshot(params, snapshot_data):
        return "rule is not in the golden snapshot for this NetworkPolicy"
    return None


def _apply(params: dict[str, Any], *, remove: bool, dry_run: bool) -> ActionResult:
    """One optimistic-concurrency JSON patch of ``spec.ingress`` (or its dry run)."""
    try:
        policy = _read(params)
        current = _ingress(policy)
        present = any(_matches(r, params) for r in current)
        if remove:
            if not present:
                return ActionResult(True, "NotFound", "rule was already absent")
            wanted = [r for r in current if not _matches(r, params)]
        else:
            if present:
                return ActionResult(True, "AlreadyPresent", "rule was already present")
            rule = golden_rule(params, load_golden_snapshot() or {})
            if rule is None:
                return ActionResult(False, "NotInSnapshot", "rule not in snapshot")
            wanted = [*current, rule]
        patch = [
            {
                "op": "test",
                "path": "/metadata/resourceVersion",
                "value": policy["metadata"]["resourceVersion"],
            },
            {"op": "add", "path": "/spec/ingress", "value": wanted},
        ]
        result = k8s.raw(
            k8s.net().patch_namespaced_network_policy(
                params["name"],
                params["namespace"],
                patch,
                _preload_content=False,
                **({"dry_run": "All"} if dry_run else {}),
            )
        )
    except k8s.ApiException as exc:
        code, message = k8s.error_code(exc)
        logger.warning("networkpolicy patch failed: %s %s", code, message)
        return ActionResult(False, code, message)
    after = _ingress(result)
    holds = any(_matches(r, params) for r in after) != remove
    verb = "DryRun" if dry_run else ("Revoked" if remove else "Restored")
    detail = (
        f"{'server dry-run accepted' if dry_run else 'applied'}: ingress rules "
        f"{len(current)} -> {len(after)} on {target(params)}"
    )
    if not holds:
        return ActionResult(False, "UnexpectedResult", detail)
    return ActionResult(True, verb, detail)


def dry_run(params: dict[str, Any]) -> ActionResult:
    """Ask the API server to admit the patch without persisting it (dryRun=All)."""
    return _apply(params, remove=False, dry_run=True)


def execute(params: dict[str, Any]) -> ActionResult:
    return _apply(params, remove=False, dry_run=False)


def revoke_dry_run(params: dict[str, Any]) -> ActionResult:
    return _apply(params, remove=True, dry_run=True)


def revoke_execute(params: dict[str, Any]) -> ActionResult:
    return _apply(params, remove=True, dry_run=False)


def postcondition(params: dict[str, Any]) -> bool:
    """True when the rule is present on the NetworkPolicy right now."""
    return any(_matches(r, params) for r in _ingress(_read(params)))


def revoke_postcondition(params: dict[str, Any]) -> bool:
    return not postcondition(params)

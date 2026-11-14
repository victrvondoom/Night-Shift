"""Deterministic diagnostics that run before the model sees anything.

Two checks against the live cluster, both producing exact resource ids:

* **NetworkPolicy drift** -- ingress rules present in the golden snapshot but
  missing from the live policy;
* **Deployment health** -- allowlisted Deployments whose rollout is stuck,
  failed or short of replicas.

What they find outranks anything the model infers from logs.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from beacon.remediation import actions_deploy, actions_netpol


@dataclass(frozen=True, slots=True)
class MissingRule:
    namespace: str
    name: str
    from_app: str | None
    port: int | None
    protocol: str = "TCP"

    def describe(self) -> str:
        return (
            f"{self.protocol} {self.port} from app={self.from_app or '?'} "
            f"into {self.namespace}/{self.name}"
        )


def _rule_params(target: str, rule: dict[str, Any]) -> list[dict[str, Any]]:
    """Every (from_app, port) pair a golden rule admits, as action params."""
    ns, _, name = target.partition("/")
    out = []
    for peer in rule.get("from") or []:
        app = ((peer.get("podSelector") or {}).get("matchLabels") or {}).get("app")
        for port in rule.get("ports") or []:
            out.append(
                {
                    "namespace": ns,
                    "name": name,
                    "from_app": app,
                    "port": port.get("port"),
                    "protocol": str(port.get("protocol") or "TCP"),
                }
            )
    return out


def netpol_drift(golden: dict[str, Any]) -> list[MissingRule]:
    """Golden ingress rules that are missing from the live NetworkPolicies."""
    missing: list[MissingRule] = []
    live = actions_netpol.snapshot(list(golden)) if golden else {}
    for target, rules in golden.items():
        current = live.get(target) or []
        for rule in rules:
            for params in _rule_params(target, rule):
                usable = params["from_app"] and isinstance(params["port"], int)
                present = usable and any(
                    actions_netpol._matches(r, params) for r in current
                )
                if not present:
                    missing.append(MissingRule(**params))
    return missing


def format_diagnostics(missing: list[MissingRule], golden: dict[str, Any]) -> str:
    total = sum(len(rules) for rules in golden.values())
    plural = "rule" if total == 1 else "rules"
    if not missing:
        return (
            "NetworkPolicy check: No NetworkPolicy drift. "
            f"All {total} golden {plural} present on {len(golden)} policy(ies)."
        )
    lines = [
        f"NetworkPolicy drift vs golden snapshot: {len(missing)} "
        f"ingress rule(s) MISSING."
    ]
    for rule in missing:
        lines.append(f"- MISSING ingress rule: {rule.describe()}")
    return "\n".join(lines)


def suggested_fix(missing: list[MissingRule]) -> tuple[str, dict[str, Any]] | None:
    """The first restorable missing rule as an allowlisted action + params."""
    for rule in missing:
        if rule.from_app and rule.port is not None:
            return ("networkpolicy.restore_ingress", asdict(rule))
    return None


def deployment_health() -> list[dict[str, Any]]:
    """Status of the Deployments Night Shift may act on (``REMEDIABLE_DEPLOYMENTS``)."""
    out = []
    for target in actions_deploy.configured():
        ns, _, name = target.partition("/")
        params = {"namespace": ns, "name": name}
        out.append({**actions_deploy.describe(params), "action_params": params})
    return out


def unhealthy_deployments(
    services: list[dict[str, Any]],
) -> list[tuple[dict[str, Any], str, str]]:
    """``(deployment, reason, action)`` for each one a restart or rollback may fix.

    A rollout that failed or is short of replicas on a *new* revision is rolled
    back (the previous revision worked); one short of replicas on its only
    revision is restarted.
    """
    out = []
    for svc in services:
        if svc.get("status") != "ACTIVE" or svc.get("healthy"):
            continue
        running, desired = svc.get("running", 0), svc.get("desired", 0)
        if svc.get("progress_deadline_exceeded"):
            why = "the newest rollout exceeded its progress deadline"
        elif running < desired:
            why = f"{running} of {desired} replicas available"
        else:
            why = "the rollout has not completed"
        action = (
            "deployment.rollback"
            if int(svc.get("revision") or 0) > 1
            else "deployment.restart"
        )
        out.append((svc, why, action))
    return out


def format_deployments(services: list[dict[str, Any]]) -> str:
    if not services:
        return ""
    lines = ["Remediable Deployments (deployment.restart / deployment.rollback):"]
    for s in services:
        lines.append(
            f"- {s['namespace']}/{s['name']}: {s.get('status')} available "
            f"{s.get('running')}/{s.get('desired')} desired, revision "
            f"{s.get('revision')}, images {', '.join(str(i) for i in s.get('images') or [])}"
        )
    return "\n".join(lines)


def run(golden: dict[str, Any]) -> dict[str, Any]:
    """Everything the handler needs: text for the prompt + structured result."""
    missing = netpol_drift(golden)
    fix = suggested_fix(missing)
    services = deployment_health()
    text = format_diagnostics(missing, golden)
    dep_text = format_deployments(services)
    if dep_text:
        text = f"{text}\n{dep_text}"
    # Drift is the specific diagnosis and always wins: it names the exact rule
    # that vanished. Only when nothing is missing do we look at the Deployments.
    source, why = ("drift", "") if fix else ("", "")
    if not fix:
        sick = unhealthy_deployments(services)
        if sick:
            svc, why, action = sick[0]
            fix = (action, dict(svc["action_params"]))
            source = "deployment_health"
            text = f"{text}\nUnhealthy: {svc['namespace']}/{svc['name']} — {why}."
    return {
        "missing_rules": [asdict(m) for m in missing],
        "deployments": services,
        "suggested_action": fix[0] if fix else None,
        "action_params": fix[1] if fix else None,
        "action_reason": why or None,
        "action_confidence": source or None,
        "text": text,
    }

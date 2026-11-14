"""The allowlist.  Nothing outside ``REGISTRY`` can be dry-run or executed."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from beacon.remediation import actions_deploy, actions_netpol
from beacon.remediation.base import ActionResult, ParamError

if TYPE_CHECKING:
    from collections.abc import Callable

__all__ = [
    "REGISTRY",
    "ActionResult",
    "ActionSpec",
    "ParamError",
    "confirmation_phrase",
    "get_action",
    "rbac_rules",
    "undo_phrase",
    "validate_params",
]


@dataclass(frozen=True, slots=True)
class ActionSpec:
    id: str
    description: str
    params_schema: dict[str, type]
    # Kubernetes RBAC the remediator service account needs: "group/resource:verbs"
    rbac_rules: tuple[str, ...]
    blast_radius: Callable[[dict[str, Any]], str]
    precondition: Callable[..., str | None]
    dry_run: Callable[..., ActionResult]
    execute: Callable[..., ActionResult]
    postcondition: Callable[..., bool]
    # The action that undoes this one with the same params ("undo fix <n>"), if any.
    inverse: str | None = None
    # How long recovery is allowed to take. Restoring a rule works the moment it
    # lands, so the alert clears in a minute; replacing pods means waiting for them
    # to start, warm up and then for Prometheus to see clean evaluations. Escalating a
    # fix that actually worked is its own kind of wrong, so this is per action.
    verify_wait_seconds: int = 30
    verify_max_attempts: int = 6


_NETPOL_PARAMS: dict[str, type] = {
    "namespace": str,
    "name": str,
    "from_app": str,
    "port": int,
    "protocol": str,
}
_DEPLOY_PARAMS: dict[str, type] = {"namespace": str, "name": str}

REGISTRY: dict[str, ActionSpec] = {
    "networkpolicy.restore_ingress": ActionSpec(
        id="networkpolicy.restore_ingress",
        description=(
            "Restore one NetworkPolicy ingress rule that exists in the golden snapshot"
        ),
        params_schema=_NETPOL_PARAMS,
        rbac_rules=("networking.k8s.io/networkpolicies:get,patch",),
        blast_radius=actions_netpol.blast_radius,
        precondition=actions_netpol.precondition,
        dry_run=actions_netpol.dry_run,
        execute=actions_netpol.execute,
        postcondition=actions_netpol.postcondition,
        inverse="networkpolicy.revoke_ingress",
    ),
    "networkpolicy.revoke_ingress": ActionSpec(
        id="networkpolicy.revoke_ingress",
        description=(
            "Undo: remove the ingress rule Night Shift restored earlier in this incident"
        ),
        params_schema=_NETPOL_PARAMS,
        rbac_rules=("networking.k8s.io/networkpolicies:get,patch",),
        blast_radius=actions_netpol.revoke_blast_radius,
        precondition=actions_netpol.precondition,  # only rules the snapshot knows
        dry_run=actions_netpol.revoke_dry_run,
        execute=actions_netpol.revoke_execute,
        postcondition=actions_netpol.revoke_postcondition,
    ),
    "deployment.restart": ActionSpec(
        id="deployment.restart",
        description="Rollout-restart one Deployment (same pod template)",
        params_schema=_DEPLOY_PARAMS,
        rbac_rules=("apps/deployments:get,patch",),
        blast_radius=actions_deploy.blast_radius,
        precondition=actions_deploy.precondition,
        dry_run=actions_deploy.dry_run,
        execute=actions_deploy.execute,
        postcondition=actions_deploy.postcondition,
        # new pods have to start, pass readiness, and then Prometheus has to
        # see clean evaluations: minutes of patience rather than seconds
        verify_wait_seconds=20,
        verify_max_attempts=15,
    ),
    "deployment.rollback": ActionSpec(
        id="deployment.rollback",
        description=(
            "Roll one Deployment back to the pod template of its previous revision"
        ),
        params_schema=_DEPLOY_PARAMS,
        rbac_rules=("apps/deployments:get,patch", "apps/replicasets:list"),
        blast_radius=actions_deploy.rollback_blast_radius,
        precondition=actions_deploy.rollback_precondition,
        dry_run=actions_deploy.rollback_dry_run,
        execute=actions_deploy.rollback_execute,
        postcondition=actions_deploy.postcondition,
        verify_wait_seconds=20,
        verify_max_attempts=15,
    ),
}


def verify_budget(action: str) -> tuple[int, int]:
    """(seconds between attempts, attempts) for this action's verification."""
    spec = REGISTRY.get(action)
    return (spec.verify_wait_seconds, spec.verify_max_attempts) if spec else (30, 6)


def get_action(action_id: str) -> ActionSpec | None:
    return REGISTRY.get(action_id)


def validate_params(action_id: str, params: dict[str, Any]) -> dict[str, Any]:
    """Return *params* if they exactly match the action's schema, else raise."""
    spec = REGISTRY.get(action_id)
    if spec is None:
        raise ParamError(f"action '{action_id}' is not allowlisted")
    for key in spec.params_schema:
        if key not in params:
            raise ParamError(f"missing param: {key}")
    for key, value in params.items():
        expected = spec.params_schema.get(key)
        if expected is None:
            raise ParamError(f"unexpected param: {key}")
        if isinstance(value, bool) or not isinstance(value, expected):
            raise ParamError(f"param {key} must be {expected.__name__}")
    return dict(params)


def confirmation_phrase(fix_id: int) -> str:
    """The exact phrase the engineer must say to approve proposal *fix_id*."""
    return f"approve fix {fix_id}"


def undo_phrase(fix_id: int) -> str:
    """The exact phrase that undoes an applied fix."""
    return f"undo fix {fix_id}"


def rbac_rules() -> set[str]:
    """Union of RBAC rules any allowlisted action needs (the remediator Role)."""
    return {rule for spec in REGISTRY.values() for rule in spec.rbac_rules}

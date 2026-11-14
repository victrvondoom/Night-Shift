"""``deployment.restart`` and ``deployment.rollback`` for allowlisted Deployments.

Only Deployments named in ``REMEDIABLE_DEPLOYMENTS`` (``ns/name[,ns/name...]``)
may be touched. A restart re-rolls the same pod template; a rollback restores
the pod template of the previous ReplicaSet revision, exactly what
``kubectl rollout undo`` does, and nothing a model wrote.
"""

from __future__ import annotations

import logging
import os
from datetime import UTC, datetime
from typing import Any

from beacon import k8s
from beacon.remediation.base import ActionResult

logger = logging.getLogger(__name__)
_REVISION = "deployment.kubernetes.io/revision"
_RESTARTED = "kubectl.kubernetes.io/restartedAt"


def target(params: dict[str, Any]) -> str:
    return f"{params['namespace']}/{params['name']}"


def configured() -> list[str]:
    raw = os.environ.get("REMEDIABLE_DEPLOYMENTS", "")
    return [t.strip() for t in raw.split(",") if "/" in t]


def is_configured(params: dict[str, Any]) -> bool:
    return target(params) in configured()


def read(params: dict[str, Any]) -> dict[str, Any]:
    return k8s.raw(
        k8s.apps().read_namespaced_deployment(
            params["name"], params["namespace"], _preload_content=False
        )
    )


def _revision(obj: dict[str, Any]) -> int:
    try:
        return int((obj["metadata"].get("annotations") or {}).get(_REVISION) or 0)
    except ValueError:
        return 0


def previous_revision(deployment: dict[str, Any]) -> dict[str, Any] | None:
    """The ReplicaSet this Deployment ran before the current revision, if any."""
    ns = deployment["metadata"]["namespace"]
    uid = deployment["metadata"]["uid"]
    selector = ",".join(
        f"{k}={v}"
        for k, v in (deployment["spec"]["selector"].get("matchLabels") or {}).items()
    )
    listing = k8s.raw(
        k8s.apps().list_namespaced_replica_set(
            ns, label_selector=selector, _preload_content=False
        )
    )
    current = _revision(deployment)
    owned = [
        rs
        for rs in listing.get("items") or []
        if any(o.get("uid") == uid for o in rs["metadata"].get("ownerReferences") or [])
        and 0 < _revision(rs) < current
    ]
    return max(owned, key=_revision) if owned else None


def rollout_healthy(deployment: dict[str, Any]) -> bool:
    spec, status, meta = (
        deployment["spec"],
        deployment.get("status") or {},
        deployment["metadata"],
    )
    want = int(spec.get("replicas") or 0)
    return (
        want > 0
        and int(status.get("observedGeneration") or 0)
        >= int(meta.get("generation") or 0)
        and int(status.get("updatedReplicas") or 0) == want
        and int(status.get("availableReplicas") or 0) == want
        and int(status.get("replicas") or 0) == want
    )


def describe(params: dict[str, Any]) -> dict[str, Any]:
    """Health summary used by diagnostics and the evidence tool."""
    try:
        d = read(params)
    except k8s.ApiException as exc:
        return {**params, "status": "unknown", "error": k8s.error_code(exc)[0]}
    status = d.get("status") or {}
    conditions = {c["type"]: c for c in status.get("conditions") or []}
    progressing = conditions.get("Progressing") or {}
    return {
        **params,
        "status": "ACTIVE",
        "desired": int(d["spec"].get("replicas") or 0),
        "running": int(status.get("availableReplicas") or 0),
        "updated": int(status.get("updatedReplicas") or 0),
        "unavailable": int(status.get("unavailableReplicas") or 0),
        "revision": _revision(d),
        "healthy": rollout_healthy(d),
        "progress_deadline_exceeded": progressing.get("reason")
        == "ProgressDeadlineExceeded",
        "last_update": progressing.get("lastUpdateTime"),
        "images": [
            c.get("image")
            for c in d["spec"]["template"]["spec"].get("containers") or []
        ],
    }


def blast_radius(params: dict[str, Any]) -> str:
    return (
        f"1 Deployment restarted: {target(params)} re-rolls its pods with the same "
        "image and configuration. Pods are replaced one by one."
    )


def rollback_blast_radius(params: dict[str, Any]) -> str:
    return (
        f"1 Deployment rolled back: {target(params)} returns to the pod template of "
        "its previous revision. Whatever the latest rollout changed is undone."
    )


def precondition(params: dict[str, Any]) -> str | None:
    if not is_configured(params):
        return f"{target(params)} is not in REMEDIABLE_DEPLOYMENTS"
    try:
        read(params)
    except k8s.ApiException as exc:
        return f"deployment unreadable: {k8s.error_code(exc)[0]}"
    return None


def rollback_precondition(params: dict[str, Any]) -> str | None:
    error = precondition(params)
    if error:
        return error
    if previous_revision(read(params)) is None:
        return "there is no previous revision to roll back to"
    return None


def _patch(
    params: dict[str, Any], patch: list[dict[str, Any]], dry_run: bool
) -> dict[str, Any]:
    return k8s.raw(
        k8s.apps().patch_namespaced_deployment(
            params["name"],
            params["namespace"],
            patch,
            _preload_content=False,
            **({"dry_run": "All"} if dry_run else {}),
        )
    )


def _restart(params: dict[str, Any], *, dry_run: bool) -> ActionResult:
    stamp = datetime.now(tz=UTC).isoformat()
    try:
        d = read(params)
        has = "annotations" in (d["spec"]["template"].get("metadata") or {})
        path = "/spec/template/metadata/annotations"
        op = (
            {
                "op": "add",
                "path": f"{path}/{_RESTARTED.replace('/', '~1')}",
                "value": stamp,
            }
            if has
            else {"op": "add", "path": path, "value": {_RESTARTED: stamp}}
        )
        out = _patch(params, [op], dry_run)
    except k8s.ApiException as exc:
        code, message = k8s.error_code(exc)
        return ActionResult(False, code, message)
    got = (out["spec"]["template"]["metadata"].get("annotations") or {}).get(_RESTARTED)
    if got != stamp:
        return ActionResult(False, "UnexpectedResult", "restart annotation not set")
    return ActionResult(
        True,
        "DryRun" if dry_run else "Restarted",
        f"{'server dry-run accepted' if dry_run else 'applied'}: rollout restart of "
        f"{target(params)} (generation {d['metadata'].get('generation')} -> "
        f"{out['metadata'].get('generation')})",
    )


def _rollback(params: dict[str, Any], *, dry_run: bool) -> ActionResult:
    try:
        d = read(params)
        prev = previous_revision(d)
        if prev is None:
            return ActionResult(False, "NoPreviousRevision", "nothing to roll back to")
        template = dict(prev["spec"]["template"])
        meta = dict(template.get("metadata") or {})
        meta["labels"] = {
            k: v
            for k, v in (meta.get("labels") or {}).items()
            if k != "pod-template-hash"
        }
        template["metadata"] = meta
        patch = [
            {
                "op": "test",
                "path": "/metadata/resourceVersion",
                "value": d["metadata"]["resourceVersion"],
            },
            {"op": "replace", "path": "/spec/template", "value": template},
        ]
        out = _patch(params, patch, dry_run)
    except k8s.ApiException as exc:
        code, message = k8s.error_code(exc)
        return ActionResult(False, code, message)
    images = [c.get("image") for c in out["spec"]["template"]["spec"]["containers"]]
    return ActionResult(
        True,
        "DryRun" if dry_run else "RolledBack",
        f"{'server dry-run accepted' if dry_run else 'applied'}: {target(params)} "
        f"revision {_revision(d)} -> template of revision {_revision(prev)} "
        f"(images {', '.join(str(i) for i in images)})",
    )


def dry_run(params: dict[str, Any]) -> ActionResult:
    return _restart(params, dry_run=True)


def execute(params: dict[str, Any]) -> ActionResult:
    return _restart(params, dry_run=False)


def rollback_dry_run(params: dict[str, Any]) -> ActionResult:
    return _rollback(params, dry_run=True)


def rollback_execute(params: dict[str, Any]) -> ActionResult:
    return _rollback(params, dry_run=False)


def postcondition(params: dict[str, Any]) -> bool:
    """True when the rollout has finished and every replica is available."""
    return rollout_healthy(read(params))

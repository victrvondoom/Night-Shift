"""One place to build Kubernetes API clients (in-cluster first, kubeconfig second).

Every object is read and written as raw JSON (camelCase, exactly what the API
server stores) so golden snapshots, patches and audit evidence all share one shape.
"""

from __future__ import annotations

import json
import os
from functools import cache
from typing import Any

from kubernetes import client, config
from kubernetes.client.exceptions import ApiException

__all__ = ["ApiException", "api", "beacon_namespace", "identity", "raw", "split"]


@cache
def api() -> client.ApiClient:
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config(config_file=os.environ.get("KUBECONFIG") or None)
    return client.ApiClient()


def beacon_namespace() -> str:
    return os.environ.get("BEACON_NAMESPACE", "beacon")


def raw(resp: Any) -> dict[str, Any]:
    """Decode a ``_preload_content=False`` response into the stored JSON object."""
    return dict(json.loads(resp.data))


def split(target: str) -> tuple[str, str]:
    """``namespace/name`` -> ``(namespace, name)``."""
    ns, _, name = target.partition("/")
    return ns, name


def net() -> client.NetworkingV1Api:
    return client.NetworkingV1Api(api())


def apps() -> client.AppsV1Api:
    return client.AppsV1Api(api())


def core() -> client.CoreV1Api:
    return client.CoreV1Api(api())


def identity() -> str:
    """Who the API server says we are (the remediator service account)."""
    try:
        review = client.AuthenticationV1Api(api()).create_self_subject_review(
            body=client.V1SelfSubjectReview()
        )
        return str(review.status.user_info.username)
    except Exception:
        return os.environ.get("BEACON_K8S_IDENTITY", "unknown")


def error_code(exc: ApiException) -> tuple[str, str]:
    """``(reason, message)`` from an API error, e.g. ``("Forbidden", "...")``."""
    try:
        body = json.loads(exc.body or "{}")
    except (TypeError, ValueError):
        body = {}
    return str(body.get("reason") or exc.reason or exc.status), str(
        body.get("message") or ""
    )

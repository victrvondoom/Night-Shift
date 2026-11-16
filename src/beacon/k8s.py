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


class _Raw:
    """Mimics a ``_preload_content=False`` urllib3 response."""

    def __init__(self, data: bytes) -> None:
        self.data = data


class _SimApi:
    """The DEMO_SIMULATOR stand-in for the two API groups the remediator uses.

    Active only when ``SIMULATOR_URL`` is set.  It never reaches a real cluster.
    """

    def __init__(self, base: str) -> None:
        self.base = base.rstrip("/")

    def _call(self, method: str, path: str, *, body: Any = None, params: dict[str, str] | None = None) -> _Raw:
        import urllib.error
        import urllib.parse
        import urllib.request

        url = f"{self.base}/k8s{path}" + (("?" + urllib.parse.urlencode(params)) if params else "")
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers={"content-type": "application/json"})  # noqa: S310
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
                return _Raw(resp.read())
        except urllib.error.HTTPError as exc:
            err = ApiException(status=exc.code, reason=exc.reason)
            err.body = exc.read().decode()
            raise err from exc

    # networking.k8s.io/v1
    def read_namespaced_network_policy(self, name: str, namespace: str, **_: Any) -> _Raw:
        return self._call("GET", f"/apis/networking.k8s.io/v1/namespaces/{namespace}/networkpolicies/{name}")

    def patch_namespaced_network_policy(self, name: str, namespace: str, body: Any, dry_run: str | None = None, **_: Any) -> _Raw:
        params = {"dryRun": dry_run} if dry_run else None
        return self._call("PATCH", f"/apis/networking.k8s.io/v1/namespaces/{namespace}/networkpolicies/{name}", body=body, params=params)

    # core/v1 (the golden snapshot ConfigMap is read-only in the simulator)
    def read_namespaced_config_map(self, name: str, namespace: str, **_: Any) -> _Raw:
        return self._call("GET", f"/api/v1/namespaces/{namespace}/configmaps/{name}")


def simulator() -> _SimApi | None:
    base = os.environ.get("SIMULATOR_URL", "")
    return _SimApi(base) if base else None


def is_simulated() -> bool:
    return bool(os.environ.get("SIMULATOR_URL"))


def net() -> client.NetworkingV1Api:
    sim = simulator()
    if sim is not None:
        return sim  # type: ignore[return-value]
    return client.NetworkingV1Api(api())


def apps() -> client.AppsV1Api:
    return client.AppsV1Api(api())


def core() -> client.CoreV1Api:
    sim = simulator()
    if sim is not None:
        return sim  # type: ignore[return-value]
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

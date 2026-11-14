"""Secrets: HashiCorp Vault (KV v2) first, environment as the local fallback.

``get("BOLNA_API_KEY")`` reads the env var of that name if set (local runs,
tests), else key ``BOLNA_API_KEY`` from the KV v2 secret at
``$VAULT_ADDR/v1/$VAULT_KV_MOUNT/data/$VAULT_SECRET_PATH``. In Kubernetes the
token comes from the pod's service account via Vault's Kubernetes auth.
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.request
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)
_SA_TOKEN = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
_cache: dict[str, Any] = {"at": 0.0, "data": {}, "token": "", "token_at": 0.0}
_TTL = 300.0


def _http(method: str, url: str, body: Any = None, token: str = "") -> Any:
    req = urllib.request.Request(  # noqa: S310
        url,
        data=json.dumps(body).encode() if body is not None else None,
        method=method,
        headers={"content-type": "application/json", "X-Vault-Token": token},
    )
    with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310
        return json.loads(resp.read().decode() or "{}")


def _token(addr: str) -> str:
    direct = os.environ.get("VAULT_TOKEN", "")
    if direct:
        return direct
    role = os.environ.get("VAULT_K8S_ROLE", "")
    if not role or not _SA_TOKEN.exists():
        return ""
    if _cache["token"] and time.time() - _cache["token_at"] < _TTL:
        return str(_cache["token"])
    out = _http(
        "POST",
        f"{addr}/v1/auth/kubernetes/login",
        {"role": role, "jwt": _SA_TOKEN.read_text().strip()},
    )
    _cache["token"] = str(out["auth"]["client_token"])
    _cache["token_at"] = time.time()
    return str(_cache["token"])


def _vault() -> dict[str, Any]:
    addr = os.environ.get("VAULT_ADDR", "").rstrip("/")
    if not addr:
        return {}
    if _cache["data"] and time.time() - _cache["at"] < _TTL:
        return dict(_cache["data"])
    mount = os.environ.get("VAULT_KV_MOUNT", "secret")
    path = os.environ.get("VAULT_SECRET_PATH", "beacon")
    try:
        token = _token(addr)
        if not token:
            return {}
        out = _http("GET", f"{addr}/v1/{mount}/data/{path}", token=token)
        _cache["data"] = dict(out["data"]["data"])
        _cache["at"] = time.time()
    except Exception as exc:
        logger.warning("vault read failed: %s", exc)
        return {}
    return dict(_cache["data"])


def get(name: str, default: str = "") -> str:
    """One secret by name; never logged, never returned to a browser."""
    direct = os.environ.get(name, "")
    if direct:
        return direct
    return str(_vault().get(name) or default)


def reset() -> None:
    _cache.update({"at": 0.0, "data": {}, "token": "", "token_at": 0.0})

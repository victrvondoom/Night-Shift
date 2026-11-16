"""Hard sandbox guard: demo remediation refuses to run outside the configured sandbox.

``SANDBOX_CONTEXTS`` (comma list of kube contexts) and ``SANDBOX_NAMESPACES`` (defaults to
``REMEDIABLE_NAMESPACES``).  When ``SANDBOX_CONTEXTS`` is set, a mutation whose active cluster
context or target namespace is not listed is refused *before* any API call.  The DEMO_SIMULATOR
context is ``demo-simulator``.  ``REQUIRE_SANDBOX=true`` makes an unset list fail closed.
"""

from __future__ import annotations

import os
from typing import Any

SIM_CONTEXT = "demo-simulator"


def _csv(name: str) -> list[str]:
    return [x.strip() for x in os.environ.get(name, "").split(",") if x.strip()]


def current_context() -> str:
    from beacon import k8s

    if k8s.is_simulated():
        return SIM_CONTEXT
    if os.environ.get("BEACON_K8S_CONTEXT"):
        return os.environ["BEACON_K8S_CONTEXT"]
    try:
        from kubernetes import config

        return str(config.list_kube_config_contexts(config_file=os.environ.get("KUBECONFIG") or None)[1]["name"])
    except Exception:
        return "in-cluster"


def sandbox_error(params: dict[str, Any]) -> str | None:
    contexts = _csv("SANDBOX_CONTEXTS")
    if not contexts:
        if os.environ.get("REQUIRE_SANDBOX", "").lower() == "true":
            return "sandbox guard: SANDBOX_CONTEXTS is not configured (REQUIRE_SANDBOX=true)"
        return None
    ctx = current_context()
    if ctx not in contexts:
        return f"sandbox guard: cluster context {ctx!r} is not in SANDBOX_CONTEXTS; refusing"
    namespaces = _csv("SANDBOX_NAMESPACES") or _csv("REMEDIABLE_NAMESPACES")
    ns = str(params.get("namespace", ""))
    if ns not in namespaces:
        return f"sandbox guard: namespace {ns!r} is outside the sandbox namespaces {namespaces}"
    return None

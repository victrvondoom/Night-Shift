"""Open Policy Agent gate: every dry run and every execute asks OPA first.

The Rego bundle in ``policy/`` is the written-down version of what Night Shift may
do: which actions, in which namespaces, and that an execute needs an approval
whose provenance is verified. Night Shift fails closed: no OPA answer, no change.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.request
from typing import Any

logger = logging.getLogger(__name__)
_PATH = "/v1/data/beacon/remediation/decision"


def evaluate(
    phase: str,
    action: str,
    params: dict[str, Any],
    *,
    approval: dict[str, Any] | None = None,
) -> tuple[bool, list[str]]:
    """``(allowed, reasons)`` for one action in one phase (``dryrun``/``execute``)."""
    base = os.environ.get("OPA_URL", "").rstrip("/")
    if not base:
        return False, ["OPA_URL is not set; policy cannot be evaluated"]
    doc = {
        "input": {
            "phase": phase,
            "action": action,
            "params": params,
            "approval": {
                k: (approval or {}).get(k)
                for k in ("source", "channel", "kind", "used_at", "contract_id")
            }
            | {"evidence": ((approval or {}).get("attestation") or {}).get("evidence")},
            "allowed_namespaces": [
                n.strip()
                for n in os.environ.get("REMEDIABLE_NAMESPACES", "").split(",")
                if n.strip()
            ],
        }
    }
    req = urllib.request.Request(  # noqa: S310
        base + _PATH,
        data=json.dumps(doc).encode(),
        method="POST",
        headers={"content-type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310
            result = json.loads(resp.read().decode()).get("result")
    except Exception as exc:
        logger.warning("OPA unreachable: %s", exc)
        return False, [f"policy engine unreachable: {exc}"]
    if not isinstance(result, dict):
        return False, ["policy returned no decision (bundle not loaded?)"]
    allowed = result.get("allow") is True
    reasons = [str(r) for r in result.get("deny") or []]
    return allowed, reasons or ([] if allowed else ["denied by policy"])

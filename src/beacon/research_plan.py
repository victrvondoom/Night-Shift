"""External research planning: what Night Shift is allowed to ask a third party, and how.

Two deterministic pieces (no model involved):

* ``sanitize_query``  -- the ONLY gate between incident context and Tavily.  A query that carries an
  internal identifier or anything secret-shaped is rejected, never "cleaned up and sent".
* ``plan``            -- derives a small set of technically specific queries from the incident's
  evidence *category* (event types, failure class), never from raw evidence text.

External queries therefore describe the *mechanism* ("how does Kubernetes select pods for an ingress
NetworkPolicy"), not the incident ("why did demo-api lose demo-db").
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

MAX_QUERY_CHARS = 160
OFFICIAL_DOMAINS = ("kubernetes.io",)

_PATTERNS: dict[str, re.Pattern[str]] = {
    "url": re.compile(r"(https?://|ftp://|www\.)", re.I),
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b"),
    "ipv6": re.compile(r"\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b", re.I),
    "email": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
    "uuid": re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I),
    "night_shift_id": re.compile(r"\b(?:evt|ext|cor|ana|brf|qry|INC|snap)-[0-9A-Za-z]{6,}\b"),
    "cluster_dns": re.compile(r"\b[\w-]+(?:\.[\w-]+)*\.(?:svc|cluster\.local|internal|local|lan|corp)\b", re.I),
    "hostport": re.compile(r"\b[a-z][\w-]*[\w]:\d{2,5}\b", re.I),
    "secret_prefix": re.compile(r"\b(?:sk|pk|tvly|gsk|ghp|gho|xox[bpa]|AKIA|AIza|bn|eyJ)[-_A-Za-z0-9]{6,}", re.I),
    "bearer": re.compile(r"\b(?:bearer|authorization|token|passcode|password|passwd|secret|api[_-]?key)\b\s*[:=]?", re.I),
    "long_token": re.compile(r"\b[A-Za-z0-9+/_-]{28,}={0,2}\b"),
    "path": re.compile(r"(?:^|\s)(?:/(?:home|root|etc|var|tmp|usr)/\S+|[A-Za-z]:\\\S+)"),
    "shell": re.compile(r"[;&|`$]|\$\(|\brm\s+-|\bkubectl\s", re.I),
}


@dataclass(frozen=True)
class Sanitized:
    ok: bool
    query: str
    reasons: tuple[str, ...] = ()


def internal_identifiers(ctx: dict[str, Any] | None) -> set[str]:
    """Identifiers from the incident that must never reach a third party (lower-cased, length >= 3)."""
    ctx = ctx or {}
    raw: list[str] = []
    for key in ("namespace", "target_app", "incident_id", "run_id", "affected_service", "alarm_name", "cluster"):
        if ctx.get(key):
            raw.append(str(ctx[key]))
    for res in str(ctx.get("resource", "")).split("/"):
        raw.append(res)
    for extra in ctx.get("extra_identifiers") or []:
        raw.append(str(extra))
    out: set[str] = set()
    for item in raw:
        item = item.strip().lower()
        if len(item) >= 3:
            out.add(item)
            out.update(p for p in re.split(r"[-_./:]", item) if len(p) >= 4 and p not in _GENERIC)
    return out


# words that are part of the public Kubernetes vocabulary; stripped from the internal-name blocklist
_GENERIC = {"demo", "kubernetes", "network", "policy", "ingress", "egress", "deployment", "service", "namespace", "default", "pods", "database", "application", "alert", "errors", "firing"}


def sanitize_query(query: str, ctx: dict[str, Any] | None = None) -> Sanitized:
    """Accept a query only if it is clean; never repair it silently."""
    q = " ".join(str(query or "").split())
    reasons: list[str] = []
    if not q:
        return Sanitized(False, "", ("empty",))
    if len(q) > MAX_QUERY_CHARS:
        reasons.append("too_long")
    for name, pat in _PATTERNS.items():
        if pat.search(q):
            reasons.append(name)
    low = q.lower()
    for ident in sorted(internal_identifiers(ctx), key=len, reverse=True):
        if re.search(rf"(?<![a-z0-9]){re.escape(ident)}(?![a-z0-9])", low):
            reasons.append("internal_identifier")
            break
    if reasons:
        return Sanitized(False, "", tuple(dict.fromkeys(reasons)))
    return Sanitized(True, q)


@dataclass(frozen=True)
class PlannedQuery:
    purpose: str
    query: str
    domains: tuple[str, ...] = OFFICIAL_DOMAINS
    extract: bool = False  # worth a (paid) Extract of the best primary source
    rejected: tuple[str, ...] = field(default=())


# failure category -> technically specific questions about the *mechanism* (never incident text)
_CATALOG: dict[str, list[tuple[str, str, bool]]] = {
    "networkpolicy_connectivity": [
        ("mechanism", "Kubernetes NetworkPolicy ingress rules podSelector how pods are selected and isolated", True),
        ("default_deny", "Kubernetes NetworkPolicy default deny all ingress empty ingress list behavior", True),
        ("policy_behaviour", "Kubernetes NetworkPolicy additive allow rules multiple policies union semantics", False),
        ("pitfalls", "Kubernetes NetworkPolicy common mistakes namespaceSelector podSelector AND OR semantics", False),
        ("troubleshooting", "Kubernetes troubleshooting service connectivity pod cannot reach another pod network plugin policy enforcement", False),
        ("enforcement", "Kubernetes NetworkPolicy requires network plugin that supports it enforcement", False),
    ],
}


def classify(ctx: dict[str, Any]) -> str:
    """Failure category from *event types only* (a deterministic label, never free text)."""
    types = set(ctx.get("event_types") or ctx.get("symptom_types") or [])
    if "networkpolicy_change" in types or str(ctx.get("rule", "")).startswith("netpol_change"):
        return "networkpolicy_connectivity"
    return "unknown"


def plan(ctx: dict[str, Any], *, limit: int = 6) -> list[PlannedQuery]:
    """Planned, sanitised external queries for this incident; unsafe or unknown-category ones are dropped."""
    category = classify(ctx)
    out: list[PlannedQuery] = []
    for purpose, query, extract in _CATALOG.get(category, [])[:limit]:
        s = sanitize_query(query, ctx)
        out.append(PlannedQuery(purpose, s.query, extract=extract) if s.ok else PlannedQuery(purpose, "", rejected=s.reasons))
    return [p for p in out if p.query]


def sanitize_followups(queries: list[Any], ctx: dict[str, Any], already: set[str], *, cap: int = 2) -> tuple[list[str], list[dict[str, Any]]]:
    """Model-proposed queries are untrusted. Returns (accepted, rejected-with-reasons); at most ``cap`` accepted."""
    seen = {a.lower() for a in already}
    accepted: list[str] = []
    rejected: list[dict[str, Any]] = []
    for raw in queries or []:
        s = sanitize_query(str(raw), ctx)
        if not s.ok:
            rejected.append({"query_preview": "[withheld]", "reasons": list(s.reasons)})
        elif s.query.lower() in seen:
            rejected.append({"query_preview": s.query[:60], "reasons": ["duplicate"]})
        elif len(accepted) >= cap:
            rejected.append({"query_preview": s.query[:60], "reasons": ["over_cap"]})
        else:
            seen.add(s.query.lower())
            accepted.append(s.query)
    return accepted, rejected

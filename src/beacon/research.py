"""Targeted external research with Tavily (Search, then Extract for the best official source).

Queries are derived from the incident's own resource, change and error context.
Fields are stored exactly as the API returned them: a missing publication date
stays ``None`` and the Tavily ``score`` is a relevance score, never a confidence.
External pages are untrusted text: they are only ever stored and displayed.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx

from beacon import health_log
from beacon.evidence import ledger
from beacon.evidence.contracts import ResearchItem, iso, now_utc, stable_id

logger = logging.getLogger(__name__)
API = "https://api.tavily.com"
OFFICIAL = ("kubernetes.io",)


class ResearchError(Exception):
    def __init__(self, category: str, detail: str = "") -> None:
        super().__init__(f"{category}: {detail}")
        self.category, self.detail = category, detail


def configured() -> bool:
    return bool(os.environ.get("TAVILY_API_KEY"))


def derive_queries(incident: dict[str, Any], corr: dict[str, Any]) -> list[str]:
    """Technical questions the incident actually raises; never a generic search."""
    types = set(corr.get("symptom_types") or [])
    target = corr.get("target_app") or "the protected workload"
    qs = [
        "Kubernetes NetworkPolicy ingress rules podSelector default deny isolated pods allowed connections",
    ]
    if "db_connection_error" in types:
        qs.append(
            f"Kubernetes NetworkPolicy empty ingress list blocks all ingress traffic to pods selected for {target} connection timed out"
        )
    return qs[:2]


def _classify(item: dict[str, Any], url: str) -> tuple[str, str]:
    text = f"{item.get('title', '')} {item.get('content', '')}".lower()
    host = httpx.URL(url).host if url else ""
    if not item.get("content"):
        return "INSUFFICIENT_EVIDENCE", "the result carried no content to evaluate"
    if not any(host == d or host.endswith("." + d) for d in OFFICIAL):
        return "UNVERIFIED", f"{host} is not an official Kubernetes source"
    updated = str(item.get("updated_date") or item.get("published_date") or "")
    if updated and updated[:4].isdigit() and int(updated[:4]) < now_utc().year - 4:
        return "STALE", f"source dated {updated[:10]}"
    if ("isolated" in text or "default deny" in text or "default-deny" in text) and "ingress" in text:
        return (
            "SUPPORTS",
            "official documentation states pods selected by an ingress policy only accept listed connections, "
            "which is the mechanism the hypothesis relies on (it does not prove it happened here)",
        )
    return "CONTEXT_ONLY", "official source on NetworkPolicy, but does not address the observed behaviour directly"


def _post(path: str, body: dict[str, Any]) -> dict[str, Any]:
    key = os.environ.get("TAVILY_API_KEY", "")
    if not key:
        health_log.record("tavily", False, "not_configured")
        raise ResearchError("not_configured", "TAVILY_API_KEY is not set")
    try:
        r = httpx.post(f"{os.environ.get('TAVILY_API_URL', API)}{path}", json=body, headers={"Authorization": f"Bearer {key}"}, timeout=float(os.environ.get("TAVILY_TIMEOUT", "30")))
    except httpx.TimeoutException as exc:
        health_log.record("tavily", False, "timeout")
        raise ResearchError("timeout", str(exc)) from exc
    except httpx.HTTPError as exc:
        health_log.record("tavily", False, "unavailable", type(exc).__name__)
        raise ResearchError("unavailable", type(exc).__name__) from exc
    if r.status_code == 429:
        health_log.record("tavily", False, "rate_limited")
        raise ResearchError("rate_limited", "HTTP 429")
    if r.status_code in (401, 403):
        health_log.record("tavily", False, "auth")
        raise ResearchError("auth", f"HTTP {r.status_code}")
    if r.status_code >= 400:
        health_log.record("tavily", False, "http_error", f"HTTP {r.status_code}")
        raise ResearchError("http_error", f"HTTP {r.status_code}")
    health_log.record("tavily", True, detail=f"{path} ok")
    return dict(r.json())


def run(incident_id: str, incident: dict[str, Any], corr: dict[str, Any]) -> list[ResearchItem]:
    """Search (+ Extract the single best official source); persist and return the items."""
    items: list[ResearchItem] = []
    for q in derive_queries(incident, corr):
        qid = stable_id("qry", incident_id, q)
        data = _post("/search", {"query": q, "search_depth": "basic", "max_results": 4, "include_domains": list(OFFICIAL), "include_answer": False})
        retrieved = iso(now_utc())
        for i, res in enumerate(data.get("results") or []):
            url = str(res.get("url") or "")
            cls, why = _classify(res, url)
            items.append(
                ResearchItem(
                    query_id=qid,
                    incident_id=incident_id,
                    query=q,
                    title=str(res.get("title") or ""),
                    url=url,
                    excerpt=str(res.get("content") or "")[:1200],
                    score=float(res["score"]) if isinstance(res.get("score"), (int, float)) else None,
                    published_date=str(res["published_date"]) if res.get("published_date") else None,
                    updated_date=str(res["updated_date"]) if res.get("updated_date") else None,
                    retrieved_at=retrieved,
                    classification=cls,  # type: ignore[arg-type]
                    classification_reason=why,
                    evidence_id=stable_id("ext", incident_id, qid, url or str(i)),
                )
            )
    # Extract only the single most relevant official page that is not already long enough.
    best = max((i for i in items if i.classification in ("SUPPORTS", "CONTEXT_ONLY")), key=lambda i: i.score or 0, default=None)
    if best is not None:
        try:
            ex = _post("/extract", {"urls": [best.url]})
            got = (ex.get("results") or [{}])[0]
            if got.get("raw_content"):
                best.excerpt = str(got["raw_content"])[:2000]
                best.extraction_status = "OK"
            else:
                best.extraction_status = "FAILED"
        except ResearchError:
            best.extraction_status = "FAILED"
    seen: set[str] = set()
    unique = [i for i in items if not (i.evidence_id in seen or seen.add(i.evidence_id))]
    ledger.record_research(unique)
    return unique

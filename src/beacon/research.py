"""The research engine: planned, sanitised, budgeted Tavily Search -> Extract -> validated, provenance-rich storage.

* Every external operation is **reserved against a persistent per-incident budget BEFORE it is sent**
  (atomic SQL; concurrent callers cannot overspend) and recorded as an attempt row whatever happens:
  success, zero results, failure, retry.  A failed request is never a free retry.
* Only ``research_plan``-approved queries leave the system.
* External content is untrusted text: it is parsed, classified by rules, hashed and stored.  Nothing here
  can reach remediation, approval or policy code (asserted by a test).
* Provider failures surface as categorised errors/run statuses; they never become "successful research".
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any

import httpx

from beacon import health_log, research_plan
from beacon.evidence import ledger
from beacon.evidence.contracts import ResearchItem, iso, now_utc, stable_id

logger = logging.getLogger(__name__)
API = "https://api.tavily.com"
OFFICIAL = research_plan.OFFICIAL_DOMAINS
SEARCH_EST_CREDITS = 1.0  # basic search; replaced by the provider-reported usage.credits when present
EXTRACT_EST_CREDITS = 1.0  # basic extract is billed per 5 successful URLs; replaced by reported usage


class ResearchError(Exception):
    def __init__(self, category: str, detail: str = "") -> None:
        super().__init__(f"{category}: {detail}")
        self.category, self.detail = category, detail


def configured() -> bool:
    return bool(os.environ.get("TAVILY_API_KEY"))


# --------------------------------------------------------------------------------------- dates / classification
def parse_date(value: Any) -> tuple[str | None, str]:
    """(ISO-8601 UTC, status). Tavily sends RFC 2822; ISO is accepted. Missing -> UNKNOWN, garbage -> UNPARSEABLE."""
    if value in (None, ""):
        return None, "UNKNOWN"
    text = str(value).strip()
    dt: datetime | None = None
    try:
        dt = parsedate_to_datetime(text)
    except (TypeError, ValueError, IndexError):
        try:
            dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            dt = None
    if dt is None:
        return None, "UNPARSEABLE"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"), "KNOWN"


def _year(value: str) -> int | None:
    iso_s, st = parse_date(value)
    return int(iso_s[:4]) if iso_s else None


def age_days(value: str | None) -> int | None:
    iso_s, st = parse_date(value)
    if not iso_s:
        return None
    return max(0, (now_utc() - datetime.fromisoformat(iso_s.replace("Z", "+00:00"))).days)


def _classify(item: dict[str, Any], url: str) -> tuple[str, str]:
    text = f"{item.get('title', '')} {item.get('content', '')}".lower()
    host = httpx.URL(url).host if url else ""
    if not item.get("content"):
        return "INSUFFICIENT_EVIDENCE", "the result carried no content to evaluate"
    if not any(host == d or host.endswith("." + d) for d in OFFICIAL):
        return "UNVERIFIED", f"{host} is not an official Kubernetes source"
    dated = _year(str(item.get("updated_date") or item.get("published_date") or ""))
    if dated is not None and dated < now_utc().year - 4:
        return "STALE", f"source dated {dated}"
    if ("isolated" in text or "default deny" in text or "default-deny" in text) and "ingress" in text:
        return (
            "SUPPORTS",
            "official documentation states pods selected by an ingress policy only accept listed connections, "
            "which is the mechanism the hypothesis relies on (it does not prove it happened here)",
        )
    return "CONTEXT_ONLY", "official source on NetworkPolicy, but does not address the observed behaviour directly"


def content_hash(text: str) -> str:
    return hashlib.sha256((text or "").encode()).hexdigest()


# --------------------------------------------------------------------------------------- transport
@dataclass
class Outcome:
    ok: bool
    data: dict[str, Any] | None = None
    category: str = ""
    status: int | None = None
    attempts: int = 1
    credits: float | None = None
    request_id: str | None = None
    budget_denied: bool = False


def _timeout() -> float:
    return float(os.environ.get("TAVILY_TIMEOUT", "30"))


def _retry_cap() -> float:
    return float(os.environ.get("TAVILY_RETRY_CAP_S", "5"))


def _send(path: str, body: dict[str, Any]) -> tuple[int | None, dict[str, str], dict[str, Any] | None, str]:
    """One HTTP call. Returns (status, headers, json-or-None, category). Never raises; never logs secrets."""
    key = os.environ.get("TAVILY_API_KEY", "")
    if not key:
        return None, {}, None, "not_configured"
    try:
        r = httpx.post(f"{os.environ.get('TAVILY_API_URL', API)}{path}", json=body, headers={"Authorization": f"Bearer {key}"}, timeout=_timeout())
    except httpx.TimeoutException:
        return None, {}, None, "timeout"
    except httpx.HTTPError as exc:
        return None, {}, None, f"unavailable:{type(exc).__name__}"
    status, headers = r.status_code, {k.lower(): v for k, v in r.headers.items()}
    if status in (401, 403):
        return status, headers, None, "auth"
    if status == 429:
        return status, headers, None, "rate_limited"
    if status in (432, 433):
        return status, headers, None, "plan_limit"
    if status >= 500:
        return status, headers, None, "server_error"
    if status >= 400:
        return status, headers, None, "http_error"
    try:
        data = r.json()
    except ValueError:
        return status, headers, None, "invalid_response"
    if not isinstance(data, dict):
        return status, headers, None, "invalid_response"
    return status, headers, data, ""


def _attempt(incident_id: str, op: str, label: str, path: str, body: dict[str, Any], est: float) -> Outcome:
    """Reserve -> send -> record, with at most ONE retry (itself reserved and recorded) for transient failures."""
    max_tries = 2
    for n in range(1, max_tries + 1):
        if ledger.reserve(incident_id, op, est) is None:
            return Outcome(False, category="budget_exhausted", attempts=n - 1, budget_denied=True)
        attempt_id = f"att-{uuid.uuid4().hex[:16]}"
        status, headers, data, cat = _send(path, body)
        credits = request_id = None
        if data is not None:
            usage = data.get("usage") if isinstance(data.get("usage"), dict) else {}
            credits = float(usage["credits"]) if isinstance(usage.get("credits"), (int, float)) else None
            request_id = str(data.get("request_id") or "") or None
            ledger.settle(incident_id, est, credits)
        outcome = "ok" if data is not None else "failed"
        ledger.record_attempt(incident_id, attempt_id, op=op, query=label, outcome=outcome, http_status=status, error_category=cat or None, request_id=request_id, credits_reported=credits, attempt_no=n, retry=n > 1)
        health_log.record(f"tavily:{'search' if op == 'search' else 'extract'}", data is not None, cat.split(":")[0])
        if data is not None:
            return Outcome(True, data, status=status, attempts=n, credits=credits, request_id=request_id)
        transient = cat in ("rate_limited", "server_error", "timeout") or cat.startswith("unavailable")
        if not transient or n == max_tries:
            return Outcome(False, category=cat.split(":")[0], status=status, attempts=n)
        wait = min(_retry_cap(), float(headers.get("retry-after", "0.5") or 0.5)) if cat == "rate_limited" else 0.5
        time.sleep(max(0.0, wait))
    return Outcome(False, category="unknown")


# --------------------------------------------------------------------------------------- context
def build_context(incident_id: str) -> dict[str, Any]:
    """Incident facts used ONLY for planning and for the sanitiser's blocklist; never sent anywhere."""
    corr = (ledger.correlations_for(incident_id) or [{}])[-1]
    events = ledger.events_for(incident_id)
    names = {e["resource"].get("name", "") for e in events} | {e["resource"].get("target_app", "") for e in events}
    return {
        "incident_id": incident_id,
        "namespace": corr.get("namespace", ""),
        "resource": corr.get("resource", ""),
        "target_app": corr.get("target_app", ""),
        "run_id": corr.get("run_id", ""),
        "rule": corr.get("rule", ""),
        "symptom_types": corr.get("symptom_types", []),
        "event_types": sorted({e["event_type"] for e in events}),
        "extra_identifiers": sorted(n for n in names if n),
    }


# --------------------------------------------------------------------------------------- orchestration
def _build_item(incident_id: str, res: dict[str, Any], planned_purpose: str, query: str, req_id: str | None, credits: float | None, retrieved: str) -> ResearchItem | None:
    url = str(res.get("url") or "").strip()
    if not url.startswith(("http://", "https://")):
        return None  # a result without a usable URL is not a source
    cls, why = _classify(res, url)
    published_at, date_status = parse_date(res.get("published_date"))
    excerpt = str(res.get("content") or "")[:1200]
    return ResearchItem(
        query_id=stable_id("qry", incident_id, query),
        incident_id=incident_id,
        query=query,
        title=str(res.get("title") or ""),
        url=url,
        domain=httpx.URL(url).host,
        excerpt=excerpt,
        content_hash=content_hash(str(res.get("content") or "")),
        score=float(res["score"]) if isinstance(res.get("score"), (int, float)) else None,
        published_date=str(res["published_date"]) if res.get("published_date") else None,
        published_at=published_at,
        date_status=date_status,  # type: ignore[arg-type]
        updated_date=str(res["updated_date"]) if res.get("updated_date") else None,
        retrieved_at=retrieved,
        request_id=req_id,
        credits=credits,
        classification=cls,  # type: ignore[arg-type]
        classification_reason=why,
        evidence_id=stable_id("ext", incident_id, url),
        planned_purpose=planned_purpose,
    )


def _store(item: ResearchItem) -> str:
    """Insert, or update an existing source ONLY if its content changed (kept as a revision). Returns new|updated|duplicate."""
    from beacon import db

    row = db.get(ledger.research_table(), item.evidence_id)
    if row is None:
        ledger.record_research([item])
        return "new"
    if row.get("content_hash") == item.content_hash:
        return "duplicate"
    if row.get("hash_basis", "snippet") == "snippet" and item.hash_basis == "extract":
        db.put(ledger.research_table(), item.evidence_id, {**item.model_dump(mode="json"), "revisions": row.get("revisions") or []})
        return "enriched"  # the same page, now with its full extracted text: not a content change
    if row.get("hash_basis", "snippet") == "extract" and item.hash_basis == "snippet":
        return "duplicate"  # a fresh search snippet never downgrades an extracted source
    revs = list(row.get("revisions") or []) + [{"content_hash": row.get("content_hash"), "retrieved_at": row.get("retrieved_at")}]
    db.put(ledger.research_table(), item.evidence_id, {**item.model_dump(mode="json"), "revisions": revs})
    return "updated"


def execute(incident_id: str, *, followups: list[str] | None = None) -> dict[str, Any]:
    """Run planned (or, when given, already-sanitised follow-up) research for one incident. Returns a run summary."""
    if not configured():
        raise ResearchError("not_configured", "TAVILY_API_KEY is not set")
    lock = ledger.acquire_run(incident_id, "followup" if followups else "plan")
    if lock is None:
        raise ResearchError("run_in_progress", "a research run is already active for this incident")
    run_id = f"run-{uuid.uuid4().hex[:12]}"
    started = iso(now_utc())
    ledger.record_run(incident_id, run_id, status="RUNNING", kind="followup" if followups else "plan", started_at=started)
    summary: dict[str, Any] = {"run_id": run_id, "new": 0, "updated": 0, "duplicate": 0, "enriched": 0, "failures": [], "budget_exhausted": False, "queries": 0}
    try:
        ctx = build_context(incident_id)
        if followups:
            planned = [research_plan.PlannedQuery("followup", q, extract=True) for q in followups]
        else:
            planned = research_plan.plan(ctx)
        done = {q["query"] for q in ledger.queries_for(incident_id) if q.get("op") == "search" and q.get("outcome") == "ok"}
        found: list[tuple[ResearchItem, bool]] = []
        for pq in planned:
            if pq.query in done:
                continue
            body = {"query": pq.query, "search_depth": "basic", "max_results": 4, "include_domains": list(pq.domains), "include_answer": False, "include_published_date": True}
            out = _attempt(incident_id, "search", pq.query, "/search", body, SEARCH_EST_CREDITS)
            summary["queries"] += out.attempts
            if out.budget_denied:
                summary["budget_exhausted"] = True
                break
            if not out.ok:
                summary["failures"].append({"op": "search", "category": out.category})
                if out.category == "auth":
                    break  # bad credentials: stop, do not burn the budget on a doomed loop
                continue
            results = out.data.get("results") if isinstance(out.data.get("results"), list) else None
            if results is None:
                summary["failures"].append({"op": "search", "category": "invalid_response"})
                continue
            retrieved = iso(now_utc())
            for res in results:
                if not isinstance(res, dict):
                    continue
                it = _build_item(incident_id, res, pq.purpose, pq.query, out.request_id, out.credits, retrieved)
                if it is not None:
                    found.append((it, pq.extract))
        # best official primary sources, extracted in ONE call (billed per 5 URLs)
        # one object per source (the same page can be returned by several queries)
        uniq: dict[str, ResearchItem] = {}
        wanted_extract: set[str] = set()
        for it, want in found:
            if it.evidence_id not in uniq or (it.score or 0) > (uniq[it.evidence_id].score or 0):
                uniq[it.evidence_id] = it
            if want:
                wanted_extract.add(it.evidence_id)
        found = [(it, it.evidence_id in wanted_extract) for it in uniq.values()]
        existing = {r["evidence_id"]: r for r in ledger.research_for(incident_id)}
        cand: dict[str, ResearchItem] = {}
        for it, want in found:
            if want and it.classification in ("SUPPORTS", "CONTEXT_ONLY") and existing.get(it.evidence_id, {}).get("extraction_status") != "OK":
                cand[it.evidence_id] = it
        top = sorted(cand.values(), key=lambda i: i.score or 0, reverse=True)[:2]
        if top and not summary["budget_exhausted"]:
            out = _attempt(incident_id, "extract", f"extract:{len(top)}", "/extract", {"urls": [i.url for i in top]}, EXTRACT_EST_CREDITS)
            summary["queries"] += out.attempts
            if out.budget_denied:
                summary["budget_exhausted"] = True
            elif not out.ok:
                summary["failures"].append({"op": "extract", "category": out.category})
                for i in top:
                    i.extraction_status = "FAILED"
            else:
                got = {str(r.get("url")): r for r in (out.data.get("results") or []) if isinstance(r, dict)}
                failed = {str(r.get("url")) for r in (out.data.get("failed_results") or []) if isinstance(r, dict)}
                for i in top:
                    r = got.get(i.url)
                    if r and r.get("raw_content"):
                        raw = str(r["raw_content"])
                        i.excerpt, i.content_hash, i.extraction_status, i.hash_basis = raw[:2000], content_hash(raw), "OK", "extract"
                    else:
                        i.extraction_status = "FAILED"
                        if i.url in failed:
                            summary["failures"].append({"op": "extract", "category": "partial_extraction_failure"})
        for it, _ in found:
            kind = _store(it)
            summary[kind] += 1
        # ledger rows for extracted sources were stored above with their final text/hash/status
        failed_n = len(summary["failures"])
        if summary["budget_exhausted"] and summary["queries"] == 0:
            status = "BUDGET_EXHAUSTED"
        elif summary["budget_exhausted"] or failed_n:
            status = "PARTIAL" if (summary["new"] + summary["updated"] + summary["duplicate"] + summary["enriched"]) or summary["queries"] > failed_n else "FAILED"
        else:
            status = "COMPLETED"
        if failed_n and not (summary["new"] + summary["updated"] + summary["duplicate"] + summary["enriched"]) and not summary["budget_exhausted"]:
            status = "FAILED"
        summary["status"] = status
    except Exception as exc:  # a crash is a FAILED run, never a silent success
        logger.exception("research run failed")
        summary["status"] = "FAILED"
        summary["failures"].append({"op": "run", "category": type(exc).__name__})
    finally:
        summary["finished_at"] = iso(now_utc())
        ledger.record_run(incident_id, run_id, **{**{k: v for k, v in summary.items() if k != "run_id"}, "started_at": started})
        ledger.release_run(lock)
    summary["budget"] = ledger.budget_for(incident_id)
    return summary

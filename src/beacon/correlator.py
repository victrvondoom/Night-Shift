"""Streaming change-to-symptom correlation, executed by Pathway.

    python -m beacon.correlator

Reads normalised events from NATS JetStream ``beacon.events`` (stream BEACON),
deduplicates redelivered events, joins a NetworkPolicy change with the
application/alert symptoms that follow it in the same namespace (and, when a
symptom names its dependency, the same target app) inside a bounded window, and
writes one correlation per change to ``beacon.correlations``.

The join is incremental and order independent: a late or out-of-order event
updates the existing correlation (Pathway retracts the old row and emits the new
one; ``correlation_id`` is deterministic so the backend upserts).  Temporal
proximity is *correlation*, never proof of causality, and ``strength`` is a
rule-based category, not a probability.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pathway as pw

logger = logging.getLogger("beacon.correlator")

RULE = "netpol_change_then_dependency_symptoms.v1"
SYMPTOMS = ("alert_firing", "db_connection_error")
STATE: dict[str, Any] = {
    "engine": "pathway",
    "pathway_version": pw.__version__,
    "started_at": time.time(),
    "events_seen": 0,
    "correlations_emitted": 0,
    "last_event_at": None,
    "last_correlation_at": None,
    "rule": RULE,
}


def window_seconds() -> int:
    return int(os.environ.get("CORRELATION_WINDOW_SECONDS", "600"))


def skew_seconds() -> int:
    return int(os.environ.get("CORRELATION_CLOCK_SKEW_SECONDS", "5"))


class EventRow(pw.Schema):
    event_id: str
    source: str
    event_type: str
    observed_at: str
    namespace: str
    resource_kind: str
    resource_name: str
    target_app: str
    run_id: str


JSON_PATHS = {
    "namespace": "/resource/namespace",
    "resource_kind": "/resource/kind",
    "resource_name": "/resource/name",
    "target_app": "/resource/target_app",
    "run_id": "/run_id",
}


def _ts(value: str) -> float:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC).timestamp()


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _explain(resource: str, types: tuple[str, ...], n: int, target: str) -> str:
    kinds = " + ".join(sorted(set(types))) or "no symptoms"
    rel = f" depending on {target}" if target else ""
    return (
        f"A write to {resource} was followed, in the same namespace{rel}, by {n} "
        f"symptom event(s) ({kinds}) inside the correlation window. This is a temporal "
        "and resource correlation, not a confirmed root cause."
    )


def _strength(types: tuple[str, ...]) -> str:
    s = set(types)
    if {"alert_firing", "db_connection_error"} <= s:
        return "STRONG"
    return "PARTIAL" if s else "CHANGE_ONLY_NO_SYMPTOM"


def _missing(types: tuple[str, ...]) -> list[str]:
    s = set(types)
    out = []
    if "alert_firing" not in s:
        out.append("no monitoring alert observed yet")
    if "db_connection_error" not in s:
        out.append("no application connection-error log observed yet")
    out.append("no confirmation that the changed policy is the root cause (hypothesis only)")
    return out


def build(events: pw.Table) -> pw.Table:
    """The correlation graph; pure Pathway transformations over the event stream."""
    # Redelivered events share an event_id: collapse them deterministically.
    uniq = events.groupby(events.event_id).reduce(
        event_id=pw.this.event_id,
        source=pw.reducers.min(events.source),
        event_type=pw.reducers.min(events.event_type),
        observed_at=pw.reducers.min(events.observed_at),
        namespace=pw.reducers.min(events.namespace),
        resource_kind=pw.reducers.min(events.resource_kind),
        resource_name=pw.reducers.min(events.resource_name),
        target_app=pw.reducers.min(events.target_app),
        run_id=pw.reducers.min(events.run_id),
    )
    uniq = uniq.with_columns(ts=pw.apply(_ts, pw.this.observed_at))
    changes = uniq.filter(pw.this.event_type == "networkpolicy_change")
    symptoms = uniq.filter(
        (pw.this.event_type == "alert_firing") | (pw.this.event_type == "db_connection_error")
    )
    win, skew = window_seconds(), skew_seconds()
    pairs = (
        changes.join(symptoms, changes.namespace == symptoms.namespace, changes.run_id == symptoms.run_id)
        .select(
            change_id=changes.event_id,
            change_ts=changes.ts,
            sym_id=symptoms.event_id,
            sym_type=symptoms.event_type,
            sym_ts=symptoms.ts,
            change_target=changes.target_app,
            sym_target=symptoms.target_app,
        )
        .filter(
            (pw.this.sym_ts >= pw.this.change_ts - skew)
            & (pw.this.sym_ts <= pw.this.change_ts + win)
            & ((pw.this.sym_target == "") | (pw.this.sym_target == pw.this.change_target))
        )
    )
    # A symptom is attributed to the *nearest preceding* change only, so a later change never
    # steals (and an older one never keeps) symptoms that follow a newer change.
    nearest = pairs.groupby(pw.this.sym_id).reduce(sym_id=pw.this.sym_id, best=pw.reducers.max(pw.this.change_ts))
    pairs = (
        pairs.join(nearest, pairs.sym_id == nearest.sym_id)
        .select(
            change_id=pairs.change_id,
            change_ts=pairs.change_ts,
            sym_id=pairs.sym_id,
            sym_type=pairs.sym_type,
            sym_ts=pairs.sym_ts,
            best=nearest.best,
        )
        .filter(pw.this.change_ts == pw.this.best)
    )
    grouped = pairs.groupby(pw.this.change_id).reduce(
        change_id=pw.this.change_id,
        sym_ids=pw.reducers.sorted_tuple(pw.this.sym_id),
        sym_types=pw.reducers.sorted_tuple(pw.this.sym_type),
        last_ts=pw.reducers.max(pw.this.sym_ts),
    )
    # a change with no symptom yet still appears (CHANGE_ONLY) so a late symptom updates it
    base = changes.select(
        change_id=pw.this.event_id,
        namespace=pw.this.namespace,
        resource=pw.apply(lambda ns, n: f"{ns}/{n}", pw.this.namespace, pw.this.resource_name),
        target_app=pw.this.target_app,
        change_ts=pw.this.ts,
        run_id=pw.this.run_id,
    )
    joined = base.join_left(grouped, base.change_id == grouped.change_id).select(
        change_id=base.change_id,
        namespace=base.namespace,
        resource=base.resource,
        target_app=base.target_app,
        change_ts=base.change_ts,
        run_id=base.run_id,
        sym_ids=pw.coalesce(grouped.sym_ids, ()),
        sym_types=pw.coalesce(grouped.sym_types, ()),
        last_ts=pw.coalesce(grouped.last_ts, base.change_ts),
    )
    return joined.select(
        correlation_id=pw.apply(lambda c: "cor-" + hashlib.sha256(c.encode()).hexdigest()[:16], pw.this.change_id),
        incident_id=pw.apply(lambda c: "INC-" + hashlib.sha256(c.encode()).hexdigest()[:10].upper(), pw.this.change_id),
        rule=RULE,
        change_event_id=pw.this.change_id,
        included_event_ids=pw.apply(lambda c, s: [c, *s], pw.this.change_id, pw.this.sym_ids),
        symptom_types=pw.apply(list, pw.this.sym_types),
        namespace=pw.this.namespace,
        resource=pw.this.resource,
        target_app=pw.this.target_app,
        window_start=pw.apply(_iso, pw.this.change_ts),
        window_end=pw.apply(_iso, pw.this.last_ts),
        window_seconds=win,
        run_id=pw.this.run_id,
        strength=pw.apply(_strength, pw.this.sym_types),
        explanation=pw.apply(
            lambda r, t, ids, tg: _explain(r, t, len(ids), tg),
            pw.this.resource, pw.this.sym_types, pw.this.sym_ids, pw.this.target_app,
        ),
        missing_evidence=pw.apply(_missing, pw.this.sym_types),
        engine="pathway",
    )


class _Health(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        body = json.dumps(
            {**STATE, "uptime_s": round(time.time() - STATE["started_at"], 1), "ok": True}
        ).encode()
        self.send_response(200 if self.path in ("/healthz", "/") else 404)
        self.send_header("content-type", "application/json")
        self.end_headers()
        self.wfile.write(body if self.path in ("/healthz", "/") else b"{}")

    def log_message(self, *a: object) -> None:
        pass


def _serve_health() -> None:
    port = int(os.environ.get("CORRELATOR_PORT", "9103"))
    srv = ThreadingHTTPServer(("0.0.0.0", port), _Health)  # noqa: S104
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    logger.info("correlator health on :%d", port)


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    uri = os.environ["NATS_URL"]
    import asyncio

    from beacon import eventbus

    consumer = os.environ.get("CORRELATOR_CONSUMER", "pathway-correlator")

    async def _ensure_stream() -> None:
        from nats.js.api import AckPolicy, ConsumerConfig, DeliverPolicy

        for attempt in range(30):  # NATS may still be starting
            try:
                nc, js = await eventbus.connect()
                # An explicit, pre-created durable pull consumer. Without it Pathway derives the name from its
                # sources, so two correlator processes would silently SHARE one consumer and split the stream.
                try:
                    await js.consumer_info(eventbus.STREAM, consumer)
                except Exception:
                    await js.add_consumer(eventbus.STREAM, ConsumerConfig(durable_name=consumer, filter_subject="beacon.events", ack_policy=AckPolicy.EXPLICIT, deliver_policy=DeliverPolicy.ALL))
                await nc.close()
                return
            except Exception as exc:
                logger.warning("waiting for NATS (%s): %s", attempt, exc)
                await asyncio.sleep(2)
        raise SystemExit("NATS JetStream unavailable")

    asyncio.run(_ensure_stream())
    events = pw.io.nats.read(
        uri,
        "beacon.events",
        schema=EventRow,
        format="json",
        json_field_paths=JSON_PATHS,
        jetstream_stream_name="BEACON",
        durable_consumer_name=consumer,
        autocommit_duration_ms=100,
        name="beacon-events",
    )

    def on_event(key: Any, row: dict[str, Any], time: int, is_addition: bool) -> None:
        if is_addition:
            STATE["events_seen"] += 1
            STATE["last_event_at"] = datetime.now(tz=UTC).isoformat()

    pw.io.subscribe(events, on_change=on_event)
    corr = build(events)

    def on_corr(key: Any, row: dict[str, Any], time: int, is_addition: bool) -> None:
        if is_addition:
            STATE["correlations_emitted"] += 1
            STATE["last_correlation_at"] = datetime.now(tz=UTC).isoformat()

    pw.io.subscribe(corr, on_change=on_corr)
    pw.io.nats.write(corr, uri, "beacon.correlations", format="json", jetstream_stream_name="BEACON")
    _serve_health()
    pw.run(monitoring_level=pw.MonitoringLevel.NONE)


if __name__ == "__main__":
    main()

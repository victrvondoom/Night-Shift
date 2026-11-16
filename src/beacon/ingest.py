"""Evidence ingestion: normalise -> NATS ``beacon.events`` -> ledger; Pathway -> ledger.

* ``publish_event``  runs in the API (webhooks) and puts one normalised event on the bus;
* ``on_event``       runs in the worker: persists the event idempotently;
* ``on_correlation`` runs in the worker: persists the Pathway correlation, opens the incident.
"""

from __future__ import annotations

import logging
from typing import Any

from beacon import eventbus
from beacon.evidence import ledger
from beacon.evidence.contracts import Correlation, NightShiftEvent, iso, now_utc

logger = logging.getLogger(__name__)
EVENTS = "beacon.events"
CORRELATIONS = "beacon.correlations"


async def publish_event(ev: NightShiftEvent, raw_body: str = "") -> str:
    """Retain the redacted source payload, then publish.  Returns the delivery path used."""
    if raw_body:
        from beacon import db

        db.put(ledger.payload_table(), ev.payload_reference, {"body": raw_body, "event_id": ev.event_id})
    if eventbus.url():
        await eventbus.publish(EVENTS, ev.model_dump(mode="json"), dedup_id=ev.event_id)
        return "nats"
    import asyncio

    await asyncio.to_thread(ledger.record_event, ev)  # no bus: persisted, never correlated
    return "direct"


async def on_event(payload: dict[str, Any]) -> None:
    ev = NightShiftEvent.model_validate(payload)
    import asyncio

    fresh = await asyncio.to_thread(ledger.record_event, ev)
    if fresh and ev.event_type == "remediation_applied":
        await asyncio.to_thread(ledger.attach_remediation_event, ev)
    logger.info("event %s %s %s", "stored" if fresh else "duplicate", ev.event_type, ev.event_id)


async def on_correlation(payload: dict[str, Any]) -> None:
    if int(payload.get("diff", 1)) < 1:
        return  # retraction of a previous row; the replacement (+1) carries the new state
    fields = {k: payload[k] for k in Correlation.model_fields if k in payload}
    fields["processed_at"] = iso(now_utc())
    corr = Correlation.model_validate(fields)
    import asyncio

    if await asyncio.to_thread(ledger.get_event, corr.change_event_id) is None:
        logger.warning("ignoring correlation %s: its change event is not in the ledger (reset or replay)", corr.correlation_id)
        return

    changed = await asyncio.to_thread(ledger.record_correlation, corr)
    logger.info("correlation %s %s (%s)", corr.correlation_id, corr.strength, "updated" if changed else "unchanged")

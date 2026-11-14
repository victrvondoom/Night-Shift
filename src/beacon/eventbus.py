"""NATS JetStream: the durable event bus between ingestion and the worker.

Subjects (stream ``BEACON``):

* ``beacon.alerts``  -- one firing Alertmanager alert per message
* ``beacon.changes`` -- Kubernetes audit events and GitHub webhooks

The API publishes and returns immediately; the worker consumes with durable
consumers and explicit acks, so an alert that arrives while the worker is
restarting is processed when it comes back rather than lost.
"""

from __future__ import annotations

import json
import logging
import os
from typing import TYPE_CHECKING, Any

import nats
from nats.js.api import RetentionPolicy, StreamConfig

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

logger = logging.getLogger(__name__)
STREAM = "BEACON"
ALERTS = "beacon.alerts"
CHANGES = "beacon.changes"


def url() -> str:
    return os.environ.get("NATS_URL", "")


async def connect() -> tuple[Any, Any]:
    nc = await nats.connect(url(), max_reconnect_attempts=-1)
    js = nc.jetstream()
    try:
        await js.add_stream(
            StreamConfig(
                name=STREAM,
                subjects=["beacon.>"],
                retention=RetentionPolicy.LIMITS,
                max_age=7 * 24 * 3600,
                duplicate_window=120,
            )
        )
    except Exception as exc:  # already exists with the same config, or a race
        logger.debug("add_stream: %s", exc)
    return nc, js


async def publish(subject: str, payload: dict[str, Any], *, dedup_id: str = "") -> None:
    """Publish one event; *dedup_id* makes a redelivered webhook a no-op."""
    nc, js = await connect()
    try:
        await js.publish(
            subject,
            json.dumps(payload, default=str).encode(),
            headers={"Nats-Msg-Id": dedup_id} if dedup_id else None,
        )
    finally:
        await nc.close()


async def consume(
    js: Any,
    subject: str,
    durable: str,
    handler: Callable[[dict[str, Any]], Awaitable[None]],
    *,
    max_deliver: int = 3,
) -> None:
    """Pull messages forever; ack on success, redeliver (bounded) on failure."""
    from nats.js.api import ConsumerConfig

    sub = await js.pull_subscribe(
        subject,
        durable=durable,
        stream=STREAM,
        config=ConsumerConfig(ack_wait=300, max_deliver=max_deliver),
    )
    while True:
        try:
            msgs = await sub.fetch(10, timeout=5)
        except (TimeoutError, nats.errors.TimeoutError):
            continue
        for msg in msgs:
            try:
                await handler(json.loads(msg.data.decode()))
                await msg.ack()
            except Exception:
                logger.exception("handler for %s failed", subject)
                await msg.nak(delay=10)

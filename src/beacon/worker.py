"""The Night Shift worker: Temporal activities + NATS consumers in one process.

Runs as the ``beacon-remediator`` service account, the only identity with RBAC
to patch NetworkPolicies and Deployments. The API never writes to the cluster.

    python -m beacon.worker
"""

from __future__ import annotations

import asyncio
import logging
import os
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from prometheus_client import start_http_server
from temporalio.client import Client
from temporalio.worker import Worker

from beacon import changes, eventbus, ingest, workflows

logger = logging.getLogger("beacon.worker")


async def _on_alert(event: dict[str, Any]) -> None:
    from beacon import handler

    result = await asyncio.to_thread(handler.handler, event, None)
    logger.info("alert handled: %s", result)


async def _on_change(event: dict[str, Any]) -> None:
    kind = str(event.get("kind") or "")
    row = (
        changes.from_audit_event(event.get("event") or {})
        if kind == "k8s_audit"
        else changes.from_github_event(kind, event.get("event") or {})
    )
    if row:
        await asyncio.to_thread(changes.record, row)


async def main() -> None:
    logging.basicConfig(level=logging.INFO)
    start_http_server(int(os.environ.get("WORKER_METRICS_PORT", "9102")))
    tasks = []
    if eventbus.url():
        _, js = await eventbus.connect()
        tasks += [
            eventbus.consume(js, eventbus.CHANGES, "ledger", _on_change),
            eventbus.consume(js, ingest.EVENTS, "evidence", ingest.on_event),
            eventbus.consume(js, ingest.CORRELATIONS, "correlations", ingest.on_correlation, max_deliver=5),
        ]
        if os.environ.get("LEGACY_TRIAGE", "true").lower() != "false":
            # the original Ollama/litellm triage path; the evidence workspace replaces it
            tasks.append(eventbus.consume(js, eventbus.ALERTS, "triage", _on_alert, max_deliver=2))
    if os.environ.get("REMEDIATION_MODE", "temporal") == "inline":
        # no Temporal server: the same remediation steps run in-process (labelled in /api/system/integrations)
        logger.info("worker up (inline remediation, no Temporal): nats=%s", eventbus.url())
        await asyncio.gather(*tasks)
        return
    client = await Client.connect(
        workflows._address(), namespace=workflows._namespace()
    )
    worker = Worker(
        client,
        task_queue=workflows.TASK_QUEUE,
        workflows=[workflows.RemediationWorkflow, workflows.StepWorkflow],
        activities=[workflows.remediate_step],
        activity_executor=ThreadPoolExecutor(max_workers=8),
    )
    logger.info("worker up: temporal=%s nats=%s", workflows._address(), eventbus.url())
    await asyncio.gather(worker.run(), *tasks)


if __name__ == "__main__":
    asyncio.run(main())

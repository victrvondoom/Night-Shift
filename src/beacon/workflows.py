"""The remediation loop as a durable Temporal workflow.

    dryrun -> require_approval -> execute -> (wait, verify)* -> resolve | escalate

Each step is an activity that calls the same function the inline loop uses
(``beacon.remediate``), so there is one implementation of every gate. Temporal
adds what a single process cannot: the loop survives a worker restart, each
activity has a timeout and bounded retries, and the workflow id is derived
from the approval id so starting the same approval twice is a no-op.

``execute`` is safe to retry because it is idempotent on the approval record:
the approval is consumed by one conditional UPDATE and the stored result is
replayed to any later attempt.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
from datetime import timedelta
from typing import Any

from temporalio import activity, workflow
from temporalio.client import Client
from temporalio.common import RetryPolicy, WorkflowIDReusePolicy
from temporalio.exceptions import WorkflowAlreadyStartedError

TASK_QUEUE = "beacon-remediation"


def _address() -> str:
    return os.environ.get("TEMPORAL_ADDRESS", "localhost:7233")


def _namespace() -> str:
    return os.environ.get("TEMPORAL_NAMESPACE", "default")


def workflow_id(approval_id: str) -> str:
    return f"remediate-{approval_id}"


@activity.defn(name="remediate_step")
def remediate_step(step: str, event: dict[str, Any]) -> dict[str, Any]:
    from beacon import remediate

    return remediate.handler({**event, "step": step}, None)


@workflow.defn(name="RemediationWorkflow")
class RemediationWorkflow:
    @workflow.run
    async def run(self, event: dict[str, Any]) -> dict[str, Any]:
        gate = RetryPolicy(maximum_attempts=3, initial_interval=timedelta(seconds=2))

        async def step(name: str, payload: dict[str, Any]) -> dict[str, Any]:
            return await workflow.execute_activity(
                remediate_step,
                args=[name, payload],
                start_to_close_timeout=timedelta(seconds=90),
                retry_policy=gate,
            )

        state: dict[str, Any] = dict(event)
        for stage, name in (
            ("dryrun", "dryrun"),
            ("approval", "require_approval"),
            ("execute", "execute"),
        ):
            payload = await step(name, event)
            state[stage] = {"Payload": payload}
            if not payload.get("ok"):
                await step("escalate", {"input": state})
                return {
                    "ok": False,
                    "final": "escalated",
                    "stage": stage,
                    "error": payload.get("error"),
                }

        executed_at = state["execute"]["Payload"]["executed_at"]
        attempts = 0
        max_attempts = int(event.get("verify_max_attempts") or 6)
        wait = float(event.get("verify_wait_seconds") or 30)
        while attempts < max_attempts:
            await asyncio.sleep(wait)  # a durable Temporal timer
            payload = await step(
                "verify", {**event, "executed_at": executed_at, "attempts": attempts}
            )
            attempts = int(payload.get("attempts", attempts + 1))
            state["verify"] = {"Payload": payload}
            if payload.get("ok"):
                await step("resolve", {"input": state})
                return {"ok": True, "final": "resolved", "attempts": attempts}
        await step("escalate", {"input": state})
        return {
            "ok": False,
            "final": "escalated",
            "stage": "verify",
            "attempts": attempts,
        }


@workflow.defn(name="StepWorkflow")
class StepWorkflow:
    """One read-only step (the proposal-time dry run) executed on the worker."""

    @workflow.run
    async def run(self, step: str, event: dict[str, Any]) -> dict[str, Any]:
        return await workflow.execute_activity(
            remediate_step,
            args=[step, event],
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=RetryPolicy(maximum_attempts=2),
        )


_SYNC_STEPS = frozenset({"dryrun", "diagnose"})


async def _run_step(step: str, payload: dict[str, Any]) -> dict[str, Any]:
    import uuid

    client = await Client.connect(_address(), namespace=_namespace())
    return dict(
        await client.execute_workflow(
            StepWorkflow.run,
            args=[step, payload],
            id=f"step-{step}-{uuid.uuid4()}",
            task_queue=TASK_QUEUE,
            execution_timeout=timedelta(seconds=45),
        )
    )


def run_step(step: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Run one side-effect-free step on the worker and wait for its result."""
    if step not in _SYNC_STEPS:
        raise ValueError(f"step {step!r} may not be run synchronously")
    if os.environ.get("REMEDIATION_MODE", "temporal") == "inline":
        from beacon import remediate

        return remediate.handler({**payload, "step": step}, None)
    return asyncio.run(_run_step(step, payload))


async def _start(payload: dict[str, Any]) -> str:
    client = await Client.connect(_address(), namespace=_namespace())
    wid = workflow_id(str(payload["approval_id"]))
    # the same approval started twice is a no-op: idempotent
    with contextlib.suppress(WorkflowAlreadyStartedError):
        await client.start_workflow(
            RemediationWorkflow.run,
            payload,
            id=wid,
            task_queue=TASK_QUEUE,
            execution_timeout=timedelta(minutes=30),
            id_reuse_policy=WorkflowIDReusePolicy.REJECT_DUPLICATE,
        )
    return wid


async def _describe(wid: str) -> dict[str, Any]:
    client = await Client.connect(_address(), namespace=_namespace())
    desc = await client.get_workflow_handle(wid).describe()
    return {
        "status": desc.status.name if desc.status else "UNKNOWN",
        "start": desc.start_time.isoformat() if desc.start_time else None,
        "stop": desc.close_time.isoformat() if desc.close_time else None,
    }


def start_remediation(payload: dict[str, Any]) -> str:
    """Start the loop for one approval; returns the execution id.

    ``REMEDIATION_MODE=inline`` runs the same steps in this process (tests and
    single-process runs); the default hands the loop to Temporal.
    """
    from beacon.remediation import registry

    wait, attempts = registry.verify_budget(str(payload.get("action", "")))
    payload = {
        **payload,
        "verify_wait_seconds": float(os.environ.get("VERIFY_WAIT_SECONDS", wait)),
        "verify_max_attempts": int(os.environ.get("VERIFY_MAX_ATTEMPTS", attempts)),
    }
    if os.environ.get("REMEDIATION_MODE", "temporal") == "inline":
        from beacon import remediate

        remediate.handler({**payload, "step": "all"}, None)
        return f"inline-{payload['approval_id']}"
    try:
        wid = asyncio.run(_start(payload))
    except Exception as exc:
        _health(False, type(exc).__name__)
        raise
    _health(True)
    return wid


def _health(ok: bool, category: str = "") -> None:
    try:
        from beacon import health_log

        health_log.record("temporal:workflow", ok, category)
    except Exception:  # bookkeeping must never break remediation
        pass


def describe(execution_id: str) -> dict[str, Any]:
    if execution_id.startswith("inline-"):
        return {"status": "COMPLETED", "start": None, "stop": None}
    return asyncio.run(_describe(execution_id))

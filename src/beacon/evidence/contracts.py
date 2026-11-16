"""Typed contracts for the one shared incident / evidence trail.

Every event keeps its original source id and timestamp.  Nothing here is a
probability: ``strength`` on a correlation is a rule-based category.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field

SCHEMA_VERSION = "nightshift.analysis.v1"


class SourceMode(StrEnum):
    LIVE = "LIVE"
    DEMO_SIMULATOR = "DEMO_SIMULATOR"


class EventType(StrEnum):
    NETPOL_CHANGE = "networkpolicy_change"
    ALERT_FIRING = "alert_firing"
    APP_ERROR = "db_connection_error"
    DEPLOYMENT = "deployment"
    HEALTH_OBSERVATION = "health_observation"
    REMEDIATION = "remediation_applied"
    OTHER_CHANGE = "other_change"


def now_utc() -> datetime:
    return datetime.now(tz=UTC)


def iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_ts(value: Any) -> datetime:
    """Parse a source timestamp to aware UTC; raises ValueError when absent/invalid."""
    if isinstance(value, datetime):
        return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)
    text = str(value or "").strip()
    if not text:
        raise ValueError("missing timestamp")
    dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    return dt.astimezone(UTC) if dt.tzinfo else dt.replace(tzinfo=UTC)


def stable_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("\x1f".join(parts).encode()).hexdigest()[:16]
    return f"{prefix}-{digest}"


class Resource(BaseModel):
    cluster: str = ""
    namespace: str = ""
    kind: str = ""  # NetworkPolicy | Service | Deployment | Alert | Log
    name: str = ""
    target_app: str = ""  # the workload the resource affects / depends on


class NightShiftEvent(BaseModel):
    event_id: str  # stable: sha256(source, source_event_id)
    source: Literal["kubernetes", "prometheus", "application", "github"]
    source_event_id: str
    incident_id: str = ""  # assigned when a correlation claims the event
    event_type: EventType
    observed_at: str  # source timestamp, UTC
    received_at: str
    resource: Resource
    severity: Literal["info", "warning", "critical"] = "info"
    summary: str = ""
    payload_reference: str = ""  # key into the retained, redacted source payload
    source_mode: SourceMode = SourceMode.LIVE
    trace_id: str = ""
    attributes: dict[str, str] = Field(default_factory=dict)  # safe labels only

    @property
    def observed_ts(self) -> float:
        return parse_ts(self.observed_at).timestamp()


class Correlation(BaseModel):
    """Output of the Pathway pipeline: a change grouped with the symptoms that followed."""

    correlation_id: str
    incident_id: str
    rule: str
    change_event_id: str
    included_event_ids: list[str]
    symptom_types: list[str]
    namespace: str
    resource: str  # ns/name of the changed object
    target_app: str
    window_start: str
    window_end: str
    window_seconds: int
    strength: Literal["CHANGE_ONLY_NO_SYMPTOM", "PARTIAL", "STRONG"]
    explanation: str
    status: Literal["CORRELATION"] = "CORRELATION"  # never "confirmed root cause"
    processed_at: str
    engine: str = "pathway"
    missing_evidence: list[str] = Field(default_factory=list)


class ResearchItem(BaseModel):
    query_id: str
    incident_id: str
    query: str
    provider: str = "tavily"
    title: str = ""
    url: str = ""
    excerpt: str = ""
    score: float | None = None  # provider search score, NOT a confidence
    published_date: str | None = None
    updated_date: str | None = None
    retrieved_at: str
    extraction_status: Literal["NOT_REQUESTED", "OK", "FAILED"] = "NOT_REQUESTED"
    classification: Literal[
        "SUPPORTS",
        "CONTRADICTS",
        "CONTEXT_ONLY",
        "UNVERIFIED",
        "STALE",
        "INSUFFICIENT_EVIDENCE",
    ] = "UNVERIFIED"
    classification_reason: str = ""
    evidence_id: str = ""


class Claim(BaseModel):
    text: str
    evidence_ids: list[str] = Field(default_factory=list)


class StructuredAnalysis(BaseModel):
    """The model's contract (validated server-side against real evidence ids)."""

    incident_summary: str
    root_cause_hypothesis: str
    supporting_event_ids: list[str]
    contradicting_event_ids: list[str] = Field(default_factory=list)
    external_evidence_ids: list[str] = Field(default_factory=list)
    what_is_confirmed: list[Claim]
    what_is_unknown: list[str]
    recommended_action_id: str | None = None
    reasoning_summary: str
    risk_summary: str
    requires_human_approval: bool = True


class ModelAnalysis(BaseModel):
    analysis_id: str
    incident_id: str
    origin: Literal["BIFROST_MODEL", "RULES_ONLY"]
    schema_version: str = SCHEMA_VERSION
    input_evidence_ids: list[str]
    evidence_set_hash: str
    structured: StructuredAnalysis | None = None
    bifrost_request_id: str | None = None
    provider: str | None = None
    model: str | None = None
    latency_ms: int | None = None
    usage: dict[str, int] | None = None
    cost: float | None = None
    attempts: int | None = None
    fallback_used: bool | None = None
    status: Literal["OK", "DOWNGRADED", "GATEWAY_ERROR"] = "OK"
    error_category: str | None = None
    downgrade_reasons: list[str] = Field(default_factory=list)
    created_at: str

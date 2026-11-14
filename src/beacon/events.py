from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from beacon.config import NightShiftConfig


class TriggerType(Enum):
    """How triage was triggered."""

    ALARM = "alarm"
    SCHEDULE = "schedule"
    SUBSCRIPTION = "subscription"


@dataclass(frozen=True, slots=True)
class TriggerInfo:
    """Parsed metadata about the event that triggered triage.

    For an Alertmanager alert, ``alarm_name`` is the ``alertname`` label and
    the full label/annotation sets ride along so verification can re-evaluate
    the same rule and probe the same health endpoint.
    """

    trigger_type: TriggerType
    log_group: str | None = None
    alarm_name: str | None = None
    alarm_reason: str | None = None
    raw_logs: str | None = None
    lookback_minutes: int | None = None
    alarm_time: str | None = None
    labels: dict[str, str] = field(default_factory=dict)
    annotations: dict[str, str] = field(default_factory=dict)

    def format_context(self) -> str:
        """Format trigger metadata into a human-readable context string."""
        parts: list[str] = [f"Trigger type: {self.trigger_type.value}"]
        if self.alarm_name:
            parts.append(f"Alert: {self.alarm_name}")
        if self.alarm_reason:
            parts.append(f"Reason: {self.alarm_reason}")
        if self.labels:
            shown = ", ".join(f"{k}={v}" for k, v in sorted(self.labels.items()))
            parts.append(f"Labels: {shown}")
        if self.trigger_type == TriggerType.SCHEDULE:
            parts.append("This is a scheduled scan, not triggered by a specific alert.")
        return "\n".join(parts)


def firing_alerts(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """The firing alerts in one Alertmanager webhook delivery (version 4)."""
    return [
        a
        for a in payload.get("alerts") or []
        if isinstance(a, dict) and a.get("status") == "firing"
    ]


def parse_event(event: dict[str, Any], config: NightShiftConfig) -> TriggerInfo:
    """Route a trigger to its parser.

    * ``{"alert": {...}}`` -- one Alertmanager alert (labels, annotations, startsAt)
    * ``{"logs": "...", "selector": "..."}`` -- log lines pushed directly
    * anything else -- a scheduled scan
    """
    alert = event.get("alert")
    if isinstance(alert, dict):
        labels = {str(k): str(v) for k, v in (alert.get("labels") or {}).items()}
        notes = {str(k): str(v) for k, v in (alert.get("annotations") or {}).items()}
        return TriggerInfo(
            trigger_type=TriggerType.ALARM,
            alarm_name=labels.get("alertname", "Unknown"),
            alarm_reason=notes.get("description") or notes.get("summary") or "",
            lookback_minutes=config.lookback_minutes,
            alarm_time=str(alert.get("startsAt") or "") or None,
            labels=labels,
            annotations=notes,
        )
    if "logs" in event:
        return TriggerInfo(
            trigger_type=TriggerType.SUBSCRIPTION,
            log_group=str(event.get("selector") or ""),
            raw_logs=str(event.get("logs") or ""),
        )
    return TriggerInfo(
        trigger_type=TriggerType.SCHEDULE, lookback_minutes=config.lookback_minutes
    )

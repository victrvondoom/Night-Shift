"""Parser for the RCA text contract produced by ``prompts/triage.txt``.

The triage model returns labelled sections (``STATUS:``, ``SUMMARY:``,
``EVIDENCE:`` ...) followed by an optional fenced ``BEACON_JSON:`` tail.
Everything downstream (handler, notifier, voice agent, dashboard) reads
the structured :class:`RcaJson` instead of scanning the raw text.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any

_SECTION_NAMES = (
    "STATUS",
    "SUMMARY",
    "AFFECTED COMPONENTS",
    "EVIDENCE",
    "NEXT STEPS",
    "CHANGE CORRELATION",
    "SPOKEN SUMMARY",
    "BEACON_JSON",
)

# Tolerates markdown emphasis around the label: ``**STATUS:** High``.
_HEADER_RE = re.compile(
    r"^\s*\**\s*(" + "|".join(_SECTION_NAMES) + r")\s*:?\s*\**\s*:?\s*(.*)$",
    re.IGNORECASE,
)
_LIST_PREFIX_RE = re.compile(r"^\s*(?:[-*•]|\d+[.)])\s*")
_FENCE_RE = re.compile(r"^\s*```")


@dataclass(slots=True)
class RcaJson:
    """Structured view of one triage response."""

    status: str = "Unknown"
    summary: str = ""
    affected_components: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    next_steps: list[str] = field(default_factory=list)
    change_correlation: str | None = None
    spoken_summary: str = ""
    beacon_json: dict[str, Any] = field(default_factory=dict)

    @property
    def fingerprint(self) -> str | None:
        value = self.beacon_json.get("fingerprint")
        return str(value) if value else None

    @property
    def suggested_action(self) -> str | None:
        value = self.beacon_json.get("suggested_action")
        return str(value) if value else None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _split_sections(text: str) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for raw_line in text.splitlines():
        match = _HEADER_RE.match(raw_line)
        if match:
            current = match.group(1).upper()
            sections.setdefault(current, [])
            rest = match.group(2).strip()
            if rest:
                sections[current].append(rest)
            continue
        if current is not None:
            sections[current].append(raw_line.rstrip())
    return sections


def _joined(lines: list[str]) -> str:
    return " ".join(line.strip() for line in lines if line.strip())


def _list_items(lines: list[str]) -> list[str]:
    items = [_LIST_PREFIX_RE.sub("", line).strip() for line in lines]
    return [item for item in items if item]


def _parse_json_tail(lines: list[str]) -> dict[str, Any]:
    body = "\n".join(line for line in lines if not _FENCE_RE.match(line)).strip()
    if not body:
        return {}
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def parse(text: str) -> RcaJson:
    """Parse triage output into an :class:`RcaJson`.

    Unstructured text (no recognised headers) is kept whole as the summary
    with ``status`` ``"Unknown"`` so callers never lose the model's words.
    """
    sections = _split_sections(text)
    if not sections:
        return RcaJson(summary=text.strip())

    status = _joined(sections.get("STATUS", [])) or "Unknown"
    components = [
        part.strip()
        for part in _joined(sections.get("AFFECTED COMPONENTS", [])).split(",")
        if part.strip()
    ]
    change = _joined(sections.get("CHANGE CORRELATION", [])) or None

    return RcaJson(
        status=status,
        summary=_joined(sections.get("SUMMARY", [])),
        affected_components=components,
        evidence=_list_items(sections.get("EVIDENCE", [])),
        next_steps=_list_items(sections.get("NEXT STEPS", [])),
        change_correlation=change,
        spoken_summary=_joined(sections.get("SPOKEN SUMMARY", [])),
        beacon_json=_parse_json_tail(sections.get("BEACON_JSON", [])),
    )


def is_healthy(text: str) -> bool:
    """Return True when the triage ``STATUS`` is ``Healthy``."""
    return parse(text).status.strip().lower() == "healthy"


def fallback_analysis(
    *,
    alarm_name: str | None,
    diagnostics: dict[str, Any] | None,
    changes: list[dict[str, Any]] | None,
    log_text: str,
    reason: str,
) -> str:
    """The RCA text contract written by code when the model is unavailable.

    Everything downstream (parser, incident, voice tools, console) reads the
    same headers, so an outage of the local model degrades triage to its deterministic
    sources instead of dropping the incident. The text says so plainly.
    """
    missing = (diagnostics or {}).get("missing_rules") or []
    services = (diagnostics or {}).get("deployments") or []
    sick = [
        s
        for s in services
        if s and s.get("status") == "ACTIVE" and not s.get("healthy")
    ]
    action = (diagnostics or {}).get("suggested_action") or ""
    change: dict[str, Any] | None = changes[0] if changes else None
    error_lines = [
        line.strip()
        for line in log_text.splitlines()
        if any(k in line for k in ("ERROR", "CRITICAL", " 5", "Traceback"))
    ]
    evidence = [line[:220] for line in error_lines[-6:]]  # the newest say most

    if missing:
        m = missing[0]
        target = f"{m.get('namespace')}/{m.get('name')}"
        summary = (
            f"The NetworkPolicy {target} is missing an ingress rule "
            f"({m.get('protocol')}/{m.get('port')} from app={m.get('from_app')}) "
            "that the golden snapshot says should exist; "
            "the service behind it cannot reach its dependency."
        )
        spoken = (
            "A network policy rule that the golden snapshot says should exist is "
            "missing, so the service can no longer reach its dependency. "
            "Restoring that one rule should bring it back."
        )
        status = "High"
        affected = target
        next_steps = [
            "Restore the missing ingress rule (networkpolicy.restore_ingress)."
        ]
    elif sick:
        d = sick[0]
        target = f"{d.get('namespace')}/{d.get('name')}"
        summary = (
            f"The Deployment {target} has {d.get('running')} of {d.get('desired')} "
            f"replicas available on revision {d.get('revision')}; the alert fired "
            "while its pods were unhealthy."
        )
        spoken = (
            "A deployment is running fewer healthy pods than it should after its "
            "latest rollout. Rolling it back to the previous revision should "
            "restore it."
            if action == "deployment.rollback"
            else "A deployment is running fewer healthy pods than it should. "
            "Restarting it should replace the unhealthy pods."
        )
        status = "High"
        affected = target
        next_steps = [f"Apply {action or 'deployment.restart'} to {target}."]
    else:
        summary = (
            f"Alarm {alarm_name or 'unknown'} fired; {len(error_lines)} error lines "
            "were found in the window, but no NetworkPolicy drift or unhealthy "
            "Deployment was detected."
        )
        spoken = (
            "The alarm fired and the logs show errors, but nothing in the "
            "deterministic checks points at a cause. A human should look."
        )
        status = "Medium" if error_lines else "Unknown"
        affected = ""
        next_steps = ["Investigate the error lines; no allowlisted fix applies."]

    correlation = (
        f"{change.get('event_name')} by {change.get('actor_short', 'unknown')} at "
        f"{change.get('event_time', '?')} on "
        f"{', '.join(change.get('resource_ids') or [])} shortly before the alarm."
        if change
        else "No write API calls were recorded before the alarm."
    )
    lines = [
        f"STATUS: {status}",
        f"SUMMARY: {summary}",
        f"AFFECTED COMPONENTS: {affected}",
        "EVIDENCE:",
        *[f"- {e}" for e in evidence],
        "NEXT STEPS:",
        *[f"- {s}" for s in next_steps],
        f"CHANGE CORRELATION: {correlation}",
        f"SPOKEN SUMMARY: {spoken}",
        (
            "NOTE: The model was unavailable ("
            + reason[:120]
            + "); this analysis comes from the deterministic checks only."
        ),
    ]
    return "\n".join(lines)

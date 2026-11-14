from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from beacon import channels
from beacon.events import TriggerType

if TYPE_CHECKING:
    from beacon.config import NightShiftConfig
    from beacon.events import TriggerInfo


def _trigger_label(trigger: TriggerInfo) -> str:
    """Return a short human-readable label for the trigger source."""
    if trigger.trigger_type == TriggerType.ALARM:
        return f"Alert: {trigger.alarm_name or 'Unknown'}"
    if trigger.trigger_type == TriggerType.SUBSCRIPTION:
        return "Log pattern match"
    return "Scheduled scan"


def _format_message(
    analysis: str,
    trigger: TriggerInfo,
    *,
    link: str = "",
    variant: str = "page",
    contract: dict[str, Any] | None = None,
) -> str:
    """Build the notification body: header, optional contract note, link, RCA."""
    header = [
        f"Trigger: {_trigger_label(trigger)}",
        f"Time: {datetime.now(tz=UTC).isoformat()}",
    ]
    if variant == "contract" and contract is not None:
        header.append(
            "Handled under Sleep Contract "
            f"{contract.get('contract_id')} (you were not woken). Night Shift is applying "
            f"{contract.get('action')} and will verify recovery; you get a second "
            "message when it is resolved or if a human is needed."
        )
        header.append(
            f'Contract granted by you: "{contract.get("transcript_quote", "")}"'
        )
    elif link:
        header.append(
            f"Night Shift is awaiting your word. Open the Night Board to talk to it: {link}"
        )
    if link and variant == "contract":
        header.append(f"Night Board: {link}")
    return "\n".join(header) + f"\n\n{analysis}"


def notify(
    analysis: str,
    trigger: TriggerInfo,
    config: NightShiftConfig,
    *,
    link: str = "",
    variant: str = "page",
    contract: dict[str, Any] | None = None,
) -> None:
    """Send the triage analysis to Slack, PagerDuty and Telegram (whichever are set).

    ``variant="contract"`` produces the "you were not woken" message.
    """
    message = _format_message(
        analysis, trigger, link=link, variant=variant, contract=contract
    )
    prefix = "Night Shift (not woken)" if variant == "contract" else "Night Shift"
    subject = f"{prefix} - {_trigger_label(trigger)}"[:100]
    channels.send("analysis", subject, message)

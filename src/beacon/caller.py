"""Ring the on-call engineer through Bolna telephony."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from beacon import bolna, store

if TYPE_CHECKING:
    from beacon.config import NightShiftConfig

logger = logging.getLogger(__name__)


def start_voice_call(incident_id: str, config: NightShiftConfig) -> str | None:
    """Place an outbound Bolna call about *incident_id*; returns the execution id.

    The call gets its own Night Shift voice session, so the agent's tool calls are
    bound to this incident exactly as a browser call's are. Failures are
    logged and return ``None``: the page in Slack/Telegram/PagerDuty already went out.
    """
    from beacon import voice_turn

    if not (config.oncall_phone and bolna.configured()):
        return None
    try:
        incident = store.get_incident(incident_id, config)
        session_id, token = voice_turn.new_voice_session(
            incident_id, channel="bolna-phone"
        )
        out = bolna.place_call(
            config.oncall_phone, voice_turn.user_data_for(incident, session_id, token)
        )
        execution_id = str(out.get("execution_id") or out.get("run_id") or "")
        from beacon import db

        db.patch("voice_calls", session_id, {"execution_id": execution_id})
        logger.info("Bolna call %s placed for incident %s", execution_id, incident_id)
        return execution_id or None
    except Exception:
        logger.exception("could not place the Bolna call for %s", incident_id)
        return None

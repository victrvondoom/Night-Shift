"""Outbound phone paging is not part of the OmniDimension integration.

Voice is a browser session the engineer starts from the incident workspace
(``POST /voice/omnidim/session``).  Paging still goes out through Slack,
Telegram and PagerDuty (``beacon.channels``); this module is kept only so the
handler's call site stays a no-op instead of silently dialling anyone.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from beacon.config import NightShiftConfig

logger = logging.getLogger(__name__)


def start_voice_call(incident_id: str, config: NightShiftConfig) -> str | None:
    if config.call_enabled:
        logger.info("phone calls are not supported with OmniDimension; open the console voice session")
    return None

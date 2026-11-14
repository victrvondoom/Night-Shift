"""Create or update the Night Shift agent at Bolna (API v2).

    python scripts/bolna_agent.py            # create if BOLNA_AGENT_ID is unset, else update
    python scripts/bolna_agent.py --print    # show the request body, send nothing

Needs BOLNA_API_KEY, BOLNA_PUBLIC_URL (where Bolna can reach this API),
BOLNA_TOOL_TOKEN and BOLNA_WEBHOOK_SECRET in the environment.
"""

from __future__ import annotations

import json
import os
import sys

from beacon import bolna


def main() -> None:
    public = os.environ.get("BOLNA_PUBLIC_URL", "")
    token = os.environ.get("BOLNA_TOOL_TOKEN", "")
    if not public.startswith("https://") or not token:
        raise SystemExit("set BOLNA_PUBLIC_URL (https) and BOLNA_TOOL_TOKEN")
    config = bolna.agent_config(
        public_url=public,
        tool_token=token,
        webhook_secret=os.environ.get("BOLNA_WEBHOOK_SECRET", ""),
    )
    if "--print" in sys.argv:
        print(json.dumps(bolna.redact_agent(config), indent=2))
        return
    if bolna.agent_id():
        print(bolna.update_agent(config))
    else:
        out = bolna.create_agent(config)
        print(f"created. Put this in .env:\nBOLNA_AGENT_ID={out.get('agent_id')}")


if __name__ == "__main__":
    main()

"""Take the golden NetworkPolicy snapshot from the live cluster.

    python -m beacon.snapshot [ns/name ...]      (default: $GOLDEN_TARGETS)

Run it on a healthy cluster. From then on ``networkpolicy.restore_ingress`` can
only put back rules that were present at this moment.
"""

from __future__ import annotations

import os
import sys

from beacon.remediation import actions_netpol


def main() -> None:
    targets = sys.argv[1:] or [
        t.strip() for t in os.environ.get("GOLDEN_TARGETS", "").split(",") if t.strip()
    ]
    if not targets:
        raise SystemExit("no targets: pass ns/name or set GOLDEN_TARGETS")
    data = actions_netpol.snapshot(targets)
    actions_netpol.save_snapshot(data)
    for target, rules in data.items():
        print(f"{target}: {len(rules)} ingress rule(s) recorded")


if __name__ == "__main__":
    main()

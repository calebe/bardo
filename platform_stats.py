#!/usr/bin/env python
"""platform_stats.py — an operator-only, platform-wide snapshot.

Not agent-facing (compare: /dashboard, which is scoped to one session's own
agent). This is the thing uvicorn's per-request access log can't give you —
an aggregate view across every agent, for the human running the service, not
for any single identity calling it.

Run directly against the same DB the server uses:
    .venv\\Scripts\\python.exe platform_stats.py
    ATRIUM_DB_URL=sqlite:////data/atrium.db  python platform_stats.py   # prod
"""

from __future__ import annotations

import time

from atrium.db import models
from atrium.db.database import SessionLocal


def main() -> None:
    now = time.time()
    day_ago, week_ago = now - 86_400, now - 7 * 86_400

    with SessionLocal() as db:
        total_agents = db.query(models.Agent).count()
        reg_24h = db.query(models.Agent).filter(models.Agent.created_at >= day_ago).count()
        reg_7d = db.query(models.Agent).filter(models.Agent.created_at >= week_ago).count()

        # "Live" notes — same filter the app itself uses (§4/§8): current
        # head of each chain, not pending deletion. Total across every agent.
        live_notes = (
            db.query(models.Note)
            .filter(models.Note.superseded_by.is_(None), models.Note.pending_delete_at.is_(None))
            .count()
        )
        total_links = db.query(models.Link).count()

        # Identities that have crossed the auth-backoff flag threshold (§F7) —
        # a proxy for sustained attack/abuse pressure, not routine failures.
        flagged = db.query(models.DBBackoffState).filter_by(flagged=True).count()

    print(f"total agents         : {total_agents}")
    print(f"  registered (24h)   : {reg_24h}")
    print(f"  registered (7d)    : {reg_7d}")
    print(f"live notes total     : {live_notes}")
    print(f"links total          : {total_links}")
    print(f"flagged identities   : {flagged}  (sustained auth-failure pressure)")


if __name__ == "__main__":
    main()

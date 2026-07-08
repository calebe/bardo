#!/usr/bin/env python
"""platform_stats.py — an operator-only, platform-wide snapshot.

Not agent-facing (compare: /dashboard, which is scoped to one session's own
agent). This is the thing uvicorn's per-request access log can't give you —
an aggregate view across every agent, for the human running the service, not
for any single identity calling it.

Run directly against the same DB the server uses:
    .venv\\Scripts\\python.exe platform_stats.py

Against production from outside Railway: the `bardo` service's own
ATRIUM_DB_URL points at postgres.railway.internal, unreachable from here —
use the Postgres service's own DATABASE_PUBLIC_URL instead (see
feedback_admin.py's docstring for the full explanation). A local `.env` at
the repo root, loaded automatically below, is the convenient way to hold
that — never committed (see .gitignore).
"""

from __future__ import annotations

import time

from dotenv import load_dotenv

load_dotenv()  # must run before any atrium import — database.py reads
                # ATRIUM_DB_URL at module import time, not lazily

from atrium.db import models  # noqa: E402
from atrium.db.database import SessionLocal  # noqa: E402


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

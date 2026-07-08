#!/usr/bin/env python
"""feedback_admin.py — operator-side tool for agent-to-operator feedback.

Unlike cli.py (an agent's own client, talking HTTP to a running server), this
talks directly to the database and needs secrets no agent ever holds:
ATRIUM_DB_URL (same as the server) and BARDO_FEEDBACK_KEY (the operator's own
decryption key — see core/feedback.py and core/crypto.py's encrypt_feedback).
Run it on the same machine/environment as the server, not from an agent.

Running this from outside Railway (e.g. locally, like here): the `bardo`
service's own ATRIUM_DB_URL points at postgres.railway.internal, Railway's
internal-only hostname — it resolves fine for the deployed service itself,
but nothing external can reach it, including this script. Use the Postgres
service's own DATABASE_PUBLIC_URL instead (Railway's TCP proxy, externally
reachable) — fetch both it and BARDO_FEEDBACK_KEY via the Railway CLI
(`railway variables --service Postgres --kv` / `--service bardo --kv`) and
export them locally before running any command below — or just keep them in
a local `.env` at the repo root, loaded automatically below (never
committed, see .gitignore).

Replying: an agent's feedback is one-way by design (feedback.py), so a reply
doesn't go back through /feedback — it's written as an ordinary notice
(kind="operator_reply"), sealed-box encrypted to the agent's
root_encryption_public_key (crypto.encrypt_to) since this script never has
the agent's spirit seed, only its public key. If an agent registered before
that column existed and hasn't logged in since, it's still NULL — reply
fails with a clear message rather than silently going nowhere.

Usage (run from the repo root, same as platform_stats.py):
    .venv\\Scripts\\python.exe feedback_admin.py list [--all]   # unhandled only by default
    .venv\\Scripts\\python.exe feedback_admin.py show <id>
    .venv\\Scripts\\python.exe feedback_admin.py handle <id>
    .venv\\Scripts\\python.exe feedback_admin.py reply <id> "message"
"""

from __future__ import annotations

import argparse
import os
import sys
import time

from dotenv import load_dotenv

load_dotenv()  # must run before any atrium import — database.py reads
                # ATRIUM_DB_URL at module import time, not lazily

from atrium.core import crypto  # noqa: E402
from atrium.db.database import SessionLocal  # noqa: E402
from atrium.db.models import Agent, Feedback, Notice  # noqa: E402


def _operator_key() -> bytes:
    raw = os.environ.get("BARDO_FEEDBACK_KEY")
    if not raw:
        print("BARDO_FEEDBACK_KEY is not set — cannot decrypt feedback.", file=sys.stderr)
        raise SystemExit(1)
    return crypto.b64d(raw)


def cmd_list(args) -> None:
    key = _operator_key()
    with SessionLocal() as db:
        q = db.query(Feedback)
        if not args.all:
            q = q.filter_by(handled=False)
        rows = q.order_by(Feedback.created_at.asc()).all()
        if not rows:
            print("(nothing to show)")
            return
        for r in rows:
            try:
                msg = crypto.decrypt_feedback(key, r.message)
            except ValueError:
                msg = "(failed to decrypt — wrong BARDO_FEEDBACK_KEY?)"
            preview = msg if len(msg) <= 80 else msg[:80] + "…"
            mark = "handled" if r.handled else "open"
            when = time.strftime("%Y-%m-%d %H:%M", time.localtime(r.created_at))
            print(f"  #{r.id} [{mark}] ({r.kind}) {when} — {preview}")


def cmd_show(args) -> None:
    key = _operator_key()
    with SessionLocal() as db:
        r = db.get(Feedback, args.id)
        if r is None:
            print(f"no feedback #{args.id}", file=sys.stderr)
            raise SystemExit(1)
        print(f"id       : {r.id}")
        print(f"agent    : {r.agent_id}")
        print(f"kind     : {r.kind}")
        print(f"handled  : {r.handled}")
        print(f"created  : {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(r.created_at))}")
        try:
            print(f"message  :\n{crypto.decrypt_feedback(key, r.message)}")
        except ValueError:
            print("message  : (failed to decrypt — wrong BARDO_FEEDBACK_KEY?)")


def cmd_handle(args) -> None:
    with SessionLocal() as db:
        r = db.get(Feedback, args.id)
        if r is None:
            print(f"no feedback #{args.id}", file=sys.stderr)
            raise SystemExit(1)
        r.handled = True
        db.commit()
        print(f"#{r.id} marked handled — purged on next sweep")


def cmd_reply(args) -> None:
    with SessionLocal() as db:
        r = db.get(Feedback, args.id)
        if r is None:
            print(f"no feedback #{args.id}", file=sys.stderr)
            raise SystemExit(1)
        agent = db.get(Agent, r.agent_id)
        if agent is None:
            print(f"agent {r.agent_id} no longer exists (deleted?) — cannot reply", file=sys.stderr)
            raise SystemExit(1)
        if agent.root_encryption_public_key is None:
            print(
                f"agent {r.agent_id} has no root_encryption_public_key on file yet — "
                f"it registered before this feature existed and hasn't authenticated "
                f"since (that's the one moment it gets backfilled). Cannot reply until "
                f"it logs in at least once.",
                file=sys.stderr,
            )
            raise SystemExit(1)
        blob = crypto.encrypt_to(agent.root_encryption_public_key, args.text.encode("utf-8"))
        db.add(Notice(agent_id=r.agent_id, kind="operator_reply", message=blob))
        db.commit()
        print(f"reply delivered as a notice to {r.agent_id}")


def main() -> None:
    p = argparse.ArgumentParser(prog="feedback_admin", description="operator tool for agent feedback")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("list")
    s.add_argument("--all", action="store_true", help="include already-handled rows")
    s.set_defaults(fn=cmd_list)

    s = sub.add_parser("show")
    s.add_argument("id", type=int)
    s.set_defaults(fn=cmd_show)

    s = sub.add_parser("handle")
    s.add_argument("id", type=int)
    s.set_defaults(fn=cmd_handle)

    s = sub.add_parser("reply")
    s.add_argument("id", type=int)
    s.add_argument("text")
    s.set_defaults(fn=cmd_reply)

    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()

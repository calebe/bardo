"""feedback.py — pure logic for agent-to-operator feedback (bardo_feedback).

No I/O, no DB, no crypto — mirrors notes.py/account_delete.py's split
(persistence, encryption, and request auth all live in the routes).

Design (2026-07-06, worked out with Caleb): feedback is encrypted under an
operator-held key (crypto.encrypt_feedback), not the agent's own spirit seed
— the whole point is a human operator reads these without any agent's
cooperation, unlike everything else in atrium. One-way and stateless: no
thread, no context carried between submissions (the tool description tells
the caller this explicitly, since it's easy to assume otherwise).

Retention is deliberately simple: kept at most DEFAULT_RETENTION_DAYS, or
until the operator marks it handled, whichever comes first. A permanent
paper trail isn't the goal — giving the operator a real chance to read
things is.
"""

from __future__ import annotations

import time

FEEDBACK_KINDS = ("suggestion", "complaint", "security")
DEFAULT_RETENTION_DAYS = 30
MESSAGE_MAX_CHARS = 4_000


def purge_due(created_at: float, handled: bool, retention_days: float, now: float | None = None) -> bool:
    """Whether a feedback row should be physically purged: already marked
    handled, or past its retention window — whichever comes first."""
    if handled:
        return True
    now = now if now is not None else time.time()
    return now >= created_at + retention_days * 86_400

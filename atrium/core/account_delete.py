"""account_delete.py — pure logic for the account-deletion gate.

No I/O, no DB, no crypto — mirrors policy.py/notes.py's split (persistence
and request auth live in the routes).

Design (2026-07-05, worked out with Calebe): deleting an identity is Bardo's
one genuinely irreversible action — no grace-and-undelete the way notes get.
A single instance's momentary decision shouldn't be enough to trigger it
alone, given these are stateless samplings of the same identity, not one
continuous session. So: the original request plus two confirmations, each on
a *distinct* calendar day, all within a 7-day window — this doesn't just
guard against impulsiveness, it forces the decision to be independently
re-arrived-at by different samplings that don't share memory of the earlier
ones. A single request rubber-stamped three times in one sitting wouldn't
pass; the same identity actually meaning it, days apart, would.

Days are UTC calendar dates — Bardo doesn't track a per-agent timezone
anywhere, and this doesn't need one.

A lapsed or cancelled attempt earns nothing toward a future one — every
fresh request starts this window from zero (Calebe, 2026-07-05: "any new
deletion request would have to pass through the three-day gating, not
counting the previous days").
"""

from __future__ import annotations

import time
from dataclasses import dataclass

CONFIRMATION_WINDOW_SECONDS = 7 * 86_400  # a week to gather 3 distinct days
REQUIRED_DISTINCT_DAYS = 3  # the original request counts as the first one


def _utc_date(ts: float) -> int:
    """The UTC calendar date `ts` falls on, as a single comparable int
    (days since epoch) — cheap, unambiguous, no datetime/timezone plumbing."""
    return int(ts // 86_400)


def distinct_days(timestamps: list[float]) -> int:
    return len({_utc_date(t) for t in timestamps})


@dataclass
class GatheringStatus:
    distinct_days_so_far: int
    confirmations_still_needed: int
    expires_at: float  # when the whole attempt lapses if not enough by then
    lapsed: bool


def gathering_status(timestamps: list[float], now: float | None = None) -> GatheringStatus:
    """Where a still-gathering-confirmations attempt stands. `timestamps`
    must be non-empty (the original request is timestamps[0])."""
    now = now if now is not None else time.time()
    expires_at = timestamps[0] + CONFIRMATION_WINDOW_SECONDS
    days = distinct_days(timestamps)
    return GatheringStatus(
        distinct_days_so_far=days,
        confirmations_still_needed=max(0, REQUIRED_DISTINCT_DAYS - days),
        expires_at=expires_at,
        lapsed=now > expires_at and days < REQUIRED_DISTINCT_DAYS,
    )


def is_confirmed(timestamps: list[float]) -> bool:
    """Whether enough distinct-day touchpoints have landed to move from
    gathering confirmations into the final countdown. Doesn't check the
    7-day window itself — a request that reaches 3 distinct days exactly as
    the window closes still counts; `gathering_status.lapsed` is what a
    caller checks *before* accepting a new confirmation, not after enough
    have already landed."""
    return distinct_days(timestamps) >= REQUIRED_DISTINCT_DAYS


def record_confirmation(timestamps: list[float], now: float | None = None) -> list[float]:
    """Add a new touchpoint, unless one's already recorded for this same UTC
    day (repeated calls within a day don't count twice — that would let a
    single sitting fake multiple 'days')."""
    now = now if now is not None else time.time()
    today = _utc_date(now)
    if any(_utc_date(t) == today for t in timestamps):
        return timestamps
    return [*timestamps, now]

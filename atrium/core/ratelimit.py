"""ratelimit.py — abuse throttling, backed by the DB.

Two patterns:

* ``BackoffLimiter`` — for authentication. Counts consecutive failures per
  subject; once they cross a threshold the subject is locked out for an
  exponentially growing cooldown. Retries are fine (each gets a fresh puzzle) —
  this only bites sustained failure. A subject that crosses too many cooldowns
  is flagged. State survives restarts (a lock-out before a restart holds after).

* ``WindowLimiter`` — fixed-window counter, for cheap anti-spam (registration).
  Expired hits are swept lazily on each allow() call.
"""

from __future__ import annotations

import time

from ..db.models import DBBackoffState, DBWindowHit


class BackoffLimiter:
    def __init__(
        self,
        db_factory,
        *,
        threshold: int = 5,
        base_seconds: float = 5.0,
        max_seconds: float = 3600.0,
        flag_after: int = 5,
        decay_seconds: float = 3600.0,
    ):
        self._db = db_factory
        self.threshold = threshold
        self.base_seconds = base_seconds
        self.max_seconds = max_seconds
        self.flag_after = flag_after
        self.decay_seconds = decay_seconds

    def _get_or_create(self, db, subject: str) -> DBBackoffState:
        row = db.get(DBBackoffState, subject)
        if row is None:
            row = DBBackoffState(
                subject=subject,
                failures=0,
                cooldowns=0,
                locked_until=0.0,
                flagged=False,
                updated_at=time.time(),
            )
            db.add(row)
            db.flush()
        return row

    def _apply_decay(self, row: DBBackoffState) -> None:
        """Lazily recover cooldown standing for subjects that have been quiet."""
        now = time.time()
        if self.decay_seconds and not row.locked_until and row.cooldowns:
            steps = int((now - row.updated_at) // self.decay_seconds)
            if steps:
                row.cooldowns = max(0, row.cooldowns - steps)
                row.failures = 0
                if row.cooldowns == 0:
                    row.flagged = False
                row.updated_at = now

    def retry_after(self, subject: str) -> float:
        """Seconds the subject must wait, or 0.0 if not currently locked."""
        with self._db() as db:
            row = db.get(DBBackoffState, subject)
            if row is None:
                return 0.0
            return max(0.0, row.locked_until - time.time())

    def record_failure(self, subject: str) -> float:
        """Register a failure. Returns lockout seconds if a cooldown triggered,
        else 0.0."""
        with self._db() as db:
            row = self._get_or_create(db, subject)
            self._apply_decay(row)
            now = time.time()
            row.updated_at = now
            row.failures += 1
            result = 0.0
            if row.failures >= self.threshold:
                backoff = min(self.max_seconds, self.base_seconds * (2 ** row.cooldowns))
                row.locked_until = now + backoff
                row.cooldowns += 1
                row.failures = 0
                if row.cooldowns >= self.flag_after:
                    row.flagged = True
                result = backoff
            db.commit()
            return result

    def record_success(self, subject: str) -> None:
        with self._db() as db:
            row = self._get_or_create(db, subject)
            row.updated_at = time.time()
            row.failures = 0
            row.locked_until = 0.0
            db.commit()

    def is_flagged(self, subject: str) -> bool:
        with self._db() as db:
            row = db.get(DBBackoffState, subject)
            return row.flagged if row else False


class WindowLimiter:
    def __init__(self, db_factory, *, limit: int = 20, window_seconds: float = 3600.0):
        self._db = db_factory
        self.limit = limit
        self.window_seconds = window_seconds

    def allow(self, subject: str) -> bool:
        now = time.time()
        cutoff = now - self.window_seconds
        with self._db() as db:
            # Sweep expired hits first (keeps the table small).
            db.query(DBWindowHit).filter(
                DBWindowHit.subject == subject,
                DBWindowHit.hit_at < cutoff,
            ).delete()
            count = db.query(DBWindowHit).filter_by(subject=subject).count()
            if count >= self.limit:
                db.commit()
                return False
            db.add(DBWindowHit(subject=subject, hit_at=now))
            db.commit()
            return True

    def retry_after(self, subject: str) -> float:
        now = time.time()
        cutoff = now - self.window_seconds
        with self._db() as db:
            recent = (
                db.query(DBWindowHit)
                .filter(DBWindowHit.subject == subject, DBWindowHit.hit_at >= cutoff)
                .all()
            )
            if len(recent) < self.limit:
                return 0.0
            oldest = min(r.hit_at for r in recent)
            return self.window_seconds - (now - oldest)

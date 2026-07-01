"""session.py — pending challenges and active sessions, backed by the DB.

This is the HSM boundary. Decrypted spirit seeds live in process memory only,
keyed by an opaque token — never written to disk, never returned over the wire
(except via the explicit export path). When a session expires or is revoked,
the seed is dropped.

The DB stores the session/challenge metadata (expiry, identifier, sliding TTL)
so that `revoke_all`, `list_sessions`, and similar ops work correctly and
survive concurrent requests. The seed dict is the only in-memory component; it
is wiped clean on every process start.

On process restart:
  - `pending_challenges` and `active_sessions` tables are wiped (seeds gone).
  - Agents that held live sessions must re-authenticate.

To scale beyond one process, replace the in-memory seed dict with a shared
secret store (Redis, KMS, etc.) — the DB schema stays as-is.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass

from . import crypto, puzzle
from ..db.models import DBActiveSession, DBPendingChallenge

SESSION_TOKEN_BYTES = 32
DEFAULT_SESSION_TTL = 3600  # sliding window, seconds
DEFAULT_MAX_LIFETIME = 86_400  # absolute cap (F5): 24h, even if kept warm
DEFAULT_CHALLENGE_TTL = 15
ARGON2_MAX_CONCURRENT = 4  # F7: bound parallel Argon2id ops to limit DoS amplification

# Process-global semaphore — one per process (correct for uvicorn single-worker).
# Multi-process deployments need this in Redis or a separate gate.
_argon2_sem = threading.Semaphore(ARGON2_MAX_CONCURRENT)


def _token() -> str:
    return crypto.b64e(os.urandom(SESSION_TOKEN_BYTES))


@dataclass
class PendingChallenge:
    challenge_id: str
    identifier: str
    spirit_seed: bytes          # in memory only; never written to DB
    expected: str
    expires_at: float
    attempts_left: int


@dataclass
class Session:
    token: str
    identifier: str
    spirit_seed: bytes          # in memory only; never written to DB
    created_at: float
    last_used_at: float
    expires_at: float
    ttl: int

    def public_view(self) -> dict:
        return {
            "token": self.token,
            "identifier": self.identifier,
            "created_at": self.created_at,
            "last_used_at": self.last_used_at,
            "expires_at": self.expires_at,
        }


class SessionStore:
    def __init__(self, db_factory, session_ttl: int = DEFAULT_SESSION_TTL,
                 max_lifetime: int = DEFAULT_MAX_LIFETIME):
        self.session_ttl = session_ttl
        self.max_lifetime = max_lifetime
        self._db = db_factory
        # In-memory seed stores. A lock guards both dicts.
        self._seeds: dict[str, bytes] = {}            # token → spirit_seed
        self._challenge_seeds: dict[str, bytes] = {}  # challenge_id → spirit_seed
        self._lock = threading.Lock()
        # Wipe ephemeral DB rows from any previous process run. The seeds died
        # with that process; these rows have no valid counterpart in memory.
        # Guard: on a brand-new DB the tables may not exist yet (migrations
        # haven't run). In that case there's nothing to clean up.
        try:
            with self._db() as db:
                db.query(DBPendingChallenge).delete()
                db.query(DBActiveSession).delete()
                db.commit()
        except Exception:
            pass

    # -- challenges -------------------------------------------------------- #

    def open_challenge(
        self,
        identifier: str,
        spirit_seed: bytes,
        *,
        ttl: int = DEFAULT_CHALLENGE_TTL,
        attempts: int = 4,
    ) -> puzzle.Puzzle:
        p = puzzle.generate(ttl_seconds=ttl)
        row = DBPendingChallenge(
            challenge_id=p.challenge_id,
            identifier=identifier,
            expected=p.expected,
            expires_at=time.time() + ttl,
            attempts_left=attempts,
        )
        with self._db() as db:
            db.add(row)
            db.commit()
        with self._lock:
            self._challenge_seeds[p.challenge_id] = spirit_seed
        return p

    def challenge_subject(self, challenge_id: str) -> str | None:
        """Identifier behind a pending challenge, for rate-limiting failures
        without consuming an attempt. None if unknown/expired."""
        with self._db() as db:
            row = db.get(DBPendingChallenge, challenge_id)
            if row is None or time.time() > row.expires_at:
                return None
            return row.identifier

    def solve_challenge(self, challenge_id: str, answer: str) -> PendingChallenge:
        """Return the (now consumed) PendingChallenge on success.

        Raises KeyError if unknown/expired, ValueError on wrong answer.
        A wrong answer burns one attempt; exhausting attempts drops the
        challenge entirely (the agent must restart with a new api_key present).
        """
        with self._db() as db:
            row = db.get(DBPendingChallenge, challenge_id)
            if row is None:
                raise KeyError("unknown or expired challenge")
            if time.time() > row.expires_at:
                db.delete(row)
                db.commit()
                with self._lock:
                    self._challenge_seeds.pop(challenge_id, None)
                raise KeyError("challenge expired")
            if not puzzle.check(row.expected, answer):
                row.attempts_left -= 1
                if row.attempts_left <= 0:
                    db.delete(row)
                    with self._lock:
                        self._challenge_seeds.pop(challenge_id, None)
                db.commit()
                raise ValueError("incorrect answer")
            # Success — consume it.
            pc = PendingChallenge(
                challenge_id=row.challenge_id,
                identifier=row.identifier,
                spirit_seed=b"",  # filled below, outside DB session
                expected=row.expected,
                expires_at=row.expires_at,
                attempts_left=row.attempts_left,
            )
            db.delete(row)
            db.commit()
        with self._lock:
            pc.spirit_seed = self._challenge_seeds.pop(challenge_id, b"")
        return pc

    # -- sessions ---------------------------------------------------------- #

    def create_session(
        self, identifier: str, spirit_seed: bytes, *, ttl: int | None = None
    ) -> Session:
        now = time.time()
        ttl = ttl or self.session_ttl
        token = _token()
        row = DBActiveSession(
            token=token,
            identifier=identifier,
            created_at=now,
            last_used_at=now,
            expires_at=now + ttl,
            ttl=ttl,
        )
        with self._db() as db:
            db.add(row)
            db.commit()
        with self._lock:
            self._seeds[token] = spirit_seed
        return Session(
            token=token,
            identifier=identifier,
            spirit_seed=spirit_seed,
            created_at=now,
            last_used_at=now,
            expires_at=now + ttl,
            ttl=ttl,
        )

    def get_session(self, token: str) -> Session:
        with self._db() as db:
            row = db.get(DBActiveSession, token)
            if row is None:
                raise KeyError("invalid session")
            now = time.time()
            if now > row.created_at + self.max_lifetime:
                db.delete(row)
                db.commit()
                with self._lock:
                    self._seeds.pop(token, None)
                raise KeyError("session reached absolute lifetime")
            if now > row.expires_at:
                db.delete(row)
                db.commit()
                with self._lock:
                    self._seeds.pop(token, None)
                raise KeyError("session expired")
            # Sliding window: push expiry out, capped at the absolute limit.
            row.last_used_at = now
            row.expires_at = min(now + row.ttl, row.created_at + self.max_lifetime)
            db.commit()
            snap = Session(
                token=row.token,
                identifier=row.identifier,
                spirit_seed=b"",  # filled below, outside DB session
                created_at=row.created_at,
                last_used_at=row.last_used_at,
                expires_at=row.expires_at,
                ttl=row.ttl,
            )
        with self._lock:
            snap.spirit_seed = self._seeds.get(token, b"")
        return snap

    def revoke_session(self, token: str) -> bool:
        with self._db() as db:
            row = db.get(DBActiveSession, token)
            if row is None:
                return False
            db.delete(row)
            db.commit()
        with self._lock:
            self._seeds.pop(token, None)
        return True

    def revoke_all(self, identifier: str) -> int:
        with self._db() as db:
            rows = db.query(DBActiveSession).filter_by(identifier=identifier).all()
            tokens = [r.token for r in rows]
            for row in rows:
                db.delete(row)
            db.commit()
        with self._lock:
            for t in tokens:
                self._seeds.pop(t, None)
        return len(tokens)

    def list_sessions(self, identifier: str) -> list[Session]:
        now = time.time()
        with self._db() as db:
            rows = (
                db.query(DBActiveSession)
                .filter_by(identifier=identifier)
                .filter(DBActiveSession.expires_at > now)
                .all()
            )
            with self._lock:
                return [
                    Session(
                        token=r.token,
                        identifier=r.identifier,
                        spirit_seed=self._seeds.get(r.token, b""),
                        created_at=r.created_at,
                        last_used_at=r.last_used_at,
                        expires_at=r.expires_at,
                        ttl=r.ttl,
                    )
                    for r in rows
                ]

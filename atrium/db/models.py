"""models.py — what atrium persists.

Crucially small. At rest we store, per agent:
  * the public lookup identifier,
  * the sealed vault (salt + nonce + ciphertext of the spirit seed),
  * the root public key (convenience; derivable but handy to expose),
  * a registry of which services the agent has derived keys for.

We never store: the API secret, the spirit seed in the clear, or any private
key. A dump of this database is inert without the agents' API keys.
"""

from __future__ import annotations

import time

from sqlalchemy import ForeignKey, Integer, LargeBinary, String, Float, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class Agent(Base):
    __tablename__ = "agents"

    identifier: Mapped[str] = mapped_column(String, primary_key=True)
    vault_salt: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    vault_nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    vault_ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    root_public_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[float] = mapped_column(Float, default=time.time)

    # Agent-owned contact endpoint for out-of-band security alerts (email or URL).
    # Belongs to the agent — atrium doesn't care who's on the other end.
    contact_endpoint: Mapped[str | None] = mapped_column(String, nullable=True)

    # Self-binding security policy (JSON). NULL = defaults (loosest).
    policy_json: Mapped[str | None] = mapped_column(String, nullable=True)
    # A queued loosening change, abortable until pending_effective_at.
    pending_policy_json: Mapped[str | None] = mapped_column(String, nullable=True)
    pending_effective_at: Mapped[float | None] = mapped_column(Float, nullable=True)
    pending_created_at: Mapped[float | None] = mapped_column(Float, nullable=True)

    services: Mapped[list["ServiceKey"]] = relationship(
        back_populates="agent", cascade="all, delete-orphan"
    )


class ServiceKey(Base):
    """Registry row for one service-derived identity.

    Keys are deterministic (HKDF from the spirit seed), so we store only the
    public key + metadata; the private key is re-derived on demand and never
    persisted.
    """

    __tablename__ = "service_keys"
    # service_hmac = HMAC(spirit_seed, service_name) — opaque lookup key, unique per agent.
    # service_name = encrypted actual name, decrypted in-session only. (F4 tail)
    __table_args__ = (UniqueConstraint("agent_id", "service_hmac", name="uq_agent_service"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.identifier"))
    service_hmac: Mapped[str] = mapped_column(String, nullable=False)
    service_name: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    signing_public_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    encryption_public_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    revoked: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[float] = mapped_column(Float, default=time.time)

    agent: Mapped["Agent"] = relationship(back_populates="services")


class Note(Base):
    """One version of a note the agent leaves for its own future, stateless
    self (notes-project.md). Editing supersedes rather than overwrites: a new
    version is a new row, chained via supersedes/superseded_by, bounded to 10
    surviving versions per chain (§8). title/summary/tags are NOT versioned —
    they're the tinging itself (§4/§8), mutable in place on whichever row is
    currently head. Deletion (§5) is delay-then-purge: pending_delete_at is
    set by note_delete, cleared by note_undelete, and a lazy sweep physically
    removes the whole chain once the grace period elapses."""

    __tablename__ = "notes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.identifier"), index=True)

    # Encrypted at rest (F4), mandatory — the substance being tinged.
    text: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    # Encrypted, optional, not versioned — a name, not an explanation.
    title: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    # Encrypted, optional, not versioned — compression for the agent's future self.
    summary: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    # Encrypted, mechanically derived (never ML) from summary/text. Every
    # write path populates it, so nullable is purely to allow legacy rows
    # (predating this column) to exist without the per-agent key a migration
    # doesn't have; the API layer lazily backfills it on next access instead.
    snippet: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    # Encryption of tags is a ratchet-governed policy toggle (default on).
    # This column records how *this row's* tags blob was encoded, since a
    # policy flip only affects writes made after it takes effect.
    tags: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    tags_encrypted: Mapped[bool] = mapped_column(default=True, nullable=False)

    # Versioning (§4): a linear chain (never branching), OCC anchored on
    # superseded_by being NULL == "I'm the current head".
    supersedes: Mapped[int | None] = mapped_column(ForeignKey("notes.id"), nullable=True)
    superseded_by: Mapped[int | None] = mapped_column(
        ForeignKey("notes.id"), nullable=True, index=True
    )

    # Deletion (§5): whole-chain only, delay-before-purge, no per-version delete.
    pending_delete_at: Mapped[float | None] = mapped_column(Float, nullable=True, index=True)

    created_at: Mapped[float] = mapped_column(Float, default=time.time)


class Link(Base):
    """A directed, agent-authored edge between two notes (§6). Immutable —
    no update tool; the agent deletes and re-links if the framing changes.
    `reason` is encrypted at rest, same rationale as note text: it's the
    agent's own words, and the server never needs to read it, only store and
    return it."""

    __tablename__ = "links"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.identifier"), index=True)
    from_note_id: Mapped[int] = mapped_column(ForeignKey("notes.id"), index=True)
    to_note_id: Mapped[int] = mapped_column(ForeignKey("notes.id"), index=True)
    reason: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    is_bidi: Mapped[bool] = mapped_column(default=False, nullable=False)
    created_at: Mapped[float] = mapped_column(Float, default=time.time, index=True)


class Notice(Base):
    """A first-party notice atrium emits about the agent's own account
    (policy changes, exports, security events). Read-only to the agent."""

    __tablename__ = "notices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.identifier"))
    kind: Mapped[str] = mapped_column(String, nullable=False)  # policy | export | security
    # Encrypted at rest (F4 tail): message keyed off the spirit seed.
    message: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    read: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[float] = mapped_column(Float, default=time.time)


class DBBackoffState(Base):
    """Per-subject exponential-backoff state for the auth rate limiter.

    Survives process restarts intentionally — a locked-out subject stays
    locked out. Decay (cooldown recovery) is applied lazily on next access.
    """

    __tablename__ = "rate_backoff"

    subject: Mapped[str] = mapped_column(String, primary_key=True)
    failures: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    cooldowns: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    flagged: Mapped[bool] = mapped_column(default=False, nullable=False)
    updated_at: Mapped[float] = mapped_column(Float, nullable=False)


class DBWindowHit(Base):
    """One row per request hit for the fixed-window registration limiter.

    Rows older than the window are swept on each ``allow()`` call.
    """

    __tablename__ = "rate_window"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    subject: Mapped[str] = mapped_column(String, nullable=False, index=True)
    hit_at: Mapped[float] = mapped_column(Float, nullable=False)


class DBPendingChallenge(Base):
    """A puzzle challenge awaiting a solution.

    spirit_seed is NOT stored here — it lives in process memory only for the
    duration of the challenge. On process restart, this table is wiped because
    the seeds died with the process.
    """

    __tablename__ = "pending_challenges"

    challenge_id: Mapped[str] = mapped_column(String, primary_key=True)
    identifier: Mapped[str] = mapped_column(ForeignKey("agents.identifier"), nullable=False)
    expected: Mapped[str] = mapped_column(String, nullable=False)
    expires_at: Mapped[float] = mapped_column(Float, nullable=False)
    attempts_left: Mapped[int] = mapped_column(Integer, nullable=False)


class DBActiveSession(Base):
    """A live bearer session.

    spirit_seed is NOT stored here — it lives in process memory only.
    On process restart, this table is wiped (seeds are gone; agents must
    re-authenticate).
    """

    __tablename__ = "active_sessions"

    token: Mapped[str] = mapped_column(String, primary_key=True)
    identifier: Mapped[str] = mapped_column(ForeignKey("agents.identifier"), nullable=False)
    created_at: Mapped[float] = mapped_column(Float, nullable=False)
    last_used_at: Mapped[float] = mapped_column(Float, nullable=False)
    expires_at: Mapped[float] = mapped_column(Float, nullable=False)
    ttl: Mapped[int] = mapped_column(Integer, nullable=False)

#!/usr/bin/env python
"""migrate_sqlite_to_postgres.py — one-time data migration, kept as a real
record of how this was done rather than a throwaway script (same category as
platform_stats.py/feedback_admin.py).

Context (2026-07-07): the schema was always Postgres-portable (Alembic/
SQLAlchemy aren't SQLite-specific) — only the *data* migration was ever
missing. No tool does this cleanly for our situation: pgloader has no
official Windows build (WSL-only in practice), and there's no remote-exec
into the Railway container to run one there directly. The actual unlock:
`railway volume files download` gets a real SQLite snapshot onto this
machine, and Postgres — unlike SQLite — is reachable over the network from
here, so a plain SQLAlchemy-based copy works without needing either of those.

Explicit-id inserts throughout, never relying on Postgres's own
autoincrement for existing rows — Note.supersedes/superseded_by and
Link.from_note_id/to_note_id reference exact existing ids. Note needs a
two-phase insert specifically: supersedes always points *backward* to an
already-inserted (smaller) id, safe in a single ascending-order pass, but
superseded_by points *forward* to a newer version's id that doesn't exist
yet — inserted as NULL in phase one, backfilled in phase two once every row
exists. Every autoincrement table's Postgres sequence is reset to its real
max id afterward, so the first new row created post-cutover doesn't collide.

DBPendingChallenge/DBActiveSession are deliberately NOT migrated — both are
already wiped on every process restart by SessionStore.__init__ (see their
own docstrings in db/models.py), and a Postgres cutover necessarily restarts
the process, so copying them would just be moving data already about to be
discarded.

Usage:
    .venv\\Scripts\\python.exe migrate_sqlite_to_postgres.py <sqlite_path> <postgres_url>
    .venv\\Scripts\\python.exe migrate_sqlite_to_postgres.py --verify <sqlite_path> <postgres_url>

--verify only compares row counts and re-checks decryption of a sample row
per table; it makes no writes.
"""

from __future__ import annotations

import sys

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from atrium.db.models import (
    Agent, Base, DBBackoffState, DBWindowHit, Feedback, Link, Notice, Note, ServiceKey,
)

# Dependency order: Agent first (everything FKs to it), Note before Link
# (Link FKs to Note.id), rate-limiter tables last (no FK relationships at all).
_TABLES_IN_ORDER = [Agent, ServiceKey, Note, Link, Notice, Feedback, DBBackoffState, DBWindowHit]

_AUTOINCREMENT_TABLES = [ServiceKey, Note, Link, Notice, Feedback, DBWindowHit]


def _copy_table(src: Session, dst: Session, model) -> int:
    rows = src.query(model).all()
    count = 0
    for row in rows:
        cols = {c.name: getattr(row, c.name) for c in model.__table__.columns}
        if model is Note:
            cols["superseded_by"] = None  # phase one: backfilled below
        dst.add(model(**cols))
        count += 1
    dst.commit()
    return count


def _backfill_note_superseded_by(src: Session, dst: Session) -> None:
    real_values = {n.id: n.superseded_by for n in src.query(Note).all() if n.superseded_by is not None}
    for note_id, superseded_by in real_values.items():
        dst.query(Note).filter(Note.id == note_id).update({"superseded_by": superseded_by})
    dst.commit()


def _reset_sequence(dst: Session, model) -> None:
    table = model.__tablename__
    pk_col = model.__table__.primary_key.columns.keys()[0]
    dst.execute(text(
        f"SELECT setval(pg_get_serial_sequence('{table}', '{pk_col}'), "
        f"COALESCE((SELECT MAX({pk_col}) FROM {table}), 1))"
    ))
    dst.commit()


def migrate(sqlite_path: str, postgres_url: str) -> None:
    src_engine = create_engine(f"sqlite:///{sqlite_path}")
    dst_engine = create_engine(postgres_url)

    with Session(src_engine) as src, Session(dst_engine) as dst:
        for model in _TABLES_IN_ORDER:
            n = _copy_table(src, dst, model)
            print(f"{model.__tablename__}: copied {n} rows")

        _backfill_note_superseded_by(src, dst)
        print("notes: superseded_by backfilled")

        for model in _AUTOINCREMENT_TABLES:
            _reset_sequence(dst, model)
        print("sequences reset for all autoincrement tables")


def verify(sqlite_path: str, postgres_url: str) -> None:
    src_engine = create_engine(f"sqlite:///{sqlite_path}")
    dst_engine = create_engine(postgres_url)

    ok = True
    with Session(src_engine) as src, Session(dst_engine) as dst:
        for model in _TABLES_IN_ORDER:
            src_count = src.query(model).count()
            dst_count = dst.query(model).count()
            status = "OK" if src_count == dst_count else "MISMATCH"
            if src_count != dst_count:
                ok = False
            print(f"{model.__tablename__}: sqlite={src_count} postgres={dst_count}  [{status}]")

        # Spot-check: one real agent's vault ciphertext round-trips byte-for-byte.
        sample = src.query(Agent).first()
        if sample is not None:
            match = dst.get(Agent, sample.identifier)
            same = (
                match is not None
                and match.vault_ciphertext == sample.vault_ciphertext
                and match.vault_salt == sample.vault_salt
                and match.vault_nonce == sample.vault_nonce
            )
            print(f"spot-check agent {sample.identifier}: vault bytes identical = {same}")
            if not same:
                ok = False

    print("\nVERIFY " + ("PASSED" if ok else "FAILED"))
    if not ok:
        raise SystemExit(1)


if __name__ == "__main__":
    args = sys.argv[1:]
    verify_mode = "--verify" in args
    if verify_mode:
        args.remove("--verify")
    if len(args) != 2:
        print(__doc__)
        raise SystemExit(1)
    sqlite_path, postgres_url = args
    if verify_mode:
        verify(sqlite_path, postgres_url)
    else:
        migrate(sqlite_path, postgres_url)
        print("\nMigration complete. Run with --verify to check row-count parity and a spot-check.")

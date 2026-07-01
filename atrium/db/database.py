"""database.py — engine + session factory.

SQLite for local use; point ATRIUM_DB_URL at PostgreSQL to go multi-user
without touching application code.

Schema management: Alembic owns the schema in all environments.
Run `alembic upgrade head` before starting the server (the run_*.ps1 scripts
and Dockerfile do this automatically). init_db() is kept only for the smoke
test, which needs a fresh throwaway schema without running migrations.
"""

from __future__ import annotations

import os

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from .models import Base

DB_URL = os.environ.get("ATRIUM_DB_URL", "sqlite:///atrium.db")

engine = create_engine(
    DB_URL,
    echo=False,
    connect_args={"check_same_thread": False} if DB_URL.startswith("sqlite") else {},
)

SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, class_=Session)


def init_db() -> None:
    Base.metadata.create_all(engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

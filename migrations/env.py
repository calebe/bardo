"""Alembic env.py — wired to atrium's engine and models.

Run migrations:
    alembic upgrade head          # apply all pending
    alembic downgrade -1          # roll back one
    alembic revision --autogenerate -m "describe change"   # create a new one

The DB URL is read from ATRIUM_DB_URL (same env var the app uses), falling
back to the sqlalchemy.url in alembic.ini.
"""
from __future__ import annotations

import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import engine_from_config, pool

# Make the atrium package importable when running alembic from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from atrium.db.models import Base  # noqa: E402 — needs sys.path patch above
from atrium.db.database import DB_URL  # noqa: E402

config = context.config

# Override the URL from the env var so alembic and the app always agree.
config.set_main_option("sqlalchemy.url", DB_URL)

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Emit SQL to stdout without a live connection."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Connect and apply migrations directly."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,  # required for SQLite ALTER TABLE support
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

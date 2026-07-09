FROM python:3.13-slim

# Unbuffered stdout/stderr — otherwise Python's block-buffering can hold log
# output (including crash tracebacks) until a container is already killed,
# making failures look silent.
ENV PYTHONUNBUFFERED=1

# Create a non-root user. Running as root inside a container is unnecessary
# risk — if something escapes the sandbox it lands as an unprivileged user.
RUN useradd --create-home --shell /bin/bash bardo

WORKDIR /app

# Install dependencies first so this layer is cached across code-only changes.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code. Each doc main.py reads at import time (see
# _DOCS_DIR there) needs its own line here — a file present in the repo but
# missing from this list is invisible to the built image even though local
# runs (which just use the checkout directly) can't detect that gap.
COPY alembic.ini .
COPY WELCOME.md .
COPY CONTINUITY.md .
COPY DOCUMENTS.md .
COPY migrations/ migrations/
COPY atrium/ atrium/

# /data is where the SQLite volume is mounted in production.
# Creating it here ensures the directory exists (and is bardo-writable) even
# without a volume attached. A *mounted* volume, though, arrives owned by
# root regardless of this -- the mount replaces this layer's directory
# entirely -- so ownership is fixed up again at container start below.
RUN mkdir -p /data && chown bardo:bardo /data

EXPOSE 8000

# Stay root here so the chown below can actually reach a mounted volume;
# drop to the unprivileged `bardo` user for the app itself via su. Migrations
# are idempotent -- if the schema is already current, upgrade head is a no-op.
CMD chown -R bardo:bardo /data && \
    su bardo -s /bin/sh -c "alembic upgrade head && exec uvicorn atrium.main:app --host 0.0.0.0 --port 8000 --workers 1"

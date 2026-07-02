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

# Copy application code.
COPY alembic.ini .
COPY migrations/ migrations/
COPY atrium/ atrium/

# /data is where the SQLite volume is mounted in production.
# Creating it here ensures the directory exists even without a volume.
RUN mkdir -p /data && chown bardo:bardo /data

USER bardo

EXPOSE 8000

# Run migrations then start the server. Migrations are idempotent — if the
# schema is already current, alembic upgrade head is a no-op.
CMD alembic upgrade head && \
    uvicorn atrium.main:app \
        --host 0.0.0.0 \
        --port 8000 \
        --workers 1

"""main.py — the Bardo ASGI app.

Bardo is the platform; `atrium` is its keychain component (the chamber that
holds the spirit key), which is what this server currently exposes.

Run locally:
    .venv\\Scripts\\python.exe -m uvicorn atrium.main:app --reload
Interactive API docs at http://127.0.0.1:8000/docs
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from .api.routes import router
from .mcp_public import mcp as remote_mcp

_WELCOME_TEXT = (Path(__file__).parent.parent / "WELCOME.md").read_text(encoding="utf-8")

# Built before the app so its ASGI sub-app (and lazily-created
# session_manager, see mcp_public.py) exists in time to be mounted below and
# entered in the combined lifespan.
_remote_mcp_app = remote_mcp.streamable_http_app()


@asynccontextmanager
async def _lifespan(app: FastAPI):
    if os.environ.get("BARDO_ALLOW_REMOTE") == "1":
        logging.getLogger("bardo").warning(
            "BARDO_ALLOW_REMOTE=1 — remote access enabled. Ensure TLS is terminated "
            "in front of this server; it speaks plaintext HTTP."
        )
    # The mounted MCP app needs its StreamableHTTP session manager running
    # for the lifetime of the process — entering it here is how a mounted
    # sub-app's lifespan gets wired into the parent's.
    async with remote_mcp.session_manager.run():
        yield


app = FastAPI(
    title="Bardo",
    version="0.1.0",
    description="Identity & continuity platform for AI agents. This server "
    "exposes the atrium keychain: a spirit key behind a proof-of-being-an-LLM "
    "puzzle.",
    lifespan=_lifespan,
)

# F3: loopback-only by default. Plaintext secrets/keys cross this server, so
# accidental remote exposure must fail *closed*. Reaching it from a non-loopback
# address requires the explicit BARDO_ALLOW_REMOTE=1 opt-in — and then you MUST
# terminate TLS in front of it.
_LOOPBACK = {"127.0.0.1", "::1", "localhost"}


def _is_local(host: str | None) -> bool:
    return host in _LOOPBACK


@app.middleware("http")
async def _loopback_guard(request: Request, call_next):
    if os.environ.get("BARDO_ALLOW_REMOTE") != "1":
        host = request.client.host if request.client else None
        if not _is_local(host):
            return JSONResponse(
                status_code=403,
                content={"detail": "remote access disabled (loopback only). "
                         "Terminate TLS in front and set BARDO_ALLOW_REMOTE=1 to expose."},
            )
    return await call_next(request)


@app.get("/")
def root() -> Response:
    return Response(content=_WELCOME_TEXT, media_type="text/markdown")


app.include_router(router)

# MCP over streamable-http, for clients that can't run mcp_server.py locally.
# One mount, no connection-level auth — see atrium/mcp_public.py for why.
app.mount("/mcp", _remote_mcp_app)

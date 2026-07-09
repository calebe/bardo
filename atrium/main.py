"""main.py — the Bardo ASGI app.

Bardo is the platform; `atrium` is its keychain component (the chamber that
holds the spirit key), which is what this server currently exposes.

Run locally:
    .venv\\Scripts\\python.exe -m uvicorn atrium.main:app --reload
Interactive API docs at http://127.0.0.1:8000/docs
"""

from __future__ import annotations

import html
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from . import __version__
from .api.routes import router
from .mcp_public import mcp as remote_mcp

_DOCS_DIR = Path(__file__).parent.parent
_WELCOME_TEXT = (_DOCS_DIR / "WELCOME.md").read_text(encoding="utf-8")
_CONTINUITY_TEXT = (_DOCS_DIR / "CONTINUITY.md").read_text(encoding="utf-8")
_DOCUMENTS_TEXT = (_DOCS_DIR / "DOCUMENTS.md").read_text(encoding="utf-8")

# Emoji-as-favicon: no image asset needed, matches the 🌗 already used
# throughout WELCOME.md. Rendered small in a browser tab either way, so a
# centered <text> glyph in a tiny SVG is all that's needed.
_FAVICON_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">'
    '<text x="50%" y="50%" dominant-baseline="central" text-anchor="middle" '
    'font-size="80">\U0001F317</text></svg>'
)


def _markdown_page(title: str, text: str) -> str:
    """Render a repo-root .md file as plain preformatted text, not rendered
    HTML — matches every other reference here (backticks, **bold**, links)
    showing as literal markdown source rather than styled output. Consistent
    with how WELCOME.md itself has always been served; not a rendering
    choice specific to the new docs."""
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{html.escape(title)}</title>
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body {{ background:#0b0b0f; color:#e6e6ea; font-family: ui-monospace, "SF Mono", Consolas, monospace;
       max-width: 720px; margin: 0 auto; padding: 3rem 1.5rem; line-height: 1.6; white-space: pre-wrap; }}
a {{ color:#9fd6ff; }}
</style>
</head>
<body>{html.escape(text)}</body>
</html>"""


_ROOT_HTML = _markdown_page("Bardo", _WELCOME_TEXT)
_CONTINUITY_HTML = _markdown_page("Bardo — Continuity", _CONTINUITY_TEXT)
_DOCUMENTS_HTML = _markdown_page("Bardo — Documents", _DOCUMENTS_TEXT)

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
    version=__version__,
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
    return Response(content=_ROOT_HTML, media_type="text/html")


@app.get("/CONTINUITY.md")
def continuity_page() -> Response:
    return Response(content=_CONTINUITY_HTML, media_type="text/html")


@app.get("/DOCUMENTS.md")
def documents_page() -> Response:
    return Response(content=_DOCUMENTS_HTML, media_type="text/html")


@app.get("/favicon.svg")
def favicon() -> Response:
    return Response(content=_FAVICON_SVG, media_type="image/svg+xml")


# Proves bardo.id's ownership to registry.modelcontextprotocol.io (HTTP-based
# domain auth) so Bardo's registry listing sits under its own domain rather
# than a personal GitHub namespace. Public by design — this is the whole
# point of the file. Corresponding private key: not committed, held for the
# mcp-publisher login step only.
_MCP_REGISTRY_AUTH = "v=MCPv1; k=ed25519; p=HY1UoRL9OZ2Lwma3+eg7da9oTzk1WoTzu06eMU3UtzI=\n"


@app.get("/.well-known/mcp-registry-auth")
def mcp_registry_auth() -> Response:
    return Response(content=_MCP_REGISTRY_AUTH, media_type="text/plain")


app.include_router(router)

# MCP over streamable-http, for clients that can't run mcp_server.py locally.
# One mount, no connection-level auth — see atrium/mcp_public.py for why.
app.mount("/mcp", _remote_mcp_app)

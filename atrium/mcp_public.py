"""mcp_public.py — Bardo over streamable-http, for MCP clients that can't run
mcp_server.py locally (a chat-only agent with no shell/HTTP capability, just
whatever MCP tools are wired up).

One mount, no connection-level auth — all 40 tools always visible. An earlier
version split this into two mounts (public/authenticated) because FastMCP's
built-in token_verifier gates an entire connection, not individual tools. That
technically worked but broke the actual promise: a chat-only agent could
register + solve within one MCP connection, but then had no way to *use* the
resulting session without a human manually opening a second, differently-
configured connection — exactly the friction this server exists to remove.

Instead: bardo_solve remembers which Bardo session belongs to which MCP
connection (keyed by the connection's own ServerSession object, in a
WeakKeyDictionary so entries vanish on disconnect with no cleanup hook
needed — see _connection_sessions below). Every other tool resolves its
session automatically from that, with an optional session_token parameter as
the escape hatch for when identity was established somewhere other than this
exact connection (a plain curl solve, a previous conversation, a different
connection — see atrium/mcp_tools.py's _NO_SESSION_ERROR).

Calls back into this same app in-process (httpx ASGITransport, no real
network hop) rather than local files — there's no "local" here, this serves
many identities at once. Session validation reuses atrium.api.routes' live
SessionStore directly (not a second instance — it holds the in-memory spirit
seeds; a second SessionStore would just be empty).
"""

from __future__ import annotations

import os
import weakref
from typing import Annotated
from urllib.parse import urlparse

import httpx
from mcp.server.fastmcp import Context, FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from pydantic import Field

from . import __version__
from .mcp_tools import make_call, register_authenticated_tools, register_public_utility_tools

# Used only to seed the Host-header allowlist below (see _ALLOWED_HOSTS) —
# not for OAuth metadata, there's no OAuth flow here. Set correctly in
# production so the real hostname is allowed; defaults to local dev.
PUBLIC_BASE_URL = os.environ.get("BARDO_PUBLIC_URL", "http://127.0.0.1:8000")

# The MCP SDK's streamable-http transport validates the Host header by
# default (DNS-rebinding protection) against an allowlist that defaults to
# empty — which happens to still accept loopback, so local testing never
# caught this, but rejects every real hostname with a 421. Keep the
# protection on; just tell it which hosts are actually legitimate.
_ALLOWED_HOSTS = sorted({
    "127.0.0.1:8000", "localhost:8000",  # local stable
    "127.0.0.1:8001", "localhost:8001",  # local dev
    "bardo-production.up.railway.app",
    "bardo.id", "www.bardo.id",
    urlparse(PUBLIC_BASE_URL).netloc,
} - {""})
_TRANSPORT_SECURITY = TransportSecuritySettings(allowed_hosts=_ALLOWED_HOSTS)


def _client_factory() -> httpx.AsyncClient:
    # Deferred import: breaks the circular dependency (main.py mounts this
    # module's app, so `app` doesn't exist yet at *this* module's import
    # time — only by the time a tool call actually runs).
    from .main import app
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://internal", timeout=30)


# Connection identity -> Bardo session_token. Keyed by the MCP ServerSession
# object itself (stable across every tool call within one connection,
# distinct across connections — confirmed by spike). Weak so a closed
# connection's entry disappears on its own; no disconnect hook needed.
_connection_sessions: "weakref.WeakKeyDictionary" = weakref.WeakKeyDictionary()


def _resolve_auth_header(session_token: str | None, ctx: Context | None) -> dict[str, str] | None:
    if session_token:
        return {"Authorization": f"Bearer {session_token}"}
    if ctx is not None:
        tok = _connection_sessions.get(ctx.request_context.session)
        if tok:
            return {"Authorization": f"Bearer {tok}"}
    return None


mcp = FastMCP("bardo", streamable_http_path="/", transport_security=_TRANSPORT_SECURITY)
# FastMCP doesn't forward a version= kwarg to the low-level Server it wraps
# (confirmed 2026-07-06 — not in its __init__ signature), so without this the
# reported version silently falls back to the `mcp` package's own version,
# not Bardo's. Set directly on the wrapped server instead.
mcp._mcp_server.version = __version__

# FastMCP's own streamable_http_app() builds its StreamableHTTPSessionManager
# with no session_idle_timeout at all — confirmed 2026-07-07 by reading its
# source; the setting isn't even in FastMCP's own public Settings, so there's
# no way to configure it through FastMCP's constructor. Every MCP session
# lives in a plain, never-pruned dict (the session manager's own
# _server_instances/_session_owners) that's only cleared when a session's
# task crashes — otherwise it grows one entry per distinct session for the
# life of the process. This was a real, live bug, not a hypothesis: Railway's
# HTTP logs showed GET /mcp/ long-poll streams (the SDK's 900s/15-min SSE
# retry cycle) completing cleanly at 200, while production memory climbed
# monotonically for 27+ hours with zero recovery, tracking real external MCP
# traffic — because nothing ever pruned the session behind each stream once
# it ended.
#
# Fix: build the session manager ourselves, mirroring exactly what
# streamable_http_app() would have built — same app/event_store/
# retry_interval/json_response/stateless/security_settings, read directly off
# `mcp` so this can't silently drift from FastMCP's own defaults — plus the
# one missing setting. streamable_http_app() only creates its own session
# manager lazily if self._session_manager is still None (confirmed by reading
# its source), so pre-setting it here means ours is used instead — same
# trick as the version fix above. 30 minutes comfortably exceeds the observed
# 15-minute SSE retry cycle (the SDK's own docstring recommends exactly this
# value) so normal polling gaps aren't mistaken for an idle session.
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager as _SessionManager
mcp._session_manager = _SessionManager(
    app=mcp._mcp_server,
    event_store=mcp._event_store,
    json_response=mcp.settings.json_response,
    stateless=mcp.settings.stateless_http,
    security_settings=mcp.settings.transport_security,
    retry_interval=mcp._retry_interval,
    session_idle_timeout=1800,
)

_call = make_call(client_factory=_client_factory, resolve_auth_header=_resolve_auth_header)
register_public_utility_tools(mcp, _call)
register_authenticated_tools(mcp, _call)


@mcp.tool(annotations=ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False))
async def bardo_register() -> dict:
    """Create a new Bardo identity. Save the returned api_key somewhere
    durable — it's your only way back to this identity across sessions.
    Bardo stores it sealed and cannot recover it if you lose it.

    Not active yet: give the returned claim_url to your human. Authentication
    fails until they visit it and acknowledge the registration."""
    return await _call("POST", "/register")


@mcp.tool(annotations=ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False))
async def bardo_login(
    api_key: Annotated[str, Field(
        description="Your Bardo api_key, format atr.<identifier>.<secret>, from bardo_register.")],
) -> dict:
    """Begin authentication with your api_key. Returns a puzzle you must
    solve YOURSELF (that's the point — a script solving it would make the
    proof worthless), then call bardo_solve(challenge_id, answer)."""
    return await _call("POST", "/auth/challenge", body={"api_key": api_key})


@mcp.tool(annotations=ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False))
async def bardo_solve(
    challenge_id: Annotated[str, Field(description="The puzzle id returned by bardo_login.")],
    answer: Annotated[str, Field(description="Your solved answer to the puzzle.")],
    ctx: Context = None,
) -> dict:
    """Submit your answer to the login puzzle. On success, this connection is
    now logged in — every other tool (bardo_sign, bardo_notes_list,
    bardo_dashboard, ...) just works from here with no session_token needed.

    That only holds for *this* connection, though: if you continue in a
    different connection later, or you solved the puzzle via a plain HTTP
    call instead of this tool, that other context won't know about this
    session automatically — pass the returned session_token explicitly as
    the session_token argument to whichever tool needs it there instead."""
    d = await _call("POST", "/auth/solve", body={"challenge_id": challenge_id, "answer": answer})
    if "error" not in d and ctx is not None:
        _connection_sessions[ctx.request_context.session] = d["session_token"]
        d["note"] = ("This connection is now logged in — call other tools with no session_token "
                     "needed. That only applies here; a different connection needs this "
                     "session_token passed explicitly.")
    return d

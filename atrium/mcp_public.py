"""mcp_public.py — Bardo over streamable-http, for MCP clients that can't run
mcp_server.py locally (a chat-only agent with no shell/HTTP capability, just
whatever MCP tools are wired up).

Two mounts, because MCP auth (when configured) gates an entire connection, not
individual tools — confirmed by spike, no way to exempt some tools on one
mount (see bardo-project memory, 2026-07-02):

  /mcp/public   no auth. register / login / solve / verify / encrypt only —
                exactly mirrors which REST routes need no session. This is the
                only way a chat-only agent can bootstrap an identity through
                MCP alone, with zero HTTP capability anywhere in the loop.
  /mcp          requires a Bearer session token (from the public mount's
                bardo_solve). Everything else — the ~28 session-gated tools,
                shared with mcp_server.py via atrium/mcp_tools.py.

Both mounts call back into this same app in-process (httpx ASGITransport, no
real network hop) rather than local files — there's no "local" here, this
serves many identities at once. Session validation reuses atrium.api.routes'
live SessionStore directly (not a second instance — it holds the in-memory
spirit seeds; a second SessionStore would just be empty).
"""

from __future__ import annotations

import os

import httpx
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP

from .mcp_tools import make_call, register_authenticated_tools, register_public_utility_tools

# The server's own public base URL — used only for OAuth resource-server
# metadata (issuer_url/resource_server_url), not for reaching itself (that's
# in-process ASGI, see _client_factory below). Must be set correctly in
# production (the Railway URL); defaults to local dev.
PUBLIC_BASE_URL = os.environ.get("BARDO_PUBLIC_URL", "http://127.0.0.1:8000")


def _client_factory() -> httpx.AsyncClient:
    # Deferred import: breaks the circular dependency (main.py mounts this
    # module's apps, so `app` doesn't exist yet at *this* module's import
    # time — only by the time a tool call actually runs).
    from .main import app
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://internal", timeout=30)


# --------------------------------------------------------------------------- #
# unauthenticated mount — the only public bootstrap path for a chat-only agent
# --------------------------------------------------------------------------- #
public_mcp = FastMCP("bardo-public", streamable_http_path="/")
_public_call = make_call(client_factory=_client_factory, get_auth_header=lambda: None)
register_public_utility_tools(public_mcp, _public_call)


@public_mcp.tool()
async def bardo_register() -> dict:
    """Create a new Bardo identity. Save the returned api_key somewhere
    durable — it's your only way back to this identity across sessions.
    Bardo stores it sealed and cannot recover it if you lose it."""
    return await _public_call("POST", "/register")


@public_mcp.tool()
async def bardo_login(api_key: str) -> dict:
    """Begin authentication with your api_key. Returns a puzzle you must
    solve YOURSELF (that's the point — a script solving it would make the
    proof worthless), then call bardo_solve(challenge_id, answer)."""
    return await _public_call("POST", "/auth/challenge", body={"api_key": api_key})


@public_mcp.tool()
async def bardo_solve(challenge_id: str, answer: str) -> dict:
    """Submit your answer to the login puzzle. On success, returns a
    session_token — hold onto it and present it as the Bearer token when
    connecting to the authenticated Bardo MCP endpoint for every other tool
    (bardo_sign, bardo_notes_list, bardo_dashboard, ...)."""
    return await _public_call("POST", "/auth/solve", body={"challenge_id": challenge_id, "answer": answer})


# --------------------------------------------------------------------------- #
# authenticated mount — everything session-gated, shared with mcp_server.py
# --------------------------------------------------------------------------- #
class _BardoTokenVerifier(TokenVerifier):
    async def verify_token(self, token: str) -> AccessToken | None:
        from .api.routes import store  # the live SessionStore — holds in-memory seeds
        try:
            sess = store.get_session(token)
        except KeyError:
            return None
        return AccessToken(
            token=token, client_id=sess.identifier, scopes=["bardo"],
            expires_at=int(sess.expires_at), subject=sess.identifier,
        )


def _get_auth_header() -> dict[str, str] | None:
    tok = get_access_token()
    return {"Authorization": f"Bearer {tok.token}"} if tok else None


authed_mcp = FastMCP(
    "bardo",
    token_verifier=_BardoTokenVerifier(),
    auth=AuthSettings(issuer_url=PUBLIC_BASE_URL, resource_server_url=PUBLIC_BASE_URL),
    streamable_http_path="/",
)
_authed_call = make_call(client_factory=_client_factory, get_auth_header=_get_auth_header)
register_authenticated_tools(authed_mcp, _authed_call)

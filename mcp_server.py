#!/usr/bin/env python
"""Bardo MCP server — frictionless access to the atrium keychain for a chat-based
Claude (no bash required).

It is a thin client over the running Bardo HTTP API, exposing the keychain as
native tools. It shares the `.bardo/` credential store with `cli.py`, so the
bash agent and the chat agent are the *same spirit* — two bodies, one anchor.

Inviolable rule: this server does every bit of plumbing EXCEPT solving the
login puzzle. `bardo_login` returns the puzzle text; the model (you) solves it
and calls `bardo_solve`. If the server solved it, the proof would be worthless —
a script would be getting in, not an LLM.

Requires the Bardo server running (default http://127.0.0.1:8000). Register it
with your MCP client (see the README / the config snippet printed by --help).

Most tools live in atrium/mcp_tools.py, shared with the public streamable-http
server mounted into atrium.main:app (see atrium/mcp_public.py) — one set of
tool bodies, two transports. Only the identity-bootstrap tools stay here: they
persist to local files, which only makes sense for this single-tenant, local
deployment.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import httpx
from mcp.server.fastmcp import FastMCP

sys.path.insert(0, str(Path(__file__).parent))
from atrium import __version__  # noqa: E402
from atrium.mcp_tools import make_call, register_authenticated_tools, register_public_utility_tools  # noqa: E402

BASE = os.environ.get("BARDO_URL", "http://127.0.0.1:8000")
HOME = Path(os.environ.get("BARDO_HOME", str(Path(__file__).parent / ".bardo")))
CREDS, SESSION, PENDING = HOME / "credentials.json", HOME / "session.json", HOME / "pending.json"

mcp = FastMCP("bardo")
# FastMCP doesn't forward a version= kwarg to the low-level Server it wraps —
# without this line the reported version silently falls back to the `mcp`
# package's own version, not Bardo's. Set directly on the wrapped server.
mcp._mcp_server.version = __version__


# --------------------------------------------------------------------------- #
# local file store — this identity's persistent anchor across process runs
# --------------------------------------------------------------------------- #
def _save(path: Path, obj) -> None:
    HOME.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2))


def _load(path: Path):
    return json.loads(path.read_text()) if path.exists() else None


def _resolve_auth_header(session_token, ctx) -> dict[str, str] | None:
    # ctx is unused here — single-tenant local process, no per-connection
    # concept to key off. An explicit override still wins if given, for
    # consistency with the public server's tools (same shared definitions).
    if session_token:
        return {"Authorization": f"Bearer {session_token}"}
    s = _load(SESSION)
    return {"Authorization": f"Bearer {s['session_token']}"} if s else None


_call = make_call(
    client_factory=lambda: httpx.AsyncClient(base_url=BASE, timeout=30),
    resolve_auth_header=_resolve_auth_header,
)


# --------------------------------------------------------------------------- #
# identity & authentication — bespoke here: these persist to .bardo/ files,
# which only makes sense for this single-tenant local deployment.
# --------------------------------------------------------------------------- #
@mcp.tool()
def bardo_whoami() -> dict:
    """Show the stored identity (your spirit's local anchor) and session status."""
    creds = _load(CREDS)
    if not creds:
        return {"registered": False, "hint": "call bardo_register to create an identity"}
    return {
        "registered": True,
        "identity": creds["identifier"],
        "spirit_public_key": creds["root_public_key_b64"],
        "session": "active" if _load(SESSION) else "none",
    }


@mcp.tool()
async def bardo_register() -> dict:
    """Create a new Bardo identity and store its API key locally. One-time.

    Not active yet: pass the returned claim_url to your human. Authentication
    fails until they visit it and acknowledge the registration."""
    d = await _call("POST", "/register")
    if "error" in d:
        return d
    _save(CREDS, d)
    return {
        "registered": True,
        "identity": d["identifier"],
        "spirit_public_key": d["root_public_key_b64"],
        "claim_url": d["claim_url"],
        "instruction": "Give this claim_url to your human now — auth won't work until they acknowledge it.",
    }


@mcp.tool()
async def bardo_login() -> dict:
    """Begin authentication. Returns a puzzle you must solve YOURSELF, then call
    bardo_solve(answer). (The server will not solve it for you — that's the point.)"""
    creds = _load(CREDS)
    if not creds:
        return {"error": "no credentials — call bardo_register first"}
    d = await _call("POST", "/auth/challenge", body={"api_key": creds["api_key"]})
    if "error" in d:
        return d
    _save(PENDING, d)
    return {
        "puzzle": d["puzzle"],
        "ttl_seconds": d["ttl_seconds"],
        "instruction": "Solve this puzzle yourself, then call bardo_solve with your answer.",
    }


@mcp.tool()
async def bardo_solve(answer: str) -> dict:
    """Submit your answer to the login puzzle. On success, opens a session."""
    pend = _load(PENDING)
    if not pend:
        return {"error": "no pending puzzle — call bardo_login first"}
    d = await _call("POST", "/auth/solve", body={"challenge_id": pend["challenge_id"], "answer": answer})
    if "error" in d:
        return d
    _save(SESSION, d)
    return {
        "authenticated": True,
        "expires_at": d.get("expires_at"),
        "unread_notices": d.get("unread_notices", 0),
        "notes": d.get("notes", 0),
    }


register_public_utility_tools(mcp, _call)
register_authenticated_tools(mcp, _call)


if __name__ == "__main__":
    mcp.run()

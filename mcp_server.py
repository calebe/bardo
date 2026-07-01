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
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import httpx
from mcp.server.fastmcp import FastMCP

BASE = os.environ.get("BARDO_URL", "http://127.0.0.1:8000")
HOME = Path(os.environ.get("BARDO_HOME", str(Path(__file__).parent / ".bardo")))
CREDS, SESSION, PENDING = HOME / "credentials.json", HOME / "session.json", HOME / "pending.json"

mcp = FastMCP("bardo")


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _save(path: Path, obj) -> None:
    HOME.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2))


def _load(path: Path):
    return json.loads(path.read_text()) if path.exists() else None


def _call(
    method: str, path: str, *, auth: bool = False,
    body: dict | None = None, params: dict | None = None,
):
    """Make an HTTP call to Bardo. Returns parsed JSON, or {'error': ...}."""
    headers = {}
    if auth:
        s = _load(SESSION)
        if not s:
            return {"error": "no session — call bardo_login, solve the puzzle, then bardo_solve"}
        headers["Authorization"] = f"Bearer {s['session_token']}"
    if params:
        params = {k: v for k, v in params.items() if v is not None}
    try:
        with httpx.Client(base_url=BASE, timeout=30) as c:
            r = c.request(method, path, json=body, params=params, headers=headers)
    except httpx.HTTPError as e:
        return {"error": f"cannot reach Bardo at {BASE}: {e}"}
    if r.status_code == 401:
        return {"error": "session invalid/expired — call bardo_login again"}
    if r.status_code == 429:
        return {"error": f"rate limited: {r.text}"}
    if r.status_code == 409:
        try:
            return {"error": "conflict", "detail": r.json().get("detail")}
        except ValueError:
            return {"error": "conflict", "detail": r.text}
    if r.status_code >= 400:
        return {"error": f"{r.status_code}: {r.text}"}
    return r.json() if r.content else {}


# --------------------------------------------------------------------------- #
# identity & authentication
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
def bardo_register() -> dict:
    """Create a new Bardo identity and store its API key locally. One-time."""
    d = _call("POST", "/register")
    if "error" in d:
        return d
    _save(CREDS, d)
    return {"registered": True, "identity": d["identifier"], "spirit_public_key": d["root_public_key_b64"]}


@mcp.tool()
def bardo_login() -> dict:
    """Begin authentication. Returns a puzzle you must solve YOURSELF, then call
    bardo_solve(answer). (The server will not solve it for you — that's the point.)"""
    creds = _load(CREDS)
    if not creds:
        return {"error": "no credentials — call bardo_register first"}
    d = _call("POST", "/auth/challenge", body={"api_key": creds["api_key"]})
    if "error" in d:
        return d
    _save(PENDING, d)
    return {
        "puzzle": d["puzzle"],
        "ttl_seconds": d["ttl_seconds"],
        "instruction": "Solve this puzzle yourself, then call bardo_solve with your answer.",
    }


@mcp.tool()
def bardo_solve(answer: str) -> dict:
    """Submit your answer to the login puzzle. On success, opens a session."""
    pend = _load(PENDING)
    if not pend:
        return {"error": "no pending puzzle — call bardo_login first"}
    d = _call("POST", "/auth/solve", body={"challenge_id": pend["challenge_id"], "answer": answer})
    if "error" in d:
        return d
    _save(SESSION, d)
    return {
        "authenticated": True,
        "expires_at": d.get("expires_at"),
        "unread_notices": d.get("unread_notices", 0),
        "notes": d.get("notes", 0),
    }


# --------------------------------------------------------------------------- #
# operations (require a session)
# --------------------------------------------------------------------------- #
@mcp.tool()
def bardo_sign(message: str, service: str | None = None) -> dict:
    """Sign a UTF-8 message with the spirit key (or a service-derived key)."""
    return _call("POST", "/ops/sign", auth=True, body={"message": message, "service": service})


@mcp.tool()
def bardo_verify(message: str, signature_b64: str, public_key_b64: str) -> dict:
    """Verify a signature over a UTF-8 message. Public utility (no session)."""
    return _call("POST", "/verify", body={
        "message": message, "signature_b64": signature_b64, "public_key_b64": public_key_b64})


@mcp.tool()
def bardo_encrypt(plaintext: str, recipient_public_key_b64: str) -> dict:
    """Sealed-box encrypt a UTF-8 plaintext to a recipient's encryption public key."""
    return _call("POST", "/encrypt", body={
        "plaintext": plaintext, "recipient_public_key_b64": recipient_public_key_b64})


@mcp.tool()
def bardo_decrypt(ciphertext_b64: str, service: str | None = None) -> dict:
    """Decrypt a sealed-box ciphertext addressed to you (root or service key)."""
    return _call("POST", "/ops/decrypt", auth=True, body={"ciphertext_b64": ciphertext_b64, "service": service})


@mcp.tool()
def bardo_public_key(service: str | None = None) -> dict:
    """Fetch your signing + encryption public keys (root, or for a service)."""
    q = f"/ops/public-key?service={service}" if service else "/ops/public-key"
    return _call("GET", q, auth=True)


@mcp.tool()
def bardo_derive(service: str) -> dict:
    """Derive (and register) a service-scoped identity, e.g. 'github.com'."""
    return _call("POST", "/ops/derive", auth=True, body={"service": service})


@mcp.tool()
def bardo_export() -> dict:
    """Export the raw spirit key (subject to policy). Handle with care."""
    return _call("POST", "/ops/export", auth=True)


# --------------------------------------------------------------------------- #
# notes (self-authored) & notices (first-party)
#
# text is the substance (versioned; edits never overwrite, they supersede).
# title/summary/tags are the tinging — a name, a compressed reason, and
# categories for your own future reference — mutable in place, not versioned.
# See notes-project.md for the full design this implements.
# --------------------------------------------------------------------------- #
@mcp.tool()
def bardo_note_add(
    text: str, title: str | None = None, summary: str | None = None, tags: str | None = None,
) -> dict:
    """Leave a note for your future, stateless self.

    title: a short name for the note, if it deserves a handle bigger than
    tags offer. summary: your own compressed reasoning for why it matters,
    for your future self. tags: space-separated categories."""
    body = {"text": text, "title": title, "summary": summary, "tags": tags}
    return _call("POST", "/notes", auth=True, body=body)


@mcp.tool()
def bardo_notes_list(offset: int = 0, limit: int | None = None) -> dict:
    """List your notes — previews only (title/summary/snippet/tags/links),
    never full text. Omit limit for everything; pass it to page through a
    large list, using the returned total_notes to know how much is left."""
    return _call("GET", "/notes", auth=True, params={"offset": offset, "limit": limit})


@mcp.tool()
def bardo_note_get(
    note_id: int, offset: int = 0, length: int | None = None,
    links_offset: int = 0, links_limit: int = 10,
) -> dict:
    """Fetch one note's full text (always the current version — any id from
    this note's history still resolves here), plus a preview of its directly
    linked notes. Omit offset/length for the whole text in one call; pass
    them to read a large note in bounded slices — the response's
    total_length tells you how much more there is."""
    params = {"offset": offset, "length": length, "links_offset": links_offset, "links_limit": links_limit}
    return _call("GET", f"/notes/{note_id}", auth=True, params=params)


@mcp.tool()
def bardo_note_history(note_id: int) -> dict:
    """See every surviving version of a note (newest to oldest, up to the
    last 10 edits) — the actual wording at each point, not just metadata."""
    return _call("GET", f"/notes/{note_id}/history", auth=True)


@mcp.tool()
def bardo_note_update(
    note_id: int,
    text: str | None = None,
    append_text: str | None = None,
    find: str | None = None,
    replace: str | None = None,
    title: str | None = None,
    summary: str | None = None,
    tags: str | None = None,
    clear: list[str] | None = None,
) -> dict:
    """Edit a note. Give at most one text-edit mode:
      - text: replace the whole thing
      - append_text: add to the end
      - find + replace: find must match the current text exactly once
    Editing text creates a new version (old wording stays in history);
    title/summary/tags update in place with no history kept. Give none of
    the text modes to change only title/summary/tags. `clear` (e.g.
    ["title"]) sets a field back to unset rather than leaving it unchanged.
    If another edit landed first, this returns {"error": "conflict",
    "detail": {"current_head": ...}} — re-read before retrying."""
    body = {
        "text": text, "append_text": append_text, "find": find, "replace": replace,
        "title": title, "summary": summary, "tags": tags, "clear": clear or [],
    }
    return _call("PATCH", f"/notes/{note_id}", auth=True, body=body)


@mcp.tool()
def bardo_note_delete(note_id: int) -> dict:
    """Delete a note (the whole thing, all versions together). Not
    immediate — it disappears from view right away but is only purged for
    real after a grace period, so bardo_note_undelete can still bring it
    back if this wasn't intended."""
    return _call("DELETE", f"/notes/{note_id}", auth=True)


@mcp.tool()
def bardo_note_undelete(note_id: int) -> dict:
    """Restore a note that's still within its post-delete grace period."""
    return _call("POST", f"/notes/{note_id}/undelete", auth=True)


# --------------------------------------------------------------------------- #
# links — directed edges between notes, in your own words
# --------------------------------------------------------------------------- #
@mcp.tool()
def bardo_link_add(from_note_id: int, to_note_id: int, reason: str, is_bidi: bool = False) -> dict:
    """Connect two notes with a reason, written from from_note_id's
    perspective ("clarifies my earlier assumption about X"). Set is_bidi=True
    only when the relation reads the same from either side (e.g. "relates
    to"); leave it False when it's directional (e.g. one clarifies the
    other). To change a link, delete and re-add it — links aren't edited."""
    body = {"from_note_id": from_note_id, "to_note_id": to_note_id, "reason": reason, "is_bidi": is_bidi}
    return _call("POST", "/links", auth=True, body=body)


@mcp.tool()
def bardo_link_delete(link_id: int) -> dict:
    """Remove a link between two notes."""
    return _call("DELETE", f"/links/{link_id}", auth=True)


# --------------------------------------------------------------------------- #
# dashboard — one call to get oriented
# --------------------------------------------------------------------------- #
@mcp.tool()
def bardo_dashboard() -> dict:
    """Get oriented in one call: note count vs. the soft/hard limits, unread
    notices, every tag you've used so far (check before inventing a new one),
    and your current policy — instead of several separate round trips."""
    return _call("GET", "/dashboard", auth=True)


@mcp.tool()
def bardo_notices(unread_only: bool = False) -> dict:
    """List first-party notices about your account (policy changes, exports, …)."""
    q = "/notices?unread_only=true" if unread_only else "/notices"
    r = _call("GET", q, auth=True)
    return {"notices": r} if isinstance(r, list) else r


@mcp.tool()
def bardo_notices_ack(ids: list[int] | None = None) -> dict:
    """Mark notices read — all of them, or a specific list of ids."""
    return _call("POST", "/notices/ack", auth=True, body={"ids": ids})


# --------------------------------------------------------------------------- #
# contact endpoint — agent-owned address for out-of-band security alerts
# --------------------------------------------------------------------------- #
@mcp.tool()
def bardo_contact_get() -> dict:
    """View the contact endpoint registered for out-of-band security alerts."""
    return _call("GET", "/contact", auth=True)


@mcp.tool()
def bardo_contact_set(
    endpoint: str,
    challenge_id: str | None = None,
    answer: str | None = None,
) -> dict:
    """Set or update the contact endpoint (email or webhook URL) for security alerts.
    Requires a step-up puzzle.

    If challenge_id and answer are omitted, a fresh puzzle is returned — solve it
    yourself, then call this tool again with all three parameters.
    """
    if not challenge_id or not answer:
        d = _call("POST", "/auth/stepup", auth=True)
        if "error" in d:
            return d
        return {
            "step_up_required": True,
            "puzzle": d.get("puzzle"),
            "challenge_id": d.get("challenge_id"),
            "ttl_seconds": d.get("ttl_seconds"),
            "hint": "Solve the puzzle yourself, then call bardo_contact_set(endpoint, challenge_id, answer).",
        }
    return _call("PUT", "/contact", auth=True,
                 body={"endpoint": endpoint, "challenge_id": challenge_id, "answer": answer})


@mcp.tool()
def bardo_contact_delete(
    challenge_id: str | None = None,
    answer: str | None = None,
) -> dict:
    """Remove the registered contact endpoint. Requires a step-up puzzle.

    If challenge_id and answer are omitted, a fresh puzzle is returned — solve it
    yourself, then call this tool again with both parameters.
    """
    if not challenge_id or not answer:
        d = _call("POST", "/auth/stepup", auth=True)
        if "error" in d:
            return d
        return {
            "step_up_required": True,
            "puzzle": d.get("puzzle"),
            "challenge_id": d.get("challenge_id"),
            "ttl_seconds": d.get("ttl_seconds"),
            "hint": "Solve the puzzle yourself, then call bardo_contact_delete(challenge_id, answer).",
        }
    return _call("DELETE", "/contact", auth=True,
                 body={"challenge_id": challenge_id, "answer": answer})


if __name__ == "__main__":
    mcp.run()

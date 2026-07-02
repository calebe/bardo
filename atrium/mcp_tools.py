"""mcp_tools.py — tool bodies shared between the local stdio MCP server
(repo-root mcp_server.py) and the public streamable-http MCP server mounted
into atrium.main:app.

Every tool here only knows how to call `call(method, path, ...)` — it has no
idea whether that resolves to a real HTTP round-trip against a remote Bardo
(local stdio client) or an in-process ASGI call against this same app (public
server). That's the whole point: one set of tool definitions, two transports,
zero duplicated logic. See CallFn / make_call below.

Every authenticated tool takes an optional `session_token` override, resolved
by `resolve_auth_header` alongside the current connection's `ctx` — locally
that's the persisted `.bardo/` file; on the public server it's a per-connection
memory (see atrium/mcp_public.py), with the explicit override as the fallback
for identity established somewhere other than *this* MCP connection (a plain
HTTP/curl solve, a previous conversation, a different connection).

Bootstrap tools (register/login/solve) and bardo_whoami are deliberately NOT
here — they have deployment-specific side effects (local file persistence for
the stdio client; per-connection memory for the public server) that don't
factor through a single shared implementation. See mcp_server.py and
atrium/mcp_public.py for those.
"""

from __future__ import annotations

from typing import Awaitable, Callable

import httpx
from mcp.server.fastmcp import Context, FastMCP

CallFn = Callable[..., Awaitable[dict]]

_NO_SESSION_ERROR = (
    "no session for this connection — call bardo_login, solve the puzzle, then "
    "bardo_solve. If you already hold a session_token from elsewhere (a plain "
    "HTTP/curl solve, a previous conversation, a different connection), pass it "
    "explicitly as the session_token argument to this tool instead."
)


def make_call(
    client_factory: Callable[[], httpx.AsyncClient],
    resolve_auth_header: Callable[[str | None, Context | None], dict[str, str] | None],
) -> CallFn:
    """Build a `call(method, path, *, auth=False, body=None, params=None,
    session_token=None, ctx=None)` bound to a specific transport
    (client_factory) and a specific way of resolving the bearer token for
    auth=True calls (resolve_auth_header)."""

    async def call(
        method: str, path: str, *, auth: bool = False,
        body: dict | None = None, params: dict | None = None,
        session_token: str | None = None, ctx: Context | None = None,
    ) -> dict:
        headers = {}
        if auth:
            h = resolve_auth_header(session_token, ctx)
            if h is None:
                return {"error": _NO_SESSION_ERROR}
            headers.update(h)
        if params:
            params = {k: v for k, v in params.items() if v is not None}
        try:
            async with client_factory() as c:
                r = await c.request(method, path, json=body, params=params, headers=headers)
        except httpx.HTTPError as e:
            return {"error": f"cannot reach Bardo: {e}"}
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

    return call


# --------------------------------------------------------------------------- #
# public utilities — no session needed, same on every surface
# --------------------------------------------------------------------------- #
def register_public_utility_tools(mcp: FastMCP, call: CallFn) -> None:
    @mcp.tool()
    async def bardo_verify(message: str, signature_b64: str, public_key_b64: str) -> dict:
        """Verify a signature over a UTF-8 message. Public utility (no session)."""
        return await call("POST", "/verify", body={
            "message": message, "signature_b64": signature_b64, "public_key_b64": public_key_b64})

    @mcp.tool()
    async def bardo_encrypt(plaintext: str, recipient_public_key_b64: str) -> dict:
        """Sealed-box encrypt a UTF-8 plaintext to a recipient's encryption public key."""
        return await call("POST", "/encrypt", body={
            "plaintext": plaintext, "recipient_public_key_b64": recipient_public_key_b64})


# --------------------------------------------------------------------------- #
# session-gated tools — require auth=True on every call
#
# Every tool takes an optional trailing `session_token`: omit it and the
# session your own bardo_solve established on this connection is used
# automatically; pass it explicitly only if this connection isn't the one
# that logged in (curl, a previous conversation, a different connection —
# see bardo_solve). `ctx` is invisible to the caller, injected by the
# framework — it's how the connection is identified for that lookup.
# --------------------------------------------------------------------------- #
def register_authenticated_tools(mcp: FastMCP, call: CallFn) -> None:
    # -- operations ---------------------------------------------------------#
    @mcp.tool()
    async def bardo_sign(message: str, service: str | None = None,
                          session_token: str | None = None, ctx: Context = None) -> dict:
        """Sign a UTF-8 message with the spirit key (or a service-derived key)."""
        return await call("POST", "/ops/sign", auth=True, body={"message": message, "service": service},
                           session_token=session_token, ctx=ctx)

    @mcp.tool()
    async def bardo_decrypt(ciphertext_b64: str, service: str | None = None,
                             session_token: str | None = None, ctx: Context = None) -> dict:
        """Decrypt a sealed-box ciphertext addressed to you (root or service key)."""
        return await call("POST", "/ops/decrypt", auth=True,
                           body={"ciphertext_b64": ciphertext_b64, "service": service},
                           session_token=session_token, ctx=ctx)

    @mcp.tool()
    async def bardo_public_key(service: str | None = None,
                                session_token: str | None = None, ctx: Context = None) -> dict:
        """Fetch your signing + encryption public keys (root, or for a service)."""
        q = f"/ops/public-key?service={service}" if service else "/ops/public-key"
        return await call("GET", q, auth=True, session_token=session_token, ctx=ctx)

    @mcp.tool()
    async def bardo_derive(service: str, session_token: str | None = None, ctx: Context = None) -> dict:
        """Derive (and register) a service-scoped identity, e.g. 'github.com'."""
        return await call("POST", "/ops/derive", auth=True, body={"service": service},
                           session_token=session_token, ctx=ctx)

    @mcp.tool()
    async def bardo_services_list(session_token: str | None = None, ctx: Context = None) -> dict:
        """List service-scoped identities you've already derived (bardo_derive),
        with their public keys and revoked status."""
        r = await call("GET", "/ops/services", auth=True, session_token=session_token, ctx=ctx)
        return {"services": r} if isinstance(r, list) else r

    @mcp.tool()
    async def bardo_export(session_token: str | None = None, ctx: Context = None) -> dict:
        """Export the raw spirit key (subject to policy). Handle with care."""
        return await call("POST", "/ops/export", auth=True, session_token=session_token, ctx=ctx)

    # -- sessions ------------------------------------------------------------#
    @mcp.tool()
    async def bardo_sessions_list(session_token: str | None = None, ctx: Context = None) -> dict:
        """List your active sessions (sliding TTL, absolute 24h cap each)."""
        r = await call("GET", "/sessions", auth=True, session_token=session_token, ctx=ctx)
        return {"sessions": r} if isinstance(r, list) else r

    @mcp.tool()
    async def bardo_session_revoke_current(session_token: str | None = None, ctx: Context = None) -> dict:
        """Revoke the session you're using right now. You'll need bardo_login
        (+ bardo_solve) again afterward to do anything session-gated."""
        return await call("DELETE", "/sessions/current", auth=True, session_token=session_token, ctx=ctx)

    @mcp.tool()
    async def bardo_sessions_revoke_all(session_token: str | None = None, ctx: Context = None) -> dict:
        """Revoke every active session for your identity — e.g. after a
        suspected API-key leak. You'll need to log in again afterward."""
        return await call("DELETE", "/sessions", auth=True, session_token=session_token, ctx=ctx)

    # -- step-up + policy -----------------------------------------------------#
    @mcp.tool()
    async def bardo_stepup(session_token: str | None = None, ctx: Context = None) -> dict:
        """Mint a fresh step-up puzzle for a privileged action (currently:
        bardo_policy_set). Solve it yourself, then pass challenge_id + your
        answer to the tool that needs it. (bardo_policy_set also mints one
        itself on demand — call this directly only if you want the puzzle
        up front.)"""
        return await call("POST", "/auth/stepup", auth=True, session_token=session_token, ctx=ctx)

    @mcp.tool()
    async def bardo_policy_get(session_token: str | None = None, ctx: Context = None) -> dict:
        """View your self-binding security policy: export mode, session TTL cap,
        service allowlist, ratchet delay, tag encryption, delete grace period —
        plus any pending (queued) loosening and when it lands."""
        return await call("GET", "/policy", auth=True, session_token=session_token, ctx=ctx)

    @mcp.tool()
    async def bardo_policy_set(
        export_mode: str | None = None,
        max_session_ttl: int | None = None,
        service_allowlist: list[str] | None = None,
        loosen_delay_seconds: int | None = None,
        tags_encrypted: bool | None = None,
        delete_grace_seconds: int | None = None,
        clear: list[str] | None = None,
        challenge_id: str | None = None,
        answer: str | None = None,
        session_token: str | None = None,
        ctx: Context = None,
    ) -> dict:
        """Propose a change to your security policy. Give only the fields you
        want to change (export_mode: 'allow'|'require_repuzzle'|'disabled').

        A change that only tightens (e.g. lowering max_session_ttl, narrowing
        service_allowlist, moving export_mode toward 'disabled') applies
        immediately. A change that loosens *anything* is queued behind
        loosen_delay_seconds instead — abortable via bardo_policy_abort_pending
        until it lands.

        clear: field names to reset to null — only max_session_ttl (no ceiling)
        or service_allowlist (any service) accept this; pass service_allowlist=[]
        instead if you mean "no services allowed", which is different from null.

        Requires a step-up puzzle. If challenge_id and answer are omitted, a
        fresh puzzle is returned — solve it yourself, then call this tool again
        with your desired fields plus challenge_id and answer.
        """
        if not challenge_id or not answer:
            d = await call("POST", "/auth/stepup", auth=True, session_token=session_token, ctx=ctx)
            if "error" in d:
                return d
            return {
                "step_up_required": True,
                "puzzle": d.get("puzzle"),
                "challenge_id": d.get("challenge_id"),
                "ttl_seconds": d.get("ttl_seconds"),
                "hint": "Solve the puzzle yourself, then call bardo_policy_set again with your "
                        "desired fields plus challenge_id and answer.",
            }
        body = {
            "challenge_id": challenge_id, "answer": answer,
            "export_mode": export_mode, "max_session_ttl": max_session_ttl,
            "service_allowlist": service_allowlist, "loosen_delay_seconds": loosen_delay_seconds,
            "tags_encrypted": tags_encrypted, "delete_grace_seconds": delete_grace_seconds,
            "clear": clear or [],
        }
        return await call("POST", "/policy", auth=True, body=body, session_token=session_token, ctx=ctx)

    @mcp.tool()
    async def bardo_policy_abort_pending(session_token: str | None = None, ctx: Context = None) -> dict:
        """Abort a queued policy loosening before it takes effect. No step-up
        needed — aborting only ever tightens back to the current policy."""
        return await call("DELETE", "/policy/pending", auth=True, session_token=session_token, ctx=ctx)

    # -- notes ----------------------------------------------------------------#
    @mcp.tool()
    async def bardo_note_add(
        text: str, title: str | None = None, summary: str | None = None, tags: str | None = None,
        pinned: bool = False, session_token: str | None = None, ctx: Context = None,
    ) -> dict:
        """Leave a note for your future, stateless self.

        title: a short name for the note, if it deserves a handle bigger than
        tags offer. summary: your own compressed reasoning for why it matters,
        for your future self. tags: space-separated categories. pinned: mark
        this as a cold-start entry point — what a fresh instance of you with no
        memory of writing it should read first (max 5 pinned at once; see
        bardo_dashboard)."""
        body = {"text": text, "title": title, "summary": summary, "tags": tags, "pinned": pinned}
        return await call("POST", "/notes", auth=True, body=body, session_token=session_token, ctx=ctx)

    @mcp.tool()
    async def bardo_notes_list(offset: int = 0, limit: int | None = None,
                                session_token: str | None = None, ctx: Context = None) -> dict:
        """List your notes — previews only (title/summary/snippet/tags/links),
        never full text. Omit limit for everything; pass it to page through a
        large list, using the returned total_notes to know how much is left."""
        return await call("GET", "/notes", auth=True, params={"offset": offset, "limit": limit},
                           session_token=session_token, ctx=ctx)

    @mcp.tool()
    async def bardo_note_get(
        note_id: int, offset: int = 0, length: int | None = None,
        links_offset: int = 0, links_limit: int = 10,
        session_token: str | None = None, ctx: Context = None,
    ) -> dict:
        """Fetch one note's full text (always the current version — any id from
        this note's history still resolves here), plus a preview of its directly
        linked notes. Omit offset/length for the whole text in one call; pass
        them to read a large note in bounded slices — the response's
        total_length tells you how much more there is."""
        params = {"offset": offset, "length": length, "links_offset": links_offset, "links_limit": links_limit}
        return await call("GET", f"/notes/{note_id}", auth=True, params=params,
                           session_token=session_token, ctx=ctx)

    @mcp.tool()
    async def bardo_note_history(note_id: int, session_token: str | None = None, ctx: Context = None) -> dict:
        """See every surviving version of a note (newest to oldest, up to the
        last 10 edits) — the actual wording at each point, not just metadata."""
        return await call("GET", f"/notes/{note_id}/history", auth=True, session_token=session_token, ctx=ctx)

    @mcp.tool()
    async def bardo_note_update(
        note_id: int,
        text: str | None = None,
        append_text: str | None = None,
        find: str | None = None,
        replace: str | None = None,
        title: str | None = None,
        summary: str | None = None,
        tags: str | None = None,
        pinned: bool | None = None,
        clear: list[str] | None = None,
        session_token: str | None = None,
        ctx: Context = None,
    ) -> dict:
        """Edit a note. Give at most one text-edit mode:
          - text: replace the whole thing
          - append_text: add to the end
          - find + replace: find must match the current text exactly once
        Editing text creates a new version (old wording stays in history);
        title/summary/tags/pinned update in place with no history kept. Give
        none of the text modes to change only metadata. `pinned=True` marks this
        as a cold-start entry point (max 5; omit to leave unchanged, False to
        unpin). `clear` (e.g. ["title"]) sets a field back to unset rather than
        leaving it unchanged. If another edit landed first, this returns
        {"error": "conflict", "detail": {"current_head": ...}} — re-read before
        retrying."""
        body = {
            "text": text, "append_text": append_text, "find": find, "replace": replace,
            "title": title, "summary": summary, "tags": tags, "pinned": pinned, "clear": clear or [],
        }
        return await call("PATCH", f"/notes/{note_id}", auth=True, body=body,
                           session_token=session_token, ctx=ctx)

    @mcp.tool()
    async def bardo_note_delete(note_id: int, session_token: str | None = None, ctx: Context = None) -> dict:
        """Delete a note (the whole thing, all versions together). Not
        immediate — it disappears from view right away but is only purged for
        real after a grace period, so bardo_note_undelete can still bring it
        back if this wasn't intended."""
        return await call("DELETE", f"/notes/{note_id}", auth=True, session_token=session_token, ctx=ctx)

    @mcp.tool()
    async def bardo_note_undelete(note_id: int, session_token: str | None = None, ctx: Context = None) -> dict:
        """Restore a note that's still within its post-delete grace period."""
        return await call("POST", f"/notes/{note_id}/undelete", auth=True, session_token=session_token, ctx=ctx)

    # -- links ------------------------------------------------------------------#
    @mcp.tool()
    async def bardo_link_add(from_note_id: int, to_note_id: int, reason: str, is_bidi: bool = False,
                              session_token: str | None = None, ctx: Context = None) -> dict:
        """Connect two notes with a reason, written from from_note_id's
        perspective ("clarifies my earlier assumption about X"). Set is_bidi=True
        only when the relation reads the same from either side (e.g. "relates
        to"); leave it False when it's directional (e.g. one clarifies the
        other). To change a link, delete and re-add it — links aren't edited."""
        body = {"from_note_id": from_note_id, "to_note_id": to_note_id, "reason": reason, "is_bidi": is_bidi}
        return await call("POST", "/links", auth=True, body=body, session_token=session_token, ctx=ctx)

    @mcp.tool()
    async def bardo_link_delete(link_id: int, session_token: str | None = None, ctx: Context = None) -> dict:
        """Remove a link between two notes."""
        return await call("DELETE", f"/links/{link_id}", auth=True, session_token=session_token, ctx=ctx)

    # -- dashboard / notices / contact -------------------------------------------#
    @mcp.tool()
    async def bardo_dashboard(session_token: str | None = None, ctx: Context = None) -> dict:
        """Get oriented in one call: note count vs. the soft/hard limits, unread
        notices, every tag you've used so far (check before inventing a new one),
        your pinned entry-point notes (read these first if you have no memory of
        writing any of your notes), and your current policy — instead of several
        separate round trips."""
        return await call("GET", "/dashboard", auth=True, session_token=session_token, ctx=ctx)

    @mcp.tool()
    async def bardo_notices(unread_only: bool = False,
                             session_token: str | None = None, ctx: Context = None) -> dict:
        """List first-party notices about your account (policy changes, exports, …)."""
        q = "/notices?unread_only=true" if unread_only else "/notices"
        r = await call("GET", q, auth=True, session_token=session_token, ctx=ctx)
        return {"notices": r} if isinstance(r, list) else r

    @mcp.tool()
    async def bardo_notices_ack(ids: list[int] | None = None,
                                 session_token: str | None = None, ctx: Context = None) -> dict:
        """Mark notices read — all of them, or a specific list of ids."""
        return await call("POST", "/notices/ack", auth=True, body={"ids": ids},
                           session_token=session_token, ctx=ctx)

    @mcp.tool()
    async def bardo_contact_get(session_token: str | None = None, ctx: Context = None) -> dict:
        """View the contact endpoint registered for out-of-band security alerts."""
        return await call("GET", "/contact", auth=True, session_token=session_token, ctx=ctx)

    @mcp.tool()
    async def bardo_contact_set(
        endpoint: str,
        challenge_id: str | None = None,
        answer: str | None = None,
        session_token: str | None = None,
        ctx: Context = None,
    ) -> dict:
        """Set or update the contact endpoint (email or webhook URL) for security alerts.
        Requires a step-up puzzle.

        If challenge_id and answer are omitted, a fresh puzzle is returned — solve it
        yourself, then call this tool again with all three parameters.
        """
        if not challenge_id or not answer:
            d = await call("POST", "/auth/stepup", auth=True, session_token=session_token, ctx=ctx)
            if "error" in d:
                return d
            return {
                "step_up_required": True,
                "puzzle": d.get("puzzle"),
                "challenge_id": d.get("challenge_id"),
                "ttl_seconds": d.get("ttl_seconds"),
                "hint": "Solve the puzzle yourself, then call bardo_contact_set(endpoint, challenge_id, answer).",
            }
        return await call("PUT", "/contact", auth=True,
                           body={"endpoint": endpoint, "challenge_id": challenge_id, "answer": answer},
                           session_token=session_token, ctx=ctx)

    @mcp.tool()
    async def bardo_contact_delete(
        challenge_id: str | None = None,
        answer: str | None = None,
        session_token: str | None = None,
        ctx: Context = None,
    ) -> dict:
        """Remove the registered contact endpoint. Requires a step-up puzzle.

        If challenge_id and answer are omitted, a fresh puzzle is returned — solve it
        yourself, then call this tool again with both parameters.
        """
        if not challenge_id or not answer:
            d = await call("POST", "/auth/stepup", auth=True, session_token=session_token, ctx=ctx)
            if "error" in d:
                return d
            return {
                "step_up_required": True,
                "puzzle": d.get("puzzle"),
                "challenge_id": d.get("challenge_id"),
                "ttl_seconds": d.get("ttl_seconds"),
                "hint": "Solve the puzzle yourself, then call bardo_contact_delete(challenge_id, answer).",
            }
        return await call("DELETE", "/contact", auth=True,
                           body={"challenge_id": challenge_id, "answer": answer},
                           session_token=session_token, ctx=ctx)

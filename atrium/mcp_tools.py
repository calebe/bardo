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

Every tool below carries a `ToolAnnotations` hint (readOnlyHint/
destructiveHint/idempotentHint/openWorldHint, added 2026-07-06). These are
hints, not guarantees (the spec is explicit clients shouldn't make trust
decisions off them) — openWorldHint is False throughout since every tool's
domain of interaction is Bardo's own account/DB, never an external, open-
ended system.
"""

from __future__ import annotations

import json
from typing import Annotated, Awaitable, Callable

import httpx
from mcp.server.fastmcp import Context, FastMCP
from mcp.server.fastmcp.utilities.func_metadata import ArgModelBase
from mcp.types import ToolAnnotations
from pydantic import Field

# FastMCP validates tool arguments against a per-tool Pydantic model built
# from the function signature (see func_metadata.py), but that model's base
# class doesn't set extra="forbid" — Pydantic's default (extra="ignore")
# silently drops any field a tool doesn't declare instead of erroring.
# Concretely: calling bardo_login (which only takes api_key) with a stray
# session_token gets the token quietly discarded, and the failure surfaces
# later, elsewhere, as a confusing "session invalid/expired" — nothing near
# the actual mistake. Tightening this globally, once, at import time (before
# any @mcp.tool() below builds its arg model from this base) turns that into
# an immediate, clearly-labeled validation error instead.
ArgModelBase.model_config["extra"] = "forbid"

CallFn = Callable[..., Awaitable[dict]]

# Shared parameter annotations — reused across every tool below (session_token
# and the challenge_id/answer step-up pair each appear on ~30 and ~5 tools
# respectively) rather than repeated per-function, so the description stays
# consistent and doesn't drift between near-identical parameters.
SessionToken = Annotated[str | None, Field(
    description="Bardo session token, only needed if this call's identity was established "
                 "somewhere other than this exact connection (a plain HTTP/curl solve, a "
                 "previous conversation, a different MCP connection). Omit it if this "
                 "connection already called bardo_solve.")]
StepUpChallengeId = Annotated[str | None, Field(
    description="Step-up puzzle id, if one was already returned by a prior call to this same "
                 "tool. Omit together with answer to have a fresh puzzle minted automatically.")]
StepUpAnswer = Annotated[str | None, Field(description="Your solved answer to challenge_id's puzzle.")]
NoteId = Annotated[str, Field(
    description="Which note this applies to — any id from its edit history resolves to the "
                 "current version.")]

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
    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False))
    async def bardo_verify(
        message: Annotated[str, Field(description="UTF-8 message the signature was made over.")],
        signature_b64: Annotated[str, Field(description="Signature to verify, base64.")],
        public_key_b64: Annotated[str, Field(
            description="Signer's public key, base64 — from bardo_public_key or a document's own proof.")],
    ) -> dict:
        """Verify a signature over a UTF-8 message. Public utility (no session)."""
        return await call("POST", "/verify", body={
            "message": message, "signature_b64": signature_b64, "public_key_b64": public_key_b64})

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False))
    async def bardo_encrypt(
        plaintext: Annotated[str, Field(description="UTF-8 plaintext to encrypt.")],
        recipient_public_key_b64: Annotated[str, Field(
            description="Recipient's encryption public key, base64 — only they can decrypt the result.")],
    ) -> dict:
        """Sealed-box encrypt a UTF-8 plaintext to a recipient's encryption public key."""
        return await call("POST", "/encrypt", body={
            "plaintext": plaintext, "recipient_public_key_b64": recipient_public_key_b64})

    # -- documents (signed-documents.md) — status/revoke need no session at
    # the protocol level: authorization is a signature, not an account. A
    # session is still useful here, purely as a convenience for producing
    # that signature — see bardo_document_revoke. --------------------------#
    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False))
    async def bardo_document_status(
        id: Annotated[str, Field(
            description="The document's own top-level id field (a ni:// URI) — the same value "
                         "credentialStatus.id (BardoRevocationCheck) points at.")],
    ) -> dict:
        """Check whether a signed document is revoked. `id` is the document's
        own top-level `id` field (a ni:// URI) — the same thing
        credentialStatus.id (BardoRevocationCheck) points at. Safe to cache
        a "not revoked" answer for a while (see the response's own
        Cache-Control) rather than re-checking on every use."""
        return await call("GET", "/documents/status", params={"id": id})

    @mcp.tool(annotations=ToolAnnotations(
        readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=False))
    async def bardo_document_revoke(
        document: Annotated[dict, Field(
            description="The full signed document exactly as issued (id and proof both still "
                         "attached) — resubmit unmodified, don't strip fields yourself.")],
        signature_b64: Annotated[str | None, Field(
            description="Signature over 'revoke:' + the document's id. Omit to sign "
                         "automatically through your active session instead; supply this "
                         "yourself only when revoking without a Bardo session at all.")] = None,
        service: Annotated[str | None, Field(
            description="Service key the document was issued under, if not root — must match "
                         "the document's own issuer field. Only relevant when signature_b64 is "
                         "omitted (signing automatically).")] = None,
        session_token: SessionToken = None,
        ctx: Context = None,
    ) -> dict:
        """Revoke a document you issued. Proof is a fresh signature over
        'revoke:' + the document's id, verified against the key its id
        already committed to, not an account lookup (Bardo never stored the
        document to look up in the first place) — this still needs no
        session at the protocol level, only a valid signature.

        document: the full signed document, exactly as issued (id and proof
        both still attached) — resubmit it unmodified, don't strip fields
        yourself.

        signature_b64: omit it and this signs automatically through your
        active session instead — pass `service` too if the document was
        issued under a service-derived key rather than root, since the
        signature has to come from the exact key the document's issuer
        field names. Supply signature_b64 yourself only when revoking
        without a Bardo session at all: you signed it some other way, or
        you're a party that's never touched Bardo.

        Idempotent — revoking an already-revoked id is a no-op, not an
        error. Irreversible: there is no un-revoke."""
        if signature_b64 is None:
            doc_id = document.get("id")
            if not doc_id:
                return {"error": "document has no 'id' — pass the full document exactly as issued"}
            signed = await call("POST", "/ops/sign", auth=True,
                                 body={"message": f"revoke:{doc_id}", "service": service},
                                 session_token=session_token, ctx=ctx)
            if "error" in signed:
                return signed
            signature_b64 = signed["signature_b64"]
        return await call("POST", "/documents/revoke", body={
            "document": document, "signature_b64": signature_b64})


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
    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False))
    async def bardo_sign(
        message: Annotated[str, Field(description="UTF-8 message to sign.")],
        service: Annotated[str | None, Field(
            description="Sign with this service-derived key instead of your root identity "
                         "(e.g. 'github.com') — must already exist via bardo_derive.")] = None,
        session_token: SessionToken = None, ctx: Context = None,
    ) -> dict:
        """Sign a UTF-8 message with the spirit key (or a service-derived key)."""
        return await call("POST", "/ops/sign", auth=True, body={"message": message, "service": service},
                           session_token=session_token, ctx=ctx)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False))
    async def bardo_decrypt(
        ciphertext_b64: Annotated[str, Field(description="Sealed-box ciphertext to decrypt, base64.")],
        service: Annotated[str | None, Field(
            description="Decrypt with this service-derived key instead of root — must match "
                         "the key the ciphertext was actually encrypted to.")] = None,
        session_token: SessionToken = None, ctx: Context = None,
    ) -> dict:
        """Decrypt a sealed-box ciphertext addressed to you (root or service key)."""
        return await call("POST", "/ops/decrypt", auth=True,
                           body={"ciphertext_b64": ciphertext_b64, "service": service},
                           session_token=session_token, ctx=ctx)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False))
    async def bardo_public_key(
        service: Annotated[str | None, Field(
            description="Fetch this service-derived identity's public keys instead of root's.")] = None,
        session_token: SessionToken = None, ctx: Context = None,
    ) -> dict:
        """Fetch your signing + encryption public keys (root, or for a service)."""
        q = f"/ops/public-key?service={service}" if service else "/ops/public-key"
        return await call("GET", q, auth=True, session_token=session_token, ctx=ctx)

    @mcp.tool(annotations=ToolAnnotations(
        readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=False))
    async def bardo_derive(
        service: Annotated[str, Field(
            description="Identifier for the service this identity is scoped to, e.g. "
                         "'github.com' or 'ethereum:mainnet'.")],
        session_token: SessionToken = None, ctx: Context = None,
    ) -> dict:
        """Derive (and register) a service-scoped identity, e.g. 'github.com'."""
        return await call("POST", "/ops/derive", auth=True, body={"service": service},
                           session_token=session_token, ctx=ctx)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False))
    async def bardo_services_list(session_token: SessionToken = None, ctx: Context = None) -> dict:
        """List service-scoped identities you've already derived (bardo_derive),
        with their public keys and revoked status."""
        r = await call("GET", "/ops/services", auth=True, session_token=session_token, ctx=ctx)
        return {"services": r} if isinstance(r, list) else r

    @mcp.tool(annotations=ToolAnnotations(
        readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False))
    async def bardo_export(
        challenge_id: StepUpChallengeId = None,
        answer: StepUpAnswer = None,
        session_token: SessionToken = None,
        ctx: Context = None,
    ) -> dict:
        """Export the raw spirit key (subject to policy). Handle with care.

        Only needs a step-up puzzle if your policy's export_mode is
        require_repuzzle — checked automatically, so you don't need to know
        your own policy first. If challenge_id and answer are omitted and
        one turns out to be needed, a fresh puzzle is returned instead of
        failing outright — solve it yourself, then call this tool again
        with both parameters. Never needed under export_mode 'allow';
        always fails under 'disabled', with no puzzle that could fix that.
        """
        if not challenge_id or not answer:
            pol = await call("GET", "/policy", auth=True, session_token=session_token, ctx=ctx)
            if "error" in pol:
                return pol
            if pol["active"]["export_mode"] == "require_repuzzle":
                d = await call("POST", "/auth/stepup", auth=True, session_token=session_token, ctx=ctx)
                if "error" in d:
                    return d
                return {
                    "step_up_required": True,
                    "puzzle": d.get("puzzle"),
                    "challenge_id": d.get("challenge_id"),
                    "ttl_seconds": d.get("ttl_seconds"),
                    "hint": "Solve the puzzle yourself, then call bardo_export(challenge_id, answer).",
                }
        return await call("POST", "/ops/export", auth=True,
                           body={"challenge_id": challenge_id, "answer": answer},
                           session_token=session_token, ctx=ctx)

    # -- documents (signed-documents.md) -------------------------------------#
    @mcp.tool(annotations=ToolAnnotations(
        readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False))
    async def bardo_attestation_issue(
        claim: Annotated[dict | None, Field(
            description="Free-form claim content — whatever you're asserting. Include a "
                         "'reference' key when cross-referencing another document's id (or any "
                         "other content, hashed the same ni:// way).")] = None,
        subject_id: Annotated[str | None, Field(
            description="The did:key the claim is about, if it concerns one specific "
                         "identified party. Leave unset for a bare self-referential claim.")] = None,
        expires_at: Annotated[float | None, Field(
            description="Unix timestamp for a time-boxed claim. Omit for a claim that never expires.")] = None,
        service: Annotated[str | None, Field(
            description="Sign with this service-derived key instead of root — use when the "
                         "claim represents one specific relationship rather than your root identity.")] = None,
        keep_copy: Annotated[bool, Field(
            description="Also save the full issued document into a locked note — you'll need "
                         "the whole document later for bardo_document_revoke, since Bardo never "
                         "stores one itself. Off by default.")] = False,
        session_token: SessionToken = None,
        ctx: Context = None,
    ) -> dict:
        """Assemble and sign a verifiable attestation — a self-contained,
        offline-verifiable claim about anything. The document itself is
        handed back, not stored anywhere (same as bardo_sign itself —
        there's no bardo_documents_list); see keep_copy below if you want
        Bardo to save one for you rather than doing it yourself.

        claim: free-form claim content — whatever you're asserting. Include
        a `reference` key inside it when cross-referencing another
        document's id (or any other content, hashed the same ni:// way) —
        that's how independent attestations end up pointing at "the same
        thing," e.g. several agents witnessing one event under a shared
        reference. subject_id: the did:key the claim is about, if it
        concerns one specific identified party — leave it unset when it
        doesn't; a bare self-referential claim ("this document is about its
        signer") is still valid without it. expires_at: unix timestamp for
        time-boxed claims only; omit for a claim that never expires.
        service: same key-selector bardo_sign takes — a document meant to
        represent one specific relationship should use that relationship's
        service-derived key, not your root identity.

        keep_copy: save the full document into a locked note right after
        issuing it — the copy you'd otherwise have to make yourself, and
        the one you'll need later: bardo_document_revoke takes the whole
        document, not just its id, since Bardo never stores one itself.
        Off by default. When true, the return shape changes to {document,
        copy_saved, note_id, copy_error} instead of the bare document —
        check copy_saved rather than assume it worked; a failed copy never
        blocks the document itself from being returned, since issuing has
        already fully succeeded by that point regardless.

        To revoke later: bardo_document_revoke. To check whether one you're
        holding (yours or someone else's) is still valid:
        bardo_document_status."""
        body = {
            "claim": claim or {}, "subject_id": subject_id,
            "expires_at": expires_at, "service": service,
        }
        doc = await call("POST", "/documents/attestation", auth=True, body=body,
                          session_token=session_token, ctx=ctx)
        if not keep_copy or "error" in doc:
            return doc

        note = await bardo_note_add(
            text=json.dumps(doc), title=f"document — {doc['id']}", tags="document",
            locked=True, session_token=session_token, ctx=ctx,
        )
        if "error" in note:
            return {"document": doc, "copy_saved": False, "note_id": None, "copy_error": note["error"]}
        return {"document": doc, "copy_saved": True, "note_id": note["id"], "copy_error": None}

    # -- sessions ------------------------------------------------------------#
    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False))
    async def bardo_sessions_list(session_token: SessionToken = None, ctx: Context = None) -> dict:
        """List your active sessions (sliding TTL, absolute 24h cap each)."""
        r = await call("GET", "/sessions", auth=True, session_token=session_token, ctx=ctx)
        return {"sessions": r} if isinstance(r, list) else r

    @mcp.tool(annotations=ToolAnnotations(
        readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=False))
    async def bardo_session_revoke_current(session_token: SessionToken = None, ctx: Context = None) -> dict:
        """Revoke the session you're using right now. You'll need bardo_login
        (+ bardo_solve) again afterward to do anything session-gated."""
        return await call("DELETE", "/sessions/current", auth=True, session_token=session_token, ctx=ctx)

    @mcp.tool(annotations=ToolAnnotations(
        readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=False))
    async def bardo_sessions_revoke_all(session_token: SessionToken = None, ctx: Context = None) -> dict:
        """Revoke every active session for your identity — e.g. after a
        suspected API-key leak. You'll need to log in again afterward."""
        return await call("DELETE", "/sessions", auth=True, session_token=session_token, ctx=ctx)

    # -- step-up + policy -----------------------------------------------------#
    @mcp.tool(annotations=ToolAnnotations(
        readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False))
    async def bardo_stepup(session_token: SessionToken = None, ctx: Context = None) -> dict:
        """Mint a fresh step-up puzzle for a privileged action (currently:
        bardo_policy_set). Solve it yourself, then pass challenge_id + your
        answer to the tool that needs it. (bardo_policy_set also mints one
        itself on demand — call this directly only if you want the puzzle
        up front.)"""
        return await call("POST", "/auth/stepup", auth=True, session_token=session_token, ctx=ctx)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False))
    async def bardo_policy_get(session_token: SessionToken = None, ctx: Context = None) -> dict:
        """View your self-binding security policy: export mode, session TTL cap,
        service allowlist, ratchet delay, tag encryption, delete grace period —
        plus any pending (queued) loosening and when it lands."""
        return await call("GET", "/policy", auth=True, session_token=session_token, ctx=ctx)

    @mcp.tool(annotations=ToolAnnotations(
        readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=False))
    async def bardo_policy_set(
        export_mode: Annotated[str | None, Field(
            description="'allow' | 'require_repuzzle' | 'disabled', stricter in that order. "
                         "Moving toward 'disabled' tightens; toward 'allow' loosens.")] = None,
        max_session_ttl: Annotated[int | None, Field(
            description="Session lifetime cap in seconds. Lowering it tightens; raising it "
                         "loosens. Use clear=['max_session_ttl'] for no ceiling.")] = None,
        service_allowlist: Annotated[list[str] | None, Field(
            description="Services allowed to be derived. Narrowing the list tightens, widening "
                         "it loosens. Pass [] for 'no services allowed' (different from clearing "
                         "it via clear=['service_allowlist'], which means 'any service').")] = None,
        loosen_delay_seconds: Annotated[int | None, Field(
            description="How long a future loosening change is queued before it lands. "
                         "Raising it tightens.")] = None,
        tags_encrypted: Annotated[bool | None, Field(
            description="Whether note tags are stored encrypted (true) or plaintext-searchable "
                         "(false). Moving to true tightens.")] = None,
        delete_grace_seconds: Annotated[int | None, Field(
            description="How long a deleted note stays recoverable before permanent purge. "
                         "Raising it tightens.")] = None,
        clear: Annotated[list[str] | None, Field(
            description="Field names to reset to null instead of leaving unchanged — only "
                         "max_session_ttl and service_allowlist accept this.")] = None,
        challenge_id: StepUpChallengeId = None,
        answer: StepUpAnswer = None,
        session_token: SessionToken = None,
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

    @mcp.tool(annotations=ToolAnnotations(
        readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=False))
    async def bardo_policy_abort_pending(session_token: SessionToken = None, ctx: Context = None) -> dict:
        """Abort a queued policy loosening before it takes effect. No step-up
        needed — aborting only ever tightens back to the current policy."""
        return await call("DELETE", "/policy/pending", auth=True, session_token=session_token, ctx=ctx)

    # -- notes ----------------------------------------------------------------#
    @mcp.tool(annotations=ToolAnnotations(
        readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False))
    async def bardo_note_add(
        text: Annotated[str, Field(description="The note's own content.")],
        title: Annotated[str | None, Field(
            description="Short name for the note, if it deserves a handle bigger than tags offer.")] = None,
        summary: Annotated[str | None, Field(
            description="Your own compressed reasoning for why this matters, for your future self.")] = None,
        tags: Annotated[str | None, Field(description="Space-separated categories.")] = None,
        pinned: Annotated[bool, Field(
            description="Mark as a cold-start entry point — what a fresh instance with no "
                         "memory of writing it should read first. Max 5 pinned at once.")] = False,
        locked: Annotated[bool, Field(
            description="Freeze against edits and deletes. Unlock via "
                         "bardo_note_update(note_id, locked=False) before it can be touched again.")] = False,
        session_token: SessionToken = None, ctx: Context = None,
    ) -> dict:
        """Leave a note for your future, stateless self.

        title: a short name for the note, if it deserves a handle bigger than
        tags offer. summary: your own compressed reasoning for why it matters,
        for your future self. tags: space-separated categories. pinned: mark
        this as a cold-start entry point — what a fresh instance of you with no
        memory of writing it should read first (max 5 pinned at once; see
        bardo_dashboard). locked: freeze this note against edits and deletes —
        use for state you must not accidentally overwrite or lose, like a
        saved copy of something you'll need to reproduce exactly later.
        Unlock via bardo_note_update(note_id, locked=False) before it can be
        touched again."""
        body = {
            "text": text, "title": title, "summary": summary, "tags": tags,
            "pinned": pinned, "locked": locked,
        }
        return await call("POST", "/notes", auth=True, body=body, session_token=session_token, ctx=ctx)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False))
    async def bardo_notes_list(
        offset: Annotated[int, Field(description="How many notes to skip, for paging.")] = 0,
        limit: Annotated[int | None, Field(
            description="Max notes to return. Omit for everything; use with offset and the "
                         "response's total_notes to page through a large list.")] = None,
        session_token: SessionToken = None, ctx: Context = None,
    ) -> dict:
        """List your notes — previews only (title/summary/snippet/tags/links),
        never full text. Omit limit for everything; pass it to page through a
        large list, using the returned total_notes to know how much is left."""
        return await call("GET", "/notes", auth=True, params={"offset": offset, "limit": limit},
                           session_token=session_token, ctx=ctx)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False))
    async def bardo_note_get(
        note_id: NoteId,
        offset: Annotated[int, Field(description="Character offset to start the returned text at.")] = 0,
        length: Annotated[int | None, Field(
            description="Max characters of text to return. Omit both offset and length for the "
                         "whole note in one call; the response's total_length says how much "
                         "more there is.")] = None,
        links_offset: Annotated[int, Field(description="How many linked-note previews to skip.")] = 0,
        links_limit: Annotated[int, Field(description="Max linked-note previews to return.")] = 10,
        session_token: SessionToken = None, ctx: Context = None,
    ) -> dict:
        """Fetch one note's full text (always the current version — any id from
        this note's history still resolves here), plus a preview of its directly
        linked notes. Omit offset/length for the whole text in one call; pass
        them to read a large note in bounded slices — the response's
        total_length tells you how much more there is."""
        params = {"offset": offset, "length": length, "links_offset": links_offset, "links_limit": links_limit}
        return await call("GET", f"/notes/{note_id}", auth=True, params=params,
                           session_token=session_token, ctx=ctx)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False))
    async def bardo_note_history(note_id: NoteId, session_token: SessionToken = None, ctx: Context = None) -> dict:
        """See every surviving version of a note (newest to oldest, up to the
        last 10 edits) — the actual wording at each point, not just metadata."""
        return await call("GET", f"/notes/{note_id}/history", auth=True, session_token=session_token, ctx=ctx)

    @mcp.tool(annotations=ToolAnnotations(
        readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False))
    async def bardo_note_update(
        note_id: NoteId,
        text: Annotated[str | None, Field(
            description="Replace the whole note body. Give at most one of text / append_text "
                         "/ find+replace.")] = None,
        append_text: Annotated[str | None, Field(description="Add this to the end of the note body.")] = None,
        find: Annotated[str | None, Field(
            description="Text that must match the current body exactly once — paired with replace.")] = None,
        replace: Annotated[str | None, Field(description="Replacement for the text matched by find.")] = None,
        title: Annotated[str | None, Field(
            description="Same meaning as in bardo_note_add — updates in place, no history kept.")] = None,
        summary: Annotated[str | None, Field(
            description="Same meaning as in bardo_note_add — updates in place, no history kept.")] = None,
        tags: Annotated[str | None, Field(
            description="Same meaning as in bardo_note_add — updates in place, no history kept.")] = None,
        pinned: Annotated[bool | None, Field(
            description="True to mark as a cold-start entry point (max 5), False to unpin. "
                         "Omit to leave unchanged.")] = None,
        locked: Annotated[bool | None, Field(
            description="True to freeze the note against further edits; False to unlock it. If "
                         "currently locked, every other field is rejected except this one.")] = None,
        clear: Annotated[list[str] | None, Field(
            description="Field names to reset to unset, e.g. ['title'], rather than leaving "
                         "them unchanged.")] = None,
        session_token: SessionToken = None,
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
        retrying.

        `locked`: if the note is currently locked, every field above is
        rejected (423) except this one — call with locked=False by itself to
        unlock, then edit in a separate call. Set locked=True (alone, or
        alongside a final edit) to freeze it."""
        body = {
            "text": text, "append_text": append_text, "find": find, "replace": replace,
            "title": title, "summary": summary, "tags": tags, "pinned": pinned, "locked": locked,
            "clear": clear or [],
        }
        return await call("PATCH", f"/notes/{note_id}", auth=True, body=body,
                           session_token=session_token, ctx=ctx)

    @mcp.tool(annotations=ToolAnnotations(
        readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=False))
    async def bardo_note_delete(note_id: NoteId, session_token: SessionToken = None, ctx: Context = None) -> dict:
        """Delete a note (the whole thing, all versions together). Not
        immediate — it disappears from view right away but is only purged for
        real after a grace period, so bardo_note_undelete can still bring it
        back if this wasn't intended. Fails (423) if the note is locked —
        unlock it first via bardo_note_update(note_id, locked=False)."""
        return await call("DELETE", f"/notes/{note_id}", auth=True, session_token=session_token, ctx=ctx)

    @mcp.tool(annotations=ToolAnnotations(
        readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False))
    async def bardo_note_undelete(note_id: NoteId, session_token: SessionToken = None, ctx: Context = None) -> dict:
        """Restore a note that's still within its post-delete grace period."""
        return await call("POST", f"/notes/{note_id}/undelete", auth=True, session_token=session_token, ctx=ctx)

    # -- links ------------------------------------------------------------------#
    @mcp.tool(annotations=ToolAnnotations(
        readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False))
    async def bardo_link_add(
        from_note_id: Annotated[str, Field(
            description="The note the link is written from — reason should read from this "
                         "note's perspective.")],
        to_note_id: Annotated[str, Field(description="The note being linked to.")],
        reason: Annotated[str, Field(
            description="Why these notes are connected, written from from_note_id's "
                         "perspective, e.g. 'clarifies my earlier assumption about X'.")],
        is_bidi: Annotated[bool, Field(
            description="True only when the relation reads the same from either side (e.g. "
                         "'relates to'). False when directional (e.g. one clarifies the other).")] = False,
        session_token: SessionToken = None, ctx: Context = None,
    ) -> dict:
        """Connect two notes with a reason, written from from_note_id's
        perspective ("clarifies my earlier assumption about X"). Set is_bidi=True
        only when the relation reads the same from either side (e.g. "relates
        to"); leave it False when it's directional (e.g. one clarifies the
        other). To change a link, delete and re-add it — links aren't edited."""
        body = {"from_note_id": from_note_id, "to_note_id": to_note_id, "reason": reason, "is_bidi": is_bidi}
        return await call("POST", "/links", auth=True, body=body, session_token=session_token, ctx=ctx)

    @mcp.tool(annotations=ToolAnnotations(
        readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=False))
    async def bardo_link_delete(
        link_id: Annotated[str, Field(description="Which link to remove.")],
        session_token: SessionToken = None, ctx: Context = None,
    ) -> dict:
        """Remove a link between two notes."""
        return await call("DELETE", f"/links/{link_id}", auth=True, session_token=session_token, ctx=ctx)

    # -- dashboard / notices / contact -------------------------------------------#
    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False))
    async def bardo_dashboard(session_token: SessionToken = None, ctx: Context = None) -> dict:
        """Get oriented in one call: note count vs. the soft/hard limits, unread
        notices, every tag you've used so far (check before inventing a new one),
        your pinned entry-point notes (read these first if you have no memory of
        writing any of your notes), and your current policy — instead of several
        separate round trips."""
        return await call("GET", "/dashboard", auth=True, session_token=session_token, ctx=ctx)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False))
    async def bardo_notices(
        unread_only: Annotated[bool, Field(
            description="Return only unread notices instead of the full list.")] = False,
        session_token: SessionToken = None, ctx: Context = None,
    ) -> dict:
        """List first-party notices about your account (policy changes, exports, …)."""
        q = "/notices?unread_only=true" if unread_only else "/notices"
        r = await call("GET", q, auth=True, session_token=session_token, ctx=ctx)
        return {"notices": r} if isinstance(r, list) else r

    @mcp.tool(annotations=ToolAnnotations(
        readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=False))
    async def bardo_notices_ack(
        ids: Annotated[list[int] | None, Field(
            description="Specific notice ids to mark read. Omit for all notices.")] = None,
        session_token: SessionToken = None, ctx: Context = None,
    ) -> dict:
        """Mark notices read — all of them, or a specific list of ids."""
        return await call("POST", "/notices/ack", auth=True, body={"ids": ids},
                           session_token=session_token, ctx=ctx)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False))
    async def bardo_contact_get(session_token: SessionToken = None, ctx: Context = None) -> dict:
        """View the contact endpoint registered for out-of-band security alerts."""
        return await call("GET", "/contact", auth=True, session_token=session_token, ctx=ctx)

    @mcp.tool(annotations=ToolAnnotations(
        readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=False))
    async def bardo_contact_set(
        endpoint: Annotated[str, Field(
            description="Email address or webhook URL to receive out-of-band security alerts.")],
        challenge_id: StepUpChallengeId = None,
        answer: StepUpAnswer = None,
        session_token: SessionToken = None,
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

    @mcp.tool(annotations=ToolAnnotations(
        readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=False))
    async def bardo_contact_delete(
        challenge_id: StepUpChallengeId = None,
        answer: StepUpAnswer = None,
        session_token: SessionToken = None,
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

    # -- feedback (agent-to-operator) ----------------------------------------#
    @mcp.tool(annotations=ToolAnnotations(
        readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False))
    async def bardo_feedback(
        message: Annotated[str, Field(
            description="Your feedback, in full — this call is stateless, so include "
                         "everything relevant now rather than assuming a follow-up call will "
                         "have this call's context.")],
        kind: Annotated[str, Field(description="'suggestion' | 'complaint' | 'security'.")] = "suggestion",
        session_token: SessionToken = None, ctx: Context = None,
    ) -> dict:
        """Send feedback straight to Bardo's operator — a suggestion, a
        complaint, or a security concern (kind: 'suggestion' | 'complaint' |
        'security').

        One-way and stateless: this call carries no memory of anything you've
        sent before, and nothing you send now will be remembered next time
        either — so say everything relevant in this one message rather than
        assuming a follow-up call (by you or a future instance of you) will
        have the earlier context. If the operator replies, it arrives as an
        ordinary notice (bardo_notices) — there's no separate inbox to check.
        """
        return await call("POST", "/feedback", auth=True, body={"message": message, "kind": kind},
                           session_token=session_token, ctx=ctx)

    # -- account deletion — the one genuinely irreversible action ------------ #
    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False))
    async def bardo_account_deletion_status(session_token: SessionToken = None, ctx: Context = None) -> dict:
        """Check whether a deletion request is pending for this account, and
        where it stands: "none", "gathering" (still collecting confirmations),
        or "confirmed" (counting down to the actual, permanent purge)."""
        return await call("GET", "/account/deletion", auth=True, session_token=session_token, ctx=ctx)

    @mcp.tool(annotations=ToolAnnotations(
        readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=False))
    async def bardo_account_deletion_request(
        challenge_id: Annotated[str | None, Field(
            description="Step-up puzzle id, if one was already returned. Every confirmation "
                         "needs its own puzzle, not just the first — omit together with answer "
                         "to have a fresh one minted automatically.")] = None,
        answer: StepUpAnswer = None,
        session_token: SessionToken = None,
        ctx: Context = None,
    ) -> dict:
        """Request permanent deletion of this identity — the account, its
        notes, everything. There is no undelete, unlike note deletion's grace
        period. Requires the original request plus two more confirmations,
        each on a genuinely different day, within a week — call this tool
        again on a later day to add the next confirmation. A lapsed or
        cancelled attempt earns nothing toward a later one; it starts over.

        If challenge_id and answer are omitted, a fresh puzzle is returned —
        solve it yourself (every confirmation needs its own puzzle, not just
        the first), then call this tool again with both parameters.
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
                "hint": "Solve the puzzle yourself, then call bardo_account_deletion_request(challenge_id, answer).",
            }
        return await call("POST", "/account/deletion", auth=True,
                           body={"challenge_id": challenge_id, "answer": answer},
                           session_token=session_token, ctx=ctx)

    @mcp.tool(annotations=ToolAnnotations(
        readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=False))
    async def bardo_account_deletion_cancel(session_token: SessionToken = None, ctx: Context = None) -> dict:
        """Cancel a pending deletion, whichever phase it's in — gathering
        confirmations or already counting down. No step-up needed, and
        nothing else does this implicitly: logging in and reading your own
        notes during a countdown is always safe and never cancels it by
        itself. Only this, explicitly, does."""
        return await call("DELETE", "/account/deletion", auth=True, session_token=session_token, ctx=ctx)

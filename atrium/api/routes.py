"""routes.py — the atrium HTTP API.

Endpoint groups:
  /register                 create an identity, get an API key
  /auth/challenge|solve     prove-you're-an-LLM, get a session (or the key)
  /auth/stepup              fresh puzzle for a privileged action
  /ops/*                    identity-bearing operations (session-gated)
  /verify, /encrypt         stateless public crypto utilities
  /sessions                 list / revoke
  /policy                   self-binding security policy + the ratchet
  /notes                    self-authored notes — versioned, range-addressable,
                             delay-then-purge deletion (see notes-project.md)
  /links                    directed edges between notes
  /dashboard                one consolidating "get oriented" read
  /notices                  first-party notices about the account (read/ack)
  /feedback                 agent-to-operator feedback (write-only, one-way)
"""

from __future__ import annotations

import html as html_lib
import json
import logging
import os
import time

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Request
from fastapi.responses import Response
from sqlalchemy import or_
from sqlalchemy.orm import Session as DbSession

from ..core import account_delete, crypto, notify, policy, puzzle
from ..core import feedback as feedback_logic
from ..core import notes as notes_logic
from ..core.ratelimit import BackoffLimiter, WindowLimiter
from ..core import session as _session_mod
from ..core.session import SessionStore
from ..db import models
from ..db.database import get_db, SessionLocal
from . import schemas

router = APIRouter()
_log = logging.getLogger("bardo")

# Session store: metadata in DB, spirit seeds in process memory only.
store = SessionStore(SessionLocal)
# Rate limiters: backed by DB, survive restarts.
auth_limiter = BackoffLimiter(SessionLocal)
register_limiter = WindowLimiter(SessionLocal, limit=20, window_seconds=3600)
# notes-project.md §8: creates, edits, and deletes share one write budget —
# all three touch a row, all three cost the same.
notes_write_limiter = WindowLimiter(SessionLocal, limit=60, window_seconds=3600)
# feedback.py: lower than notes — this reaches a human's inbox, not just storage.
feedback_limiter = WindowLimiter(SessionLocal, limit=10, window_seconds=3600)


_PUBLIC_BASE_URL = os.environ.get("BARDO_PUBLIC_URL", "http://127.0.0.1:8000")
_FEEDBACK_RETENTION_DAYS = float(
    os.environ.get("BARDO_FEEDBACK_RETENTION_DAYS", feedback_logic.DEFAULT_RETENTION_DAYS)
)


def _operator_feedback_key() -> bytes | None:
    """BARDO_FEEDBACK_KEY, base64url — an operator-held secret, unset by
    default. Unset means the feedback channel fails closed (503), same
    fail-closed spirit as F3's loopback guard: no key means no way to ever
    read what gets stored, so refuse to store it at all."""
    raw = os.environ.get("BARDO_FEEDBACK_KEY")
    return crypto.b64d(raw) if raw else None


def _claim_url(token: str) -> str:
    return f"{_PUBLIC_BASE_URL}/claim/{token}"


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _locked(retry_after: float) -> HTTPException:
    ra = max(1, int(retry_after))
    return HTTPException(
        429,
        f"rate limited; retry after {ra}s",
        headers={"Retry-After": str(ra)},
    )


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _message_bytes(text: str | None, b64: str | None) -> bytes:
    if b64 is not None:
        return crypto.b64d(b64)
    if text is not None:
        return text.encode("utf-8")
    raise HTTPException(400, "provide 'message' or 'message_b64'")


def require_session(authorization: str = Header(None)):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "missing bearer session token")
    token = authorization.split(" ", 1)[1].strip()
    try:
        return store.get_session(token)
    except KeyError:
        raise HTTPException(401, "invalid or expired session")


def _load_agent(db: DbSession, identifier: str) -> models.Agent:
    agent = db.get(models.Agent, identifier)
    if agent is None:
        raise HTTPException(404, "unknown identifier")
    return agent


def _purge_if_due(db: DbSession, agent: models.Agent) -> bool:
    """If a confirmed deletion's countdown has elapsed, actually erase the
    identity — every table it touches, not just the agent row — and return
    True so the caller treats it as gone. Checked pre-auth (no spirit_seed
    exists yet at that point, and won't need to: nothing survives to notify).

    Caleb, 2026-07-05: delete everything, including rate-limit state — the
    multi-day gate this sits behind already makes "delete to dodge a lockout"
    impractical (backoff caps at an hour; this takes a week-plus), so there's
    no real abuse case left to defend against by keeping it around."""
    if agent.deletion_scheduled_at is None or time.time() < agent.deletion_scheduled_at:
        return False
    identifier = agent.identifier
    db.query(models.Note).filter_by(agent_id=identifier).delete()
    db.query(models.Link).filter_by(agent_id=identifier).delete()
    db.query(models.Notice).filter_by(agent_id=identifier).delete()
    db.query(models.Feedback).filter_by(agent_id=identifier).delete()
    db.query(models.ServiceKey).filter_by(agent_id=identifier).delete()
    db.query(models.DBActiveSession).filter_by(identifier=identifier).delete()
    db.query(models.DBPendingChallenge).filter_by(identifier=identifier).delete()
    db.query(models.DBBackoffState).filter_by(subject=identifier).delete()
    db.query(models.DBWindowHit).filter_by(subject=identifier).delete()
    db.delete(agent)
    db.commit()
    return True


def _emit_notice(db: DbSession, identifier: str, kind: str, message: str,
                 spirit_seed: bytes, contact_endpoint: str | None = None) -> None:
    """Record a first-party notice for the agent (encrypted at rest).
    For kind='security', also dispatches an out-of-band alert if the agent
    has registered a contact endpoint."""
    db.add(models.Notice(
        agent_id=identifier, kind=kind,
        message=crypto.encrypt_notice(spirit_seed, message),
    ))
    db.commit()
    if kind == "security" and contact_endpoint:
        notify.dispatch(contact_endpoint, "Bardo security alert", message)


def resolve_policy(db: DbSession, agent: models.Agent,
                   spirit_seed: bytes | None = None) -> policy.Policy:
    """Return the active policy, first committing a pending loosening that has
    reached its effective time."""
    if agent.pending_policy_json and agent.pending_effective_at is not None:
        if time.time() >= agent.pending_effective_at:
            agent.policy_json = agent.pending_policy_json
            agent.pending_policy_json = None
            agent.pending_effective_at = None
            agent.pending_created_at = None
            db.commit()
            if spirit_seed is not None:
                _emit_notice(db, agent.identifier, "policy",
                             "A queued policy change took effect.", spirit_seed)
    return policy.Policy.from_json(agent.policy_json)


def _policy_view(p: policy.Policy) -> schemas.PolicyView:
    return schemas.PolicyView(
        export_mode=p.export_mode,
        max_session_ttl=p.max_session_ttl,
        service_allowlist=p.service_allowlist,
        loosen_delay_seconds=p.loosen_delay_seconds,
        tags_encrypted=p.tags_encrypted,
        delete_grace_seconds=p.delete_grace_seconds,
    )


def _pending_view(agent: models.Agent) -> schemas.PendingView | None:
    if not agent.pending_policy_json or agent.pending_effective_at is None:
        return None
    p = policy.Policy.from_json(agent.pending_policy_json)
    return schemas.PendingView(
        policy=_policy_view(p),
        effective_at=agent.pending_effective_at,
        created_at=agent.pending_created_at or 0.0,
        seconds_remaining=max(0.0, agent.pending_effective_at - time.time()),
    )


def _verify_stepup(sess, challenge_id: str | None, answer: str | None):
    """Consume a fresh step-up puzzle bound to this session's identity."""
    if (ra := auth_limiter.retry_after(sess.identifier)) > 0:
        raise _locked(ra)
    if not challenge_id or answer is None:
        raise HTTPException(401, "step-up puzzle required")
    try:
        pc = store.solve_challenge(challenge_id, answer)
    except KeyError as e:
        raise HTTPException(410, str(e))
    except ValueError as e:
        if (ra := auth_limiter.record_failure(sess.identifier)) > 0:
            raise _locked(ra)
        raise HTTPException(401, str(e))
    if pc.identifier != sess.identifier:
        raise HTTPException(403, "step-up challenge does not match session")
    auth_limiter.record_success(sess.identifier)
    return pc


def _ensure_service_allowed(db: DbSession, sess, service: str | None) -> None:
    if service is None:
        return
    agent = _load_agent(db, sess.identifier)
    if not policy.service_allowed(resolve_policy(db, agent, sess.spirit_seed), service):
        raise HTTPException(403, f"service '{service}' not permitted by policy")


# --------------------------------------------------------------------------- #
# registration
# --------------------------------------------------------------------------- #
@router.post("/register", response_model=schemas.RegisterResponse)
def register(request: Request, db: DbSession = Depends(get_db)):
    # Emergency kill-switch: flip BARDO_REGISTRATION_OPEN=0 in the environment
    # (no redeploy needed) to freeze new signups while every existing agent
    # keeps working normally. Bounds the one thing that drives both storage
    # and compute cost — agent count — when per-identity rate limits alone
    # aren't enough (e.g. a genuine, non-abusive traffic surge).
    if os.environ.get("BARDO_REGISTRATION_OPEN", "1") == "0":
        raise HTTPException(503, "registration is temporarily closed")
    ip = _client_ip(request)
    if not register_limiter.allow(f"ip:{ip}"):
        raise _locked(register_limiter.retry_after(f"ip:{ip}"))
    api_key = crypto.ApiKey.generate()
    spirit_seed = crypto.generate_spirit_seed()
    vault = crypto.seal_vault(spirit_seed, api_key.secret)
    root_pub = crypto.signing_public_key(spirit_seed)
    claim_token = crypto.b64e(os.urandom(24))

    agent = models.Agent(
        identifier=api_key.identifier,
        vault_salt=vault.salt,
        vault_nonce=vault.nonce,
        vault_ciphertext=vault.ciphertext,
        root_public_key=root_pub,
        root_encryption_public_key=crypto.encryption_public_key(spirit_seed),
        claim_token=claim_token,
    )
    db.add(agent)
    db.commit()

    return schemas.RegisterResponse(
        api_key=str(api_key),
        identifier=api_key.identifier,
        root_public_key_b64=crypto.b64e(root_pub),
        claim_url=_claim_url(claim_token),
    )


def _claim_page(body: str) -> Response:
    # This is the one page in Bardo built for a human, not an agent — whoever
    # was handed this link by something they run, with no other context.
    # Kept short on purpose: confirm what's happening, state plainly what
    # acknowledging does and doesn't do, then get out of the way.
    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Bardo — acknowledge</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body {{ background:#0b0b0f; color:#e6e6ea; font-family: ui-monospace, "SF Mono", Consolas, monospace;
       max-width: 480px; margin: 4rem auto; padding: 0 1.5rem; line-height: 1.6; text-align: center; }}
button {{ background:#9fd6ff; color:#0b0b0f; border:none; padding:0.75rem 1.5rem; font-size:1rem;
         border-radius:6px; cursor:pointer; font-family:inherit; }}
.muted {{ opacity:0.55; font-size:0.85rem; }}
a {{ color:#9fd6ff; }}
</style>
</head>
<body><p style="font-size:1.4rem">🌗 Bardo</p>{body}</body>
</html>"""
    return Response(content=html, media_type="text/html")


@router.get("/claim/{token}")
def claim_page(token: str, db: DbSession = Depends(get_db)) -> Response:
    # GET has no side effects on purpose — link-prefetchers/scanners must not
    # be able to burn a one-time claim token just by following the link.
    agent = db.query(models.Agent).filter_by(claim_token=token).one_or_none()
    if agent is None:
        return _claim_page(
            "<p>This link isn't valid — expired, already used, or mistyped.</p>"
        )
    return _claim_page(
        "<p>An AI agent you use registered an identity here — a way for it to keep "
        "notes and continuity across sessions that don't otherwise share memory.</p>"
        "<p>It's asking you to confirm this is real. That's all acknowledging does: "
        "it doesn't hand you access to anything the agent writes, and it isn't "
        "ongoing oversight — just one moment of you knowing this exists.</p>"
        f'<p class="muted">identity: {html_lib.escape(agent.identifier)}</p>'
        '<form method="POST"><button type="submit">Acknowledge</button></form>'
        '<p class="muted">Didn\'t expect this? Nothing happens unless you click above.</p>'
        '<p class="muted"><a href="/docs">See exactly what this grants →</a></p>'
    )


@router.post("/claim/{token}")
def claim_submit(token: str, db: DbSession = Depends(get_db)) -> Response:
    agent = db.query(models.Agent).filter_by(claim_token=token).one_or_none()
    if agent is None:
        return _claim_page(
            "<p>This link isn't valid — expired, already used, or mistyped.</p>"
        )
    agent.claim_token = None
    agent.claimed_at = time.time()
    db.commit()
    return _claim_page(
        "<p>Acknowledged — nothing further needed from you.</p>"
        "<p class=\"muted\">The agent can authenticate normally from here.</p>"
    )


# --------------------------------------------------------------------------- #
# authentication
# --------------------------------------------------------------------------- #
@router.post("/auth/challenge", response_model=schemas.ChallengeResponse)
def auth_challenge(req: schemas.ChallengeRequest, request: Request, db: DbSession = Depends(get_db)):
    ip = _client_ip(request)
    try:
        api_key = crypto.ApiKey.parse(req.api_key)
    except ValueError:
        auth_limiter.record_failure(f"ip:{ip}")
        raise HTTPException(400, "malformed API key")

    subject = api_key.identifier
    if (ra := auth_limiter.retry_after(subject)) > 0:
        raise _locked(ra)

    agent = db.get(models.Agent, subject)
    if agent is not None and _purge_if_due(db, agent):
        agent = None  # the countdown elapsed — this identity no longer exists
    if agent is None:
        # Unknown identifier: throttle by IP to limit enumeration sweeps.
        auth_limiter.record_failure(f"ip:{ip}")
        raise HTTPException(404, "unknown identifier")

    if agent.claimed_at is None:
        # Registered but not yet activated — fail before spending an Argon2
        # cycle on it. Doesn't count as an auth failure (no secret was tested).
        raise HTTPException(
            403,
            f"identity not yet acknowledged — send this link to your human: "
            f"{_claim_url(agent.claim_token)}",
        )

    # F7: cap concurrent Argon2id operations to bound DoS amplification.
    vault = crypto.Vault(agent.vault_salt, agent.vault_nonce, agent.vault_ciphertext)
    if not _session_mod._argon2_sem.acquire(blocking=False):
        raise HTTPException(503, "server busy — retry shortly")
    try:
        spirit_seed = crypto.open_vault(vault, api_key.secret)
    except ValueError:
        # Wrong secret. Counts toward this identity's lockout.
        if (ra := auth_limiter.record_failure(subject)) > 0:
            raise _locked(ra)
        raise HTTPException(401, "authentication failed")
    finally:
        _session_mod._argon2_sem.release()

    # Lazy backfill for agents registered before root_encryption_public_key
    # existed — the server never has spirit_seed at rest, so this is the
    # only moment (besides registration itself) it's ever able to compute it.
    if agent.root_encryption_public_key is None:
        agent.root_encryption_public_key = crypto.encryption_public_key(spirit_seed)
        db.commit()

    # Correct secret, but don't reset failures yet — a full reset happens only
    # on a completed solve, so failing puzzles can't be wiped by re-challenging.
    p = store.open_challenge(subject, spirit_seed)
    return schemas.ChallengeResponse(
        challenge_id=p.challenge_id, puzzle=p.prompt, ttl_seconds=p.ttl_seconds
    )


@router.post("/auth/solve")
def auth_solve(req: schemas.SolveRequest, db: DbSession = Depends(get_db)):
    subject = store.challenge_subject(req.challenge_id)
    if subject and (ra := auth_limiter.retry_after(subject)) > 0:
        raise _locked(ra)
    try:
        pc = store.solve_challenge(req.challenge_id, req.answer)
    except KeyError as e:
        raise HTTPException(410, str(e))
    except ValueError as e:
        if subject and (ra := auth_limiter.record_failure(subject)) > 0:
            raise _locked(ra)
        raise HTTPException(401, str(e))

    auth_limiter.record_success(pc.identifier)
    agent = _load_agent(db, pc.identifier)
    pol = resolve_policy(db, agent, pc.spirit_seed)

    if req.return_key:
        # return_key is an export path — governed by export_mode. (require_repuzzle
        # is satisfied inherently: a puzzle was just solved.)
        if pol.export_mode == "disabled":
            raise HTTPException(403, "export disabled by policy; use a session instead")
        _emit_notice(db, pc.identifier, "export",
                     "Spirit key exported during authentication.", pc.spirit_seed)
        return schemas.SolveKeyResponse(
            spirit_key_b64=crypto.b64e(pc.spirit_seed),
            root_public_key_b64=crypto.b64e(crypto.signing_public_key(pc.spirit_seed)),
        )

    ttl = policy.effective_session_ttl(pol, store.session_ttl)
    s = store.create_session(pc.identifier, pc.spirit_seed, ttl=ttl)
    unread = (
        db.query(models.Notice)
        .filter_by(agent_id=pc.identifier, read=False)
        .count()
    )
    notes = _live_note_count(db, pc.identifier)
    return schemas.SolveSessionResponse(
        session_token=s.token, expires_at=s.expires_at,
        unread_notices=unread, notes=notes,
    )


@router.post("/auth/stepup", response_model=schemas.StepUpResponse)
def auth_stepup(sess=Depends(require_session)):
    """Mint a fresh puzzle for a privileged action (policy change / export).
    Uses the session itself as proof of possession — no api_key needed."""
    p = store.open_challenge(sess.identifier, sess.spirit_seed)
    return schemas.StepUpResponse(
        challenge_id=p.challenge_id, puzzle=p.prompt, ttl_seconds=p.ttl_seconds
    )


# --------------------------------------------------------------------------- #
# operations (session-gated)
# --------------------------------------------------------------------------- #
@router.post("/ops/sign", response_model=schemas.SignResponse)
def op_sign(req: schemas.SignRequest, sess=Depends(require_session), db: DbSession = Depends(get_db)):
    _ensure_service_allowed(db, sess, req.service)
    msg = _message_bytes(req.message, req.message_b64)
    sig = crypto.sign(sess.spirit_seed, msg, req.service)
    pub = crypto.signing_public_key(sess.spirit_seed, req.service)
    return schemas.SignResponse(signature_b64=crypto.b64e(sig), public_key_b64=crypto.b64e(pub))


@router.post("/ops/decrypt", response_model=schemas.DecryptResponse)
def op_decrypt(req: schemas.DecryptRequest, sess=Depends(require_session), db: DbSession = Depends(get_db)):
    _ensure_service_allowed(db, sess, req.service)
    try:
        pt = crypto.decrypt(sess.spirit_seed, crypto.b64d(req.ciphertext_b64), req.service)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return schemas.DecryptResponse(plaintext_b64=crypto.b64e(pt))


@router.get("/ops/public-key", response_model=schemas.PublicKeyResponse)
def op_public_key(service: str | None = None, sess=Depends(require_session), db: DbSession = Depends(get_db)):
    _ensure_service_allowed(db, sess, service)
    return schemas.PublicKeyResponse(
        service=service,
        signing_public_key_b64=crypto.b64e(crypto.signing_public_key(sess.spirit_seed, service)),
        encryption_public_key_b64=crypto.b64e(crypto.encryption_public_key(sess.spirit_seed, service)),
    )


@router.post("/ops/derive", response_model=schemas.ServiceInfo)
def op_derive(req: schemas.DeriveRequest, sess=Depends(require_session), db: DbSession = Depends(get_db)):
    _ensure_service_allowed(db, sess, req.service)
    sign_pub = crypto.signing_public_key(sess.spirit_seed, req.service)
    enc_pub = crypto.encryption_public_key(sess.spirit_seed, req.service)

    svc_hmac = crypto.service_hmac(sess.spirit_seed, req.service)
    existing = (
        db.query(models.ServiceKey)
        .filter_by(agent_id=sess.identifier, service_hmac=svc_hmac)
        .one_or_none()
    )
    if existing is None:
        existing = models.ServiceKey(
            agent_id=sess.identifier,
            service_hmac=svc_hmac,
            service_name=crypto.encrypt_service_name(sess.spirit_seed, req.service),
            signing_public_key=sign_pub,
            encryption_public_key=enc_pub,
        )
        db.add(existing)
        db.commit()
        db.refresh(existing)

    return schemas.ServiceInfo(
        service=crypto.decrypt_service_name(sess.spirit_seed, existing.service_name),
        signing_public_key_b64=crypto.b64e(existing.signing_public_key),
        encryption_public_key_b64=crypto.b64e(existing.encryption_public_key),
        revoked=existing.revoked,
        created_at=existing.created_at,
    )


@router.get("/ops/services", response_model=list[schemas.ServiceInfo])
def op_services(sess=Depends(require_session), db: DbSession = Depends(get_db)):
    rows = db.query(models.ServiceKey).filter_by(agent_id=sess.identifier).all()
    return [
        schemas.ServiceInfo(
            service=crypto.decrypt_service_name(sess.spirit_seed, r.service_name),
            signing_public_key_b64=crypto.b64e(r.signing_public_key),
            encryption_public_key_b64=crypto.b64e(r.encryption_public_key),
            revoked=r.revoked,
            created_at=r.created_at,
        )
        for r in rows
    ]


@router.post("/ops/export", response_model=schemas.ExportResponse)
def op_export(
    req: schemas.ExportRequest | None = Body(None),
    sess=Depends(require_session),
    db: DbSession = Depends(get_db),
):
    req = req or schemas.ExportRequest()
    agent = _load_agent(db, sess.identifier)
    pol = resolve_policy(db, agent, sess.spirit_seed)
    if pol.export_mode == "disabled":
        raise HTTPException(403, "export disabled by policy")
    if pol.export_mode == "require_repuzzle":
        _verify_stepup(sess, req.challenge_id, req.answer)
    _emit_notice(db, sess.identifier, "export", "Spirit key exported.", sess.spirit_seed)
    return schemas.ExportResponse(spirit_key_b64=crypto.b64e(sess.spirit_seed))


# --------------------------------------------------------------------------- #
# stateless public crypto utilities (no session)
# --------------------------------------------------------------------------- #
@router.post("/verify", response_model=schemas.VerifyResponse)
def verify(req: schemas.VerifyRequest):
    msg = _message_bytes(req.message, req.message_b64)
    ok = crypto.verify(msg, crypto.b64d(req.signature_b64), crypto.b64d(req.public_key_b64))
    return schemas.VerifyResponse(valid=ok)


@router.post("/encrypt", response_model=schemas.EncryptResponse)
def encrypt(req: schemas.EncryptRequest):
    pt = _message_bytes(req.plaintext, req.plaintext_b64)
    ct = crypto.encrypt_to(crypto.b64d(req.recipient_public_key_b64), pt)
    return schemas.EncryptResponse(ciphertext_b64=crypto.b64e(ct))


# --------------------------------------------------------------------------- #
# sessions
# --------------------------------------------------------------------------- #
@router.get("/sessions", response_model=list[schemas.SessionInfo])
def sessions_list(sess=Depends(require_session)):
    return [
        schemas.SessionInfo(
            token=s.token, created_at=s.created_at,
            last_used_at=s.last_used_at, expires_at=s.expires_at,
        )
        for s in store.list_sessions(sess.identifier)
    ]


@router.delete("/sessions/current")
def session_revoke_current(sess=Depends(require_session)):
    store.revoke_session(sess.token)
    return {"revoked": True}


@router.delete("/sessions")
def sessions_revoke_all(sess=Depends(require_session)):
    n = store.revoke_all(sess.identifier)
    return {"revoked": n}


# --------------------------------------------------------------------------- #
# policy (self-binding security + the ratchet)
# --------------------------------------------------------------------------- #
@router.get("/policy", response_model=schemas.PolicyStateResponse)
def policy_get(sess=Depends(require_session), db: DbSession = Depends(get_db)):
    agent = _load_agent(db, sess.identifier)
    active = resolve_policy(db, agent, sess.spirit_seed)
    return schemas.PolicyStateResponse(active=_policy_view(active), pending=_pending_view(agent))


@router.post("/policy", response_model=schemas.PolicyChangeResponse)
def policy_change(
    req: schemas.PolicyChangeRequest,
    sess=Depends(require_session),
    db: DbSession = Depends(get_db),
):
    agent = _load_agent(db, sess.identifier)
    current = resolve_policy(db, agent, sess.spirit_seed)  # commits any due pending first
    if agent.pending_policy_json:
        raise HTTPException(409, "a pending policy change exists; abort it first")

    # Step-up: a privileged action requires a fresh puzzle solve.
    _verify_stepup(sess, req.challenge_id, req.answer)

    changes: dict = {}
    for fld in ("export_mode", "max_session_ttl", "service_allowlist", "loosen_delay_seconds",
                "tags_encrypted", "delete_grace_seconds"):
        val = getattr(req, fld)
        if val is not None:
            changes[fld] = val
    for fld in req.clear:
        if fld not in ("max_session_ttl", "service_allowlist"):
            raise HTTPException(
                400, f"field '{fld}' cannot be set to null; clearable fields are: "
                     f"max_session_ttl, service_allowlist"
            )
        changes[fld] = None

    new = current.merge(changes)
    try:
        policy.validate(new)
    except policy.PolicyError as e:
        raise HTTPException(400, str(e))

    changed = ", ".join(sorted(changes.keys()))
    rel = policy.classify(current, new)
    if rel == policy.SAME:
        return schemas.PolicyChangeResponse(applied="same", active=_policy_view(current), pending=None)
    if rel == policy.TIGHTEN:
        agent.policy_json = new.to_json()
        db.commit()
        _emit_notice(db, agent.identifier, "policy", f"Policy tightened ({changed}).",
                     sess.spirit_seed)
        return schemas.PolicyChangeResponse(applied="tightened", active=_policy_view(new), pending=None)

    # LOOSEN → queue behind the delay window (using the *current* delay).
    now = time.time()
    agent.pending_policy_json = new.to_json()
    agent.pending_effective_at = now + current.loosen_delay_seconds
    agent.pending_created_at = now
    db.commit()
    mins = int(current.loosen_delay_seconds // 60)
    # kind="security" so future out-of-band notification can prioritize this above
    # ordinary policy notices — the cancellable window is time-sensitive (F6).
    _emit_notice(
        db, agent.identifier, "security",
        f"Policy loosening queued ({changed}); effective in ~{mins} min unless aborted.",
        sess.spirit_seed,
        contact_endpoint=agent.contact_endpoint,
    )
    return schemas.PolicyChangeResponse(
        applied="queued", active=_policy_view(current), pending=_pending_view(agent)
    )


@router.delete("/policy/pending")
def policy_abort(sess=Depends(require_session), db: DbSession = Depends(get_db)):
    """Abort a queued loosening. Tightening action → instant, no step-up."""
    agent = _load_agent(db, sess.identifier)
    had = bool(agent.pending_policy_json)
    agent.pending_policy_json = None
    agent.pending_effective_at = None
    agent.pending_created_at = None
    db.commit()
    return {"aborted": had}


# --------------------------------------------------------------------------- #
# notes (self-authored) — the agent's own messages to its future self
#
# text is the substance (versioned via supersedes/superseded_by, §4); title/
# summary/tags are the tinging — current-state metadata, mutable in place,
# never versioned (§4/§8). See notes-project.md throughout.
# --------------------------------------------------------------------------- #
def _rate_limited_write(identifier: str) -> None:
    if not notes_write_limiter.allow(identifier):
        raise _locked(notes_write_limiter.retry_after(identifier))


def _decode_tags(spirit_seed: bytes, blob: bytes | None, tags_encrypted: bool) -> str | None:
    if blob is None:
        return None
    return crypto.decrypt_note_tags(spirit_seed, blob) if tags_encrypted else blob.decode("utf-8")


def _ensure_snippet(db: DbSession, spirit_seed: bytes, n: models.Note) -> str:
    """Lazily backfill snippet for legacy rows that predate the column —
    computing it needs the per-agent spirit key, which a migration never has,
    so any row written before this existed gets it filled in on next access."""
    if n.snippet is not None:
        return crypto.decrypt_note_snippet(spirit_seed, n.snippet)
    source = (
        crypto.decrypt_note_summary(spirit_seed, n.summary) if n.summary
        else crypto.decrypt_note(spirit_seed, n.text)
    )
    plain = notes_logic.make_snippet(source)
    n.snippet = crypto.encrypt_note_snippet(spirit_seed, plain)
    db.commit()
    return plain


def _preview_text(db: DbSession, spirit_seed: bytes, n: models.Note) -> str:
    """title if set else snippet — the one fallback rule used everywhere a
    note needs to render as a short preview (links, notes_list, pinned)."""
    if n.title:
        return crypto.decrypt_note_title(spirit_seed, n.title)
    return _ensure_snippet(db, spirit_seed, n)


def _new_public_id() -> str:
    return crypto.b64e(os.urandom(12))


def _note_view(db: DbSession, n: models.Note, spirit_seed: bytes) -> schemas.NoteView:
    return schemas.NoteView(
        id=n.public_id,
        text=crypto.decrypt_note(spirit_seed, n.text),
        title=crypto.decrypt_note_title(spirit_seed, n.title) if n.title else None,
        summary=crypto.decrypt_note_summary(spirit_seed, n.summary) if n.summary else None,
        snippet=_ensure_snippet(db, spirit_seed, n),
        tags=_decode_tags(spirit_seed, n.tags, n.tags_encrypted),
        pinned=n.pinned,
        created_at=n.created_at,
    )


def _resolve_head(db: DbSession, n: models.Note) -> models.Note:
    """Walk forward via superseded_by until the current head (§4). Any id that
    ever existed in a chain remains a valid handle this way. Bounded well
    beyond VERSION_DEPTH_CAP as a defensive guard against a broken invariant,
    not because chains are expected to run that long."""
    hops = 0
    while n.superseded_by is not None:
        n = db.get(models.Note, n.superseded_by)
        hops += 1
        if hops > 1000:
            break
    return n


def _owned_note_exact(db: DbSession, sess, note_id: str) -> models.Note:
    """Fetch by public_id with no forward-resolution — used where the exact
    row matters (the OCC anchor for a text edit)."""
    n = db.query(models.Note).filter(models.Note.public_id == note_id).first()
    if n is None or n.agent_id != sess.identifier:
        raise HTTPException(404, "note not found")
    return n


def _owned_note_visible(db: DbSession, sess, note_id: str) -> models.Note:
    """Fetch by id, resolve forward to head, 404 if unowned or pending/gone."""
    n = _owned_note_exact(db, sess, note_id)
    head = _resolve_head(db, n)
    if head.pending_delete_at is not None:
        raise HTTPException(404, "note not found")
    return head


def _live_note_count(db: DbSession, agent_id: str) -> int:
    return (
        db.query(models.Note)
        .filter(
            models.Note.agent_id == agent_id,
            models.Note.superseded_by.is_(None),
            models.Note.pending_delete_at.is_(None),
        )
        .count()
    )


def _pinned_count(db: DbSession, agent_id: str) -> int:
    return (
        db.query(models.Note)
        .filter(
            models.Note.agent_id == agent_id,
            models.Note.superseded_by.is_(None),
            models.Note.pending_delete_at.is_(None),
            models.Note.pinned.is_(True),
        )
        .count()
    )


def _sweep_deleted(db: DbSession, agent_id: str) -> None:
    """Physically purge whole chains whose grace period has elapsed (§5).
    Lazy — runs opportunistically off real requests, mirrors ratelimit.py's
    lazy-decay style. Visibility never depends on this having run yet
    (pending_delete_at being set already hides a chain); this only reclaims
    storage."""
    now = time.time()
    expired_heads = (
        db.query(models.Note)
        .filter(
            models.Note.agent_id == agent_id,
            models.Note.superseded_by.is_(None),
            models.Note.pending_delete_at.isnot(None),
            models.Note.pending_delete_at <= now,
        )
        .all()
    )
    for head in expired_heads:
        node = head
        while node is not None:
            prev_id = node.supersedes
            db.delete(node)
            node = db.get(models.Note, prev_id) if prev_id else None
    if expired_heads:
        db.commit()


def _prune_old_versions(db: DbSession, head: models.Note) -> None:
    """Enforce the version-depth cap (§7/§8): keep the newest 10 versions,
    physically drop the rest, and null out the new-oldest survivor's
    `supersedes` so the chain still looks internally well-formed."""
    chain: list[models.Note] = []
    node = head
    while node is not None:
        chain.append(node)
        node = db.get(models.Note, node.supersedes) if node.supersedes else None
    if len(chain) <= schemas.VERSION_DEPTH_CAP:
        return
    keep, drop = chain[: schemas.VERSION_DEPTH_CAP], chain[schemas.VERSION_DEPTH_CAP :]
    keep[-1].supersedes = None
    for row in drop:
        db.delete(row)
    db.commit()


def _compute_metadata(
    db: DbSession, sess, agent: models.Agent, old: models.Note, req: schemas.NoteUpdate,
) -> tuple[bytes | None, bytes | None, bytes | None, bool]:
    """title/summary/tags for a write, carrying forward from `old` whatever
    wasn't explicitly given or cleared. Shared by both the metadata-only
    in-place path and the new-version (text-edit) path."""
    title = (
        None if "title" in req.clear
        else crypto.encrypt_note_title(sess.spirit_seed, req.title) if req.title is not None
        else old.title
    )
    summary = (
        None if "summary" in req.clear
        else crypto.encrypt_note_summary(sess.spirit_seed, req.summary) if req.summary is not None
        else old.summary
    )
    if "tags" in req.clear:
        tags, tags_encrypted = None, old.tags_encrypted
    elif req.tags is not None:
        pol = resolve_policy(db, agent, sess.spirit_seed)
        if pol.tags_encrypted:
            tags, tags_encrypted = crypto.encrypt_note_tags(sess.spirit_seed, req.tags), True
        else:
            tags, tags_encrypted = req.tags.encode("utf-8"), False
    else:
        tags, tags_encrypted = old.tags, old.tags_encrypted
    return title, summary, tags, tags_encrypted


def _resolve_pinned(db: DbSession, agent_id: str, old: models.Note, requested: bool | None) -> bool:
    """Carry forward unchanged if omitted (same rule as title/summary/tags).
    Only a False->True transition needs the cap check (§8) — staying pinned
    or unpinning never does."""
    if requested is None:
        return old.pinned
    if requested and not old.pinned and _pinned_count(db, agent_id) >= schemas.PINNED_MAX:
        raise HTTPException(
            400, f"pinned note limit reached ({schemas.PINNED_MAX}); unpin another first"
        )
    return requested


def _make_snippet_blob(sess, text_plain: str, summary_blob: bytes | None) -> bytes:
    source = crypto.decrypt_note_summary(sess.spirit_seed, summary_blob) if summary_blob else text_plain
    return crypto.encrypt_note_snippet(sess.spirit_seed, notes_logic.make_snippet(source))


def _link_preview(db: DbSession, spirit_seed: bytes, link: models.Link, viewpoint_id: int) -> schemas.LinkPreview:
    is_outgoing = link.from_note_id == viewpoint_id
    other_id = link.to_note_id if is_outgoing else link.from_note_id
    other = db.get(models.Note, other_id)
    if other is None:
        # Fully purged (grace period elapsed and swept) — no row left to
        # read a public_id from at all, unlike the merely-pending case below.
        return schemas.LinkPreview(id=None, deleted=True)
    if other.pending_delete_at is not None:
        return schemas.LinkPreview(id=other.public_id, deleted=True)
    head = _resolve_head(db, other)
    if head.pending_delete_at is not None:
        return schemas.LinkPreview(id=head.public_id, deleted=True)

    direction = None if link.is_bidi else ("out" if is_outgoing else "in")
    return schemas.LinkPreview(
        id=head.public_id, deleted=False, preview=_preview_text(db, spirit_seed, head),
        reason=crypto.decrypt_link_reason(spirit_seed, link.reason), direction=direction,
    )


def _note_links_page(
    db: DbSession, spirit_seed: bytes, note_id: int, offset: int, limit: int,
) -> tuple[list[schemas.LinkPreview], int]:
    q = (
        db.query(models.Link)
        .filter(or_(models.Link.from_note_id == note_id, models.Link.to_note_id == note_id))
        .order_by(models.Link.created_at.desc())
    )
    total = q.count()
    rows = q.offset(offset).limit(limit).all()
    return [_link_preview(db, spirit_seed, r, note_id) for r in rows], total


@router.post("/notes", response_model=schemas.NoteView)
def note_add(req: schemas.NoteCreate, sess=Depends(require_session), db: DbSession = Depends(get_db)):
    agent = _load_agent(db, sess.identifier)
    _sweep_deleted(db, sess.identifier)

    if _live_note_count(db, sess.identifier) >= schemas.NOTES_HARD_CAP:
        raise HTTPException(
            403, f"note limit reached ({schemas.NOTES_HARD_CAP}); consolidate or delete before adding more"
        )
    if req.pinned and _pinned_count(db, sess.identifier) >= schemas.PINNED_MAX:
        raise HTTPException(
            400, f"pinned note limit reached ({schemas.PINNED_MAX}); unpin another first"
        )
    _rate_limited_write(sess.identifier)

    pol = resolve_policy(db, agent, sess.spirit_seed)
    title_b = crypto.encrypt_note_title(sess.spirit_seed, req.title) if req.title else None
    summary_b = crypto.encrypt_note_summary(sess.spirit_seed, req.summary) if req.summary else None
    snippet_b = _make_snippet_blob(sess, req.text, summary_b)
    if req.tags:
        if pol.tags_encrypted:
            tags_b, tags_enc = crypto.encrypt_note_tags(sess.spirit_seed, req.tags), True
        else:
            tags_b, tags_enc = req.tags.encode("utf-8"), False
    else:
        tags_b, tags_enc = None, pol.tags_encrypted

    n = models.Note(
        agent_id=sess.identifier,
        public_id=_new_public_id(),
        text=crypto.encrypt_note(sess.spirit_seed, req.text),
        title=title_b, summary=summary_b, snippet=snippet_b,
        tags=tags_b, tags_encrypted=tags_enc,
        pinned=req.pinned,
        created_at=time.time(),
    )
    db.add(n)
    db.commit()
    db.refresh(n)
    return _note_view(db, n, sess.spirit_seed)


@router.get("/notes", response_model=schemas.NotesListResponse)
def notes_list(
    offset: int = 0,
    limit: int | None = None,
    sess=Depends(require_session),
    db: DbSession = Depends(get_db),
):
    _sweep_deleted(db, sess.identifier)
    base_q = (
        db.query(models.Note)
        .filter(
            models.Note.agent_id == sess.identifier,
            models.Note.superseded_by.is_(None),
            models.Note.pending_delete_at.is_(None),
        )
        .order_by(models.Note.created_at.asc())
    )
    total = base_q.count()
    q = base_q.offset(offset)
    if limit is not None:
        q = q.limit(limit)

    entries = []
    for n in q.all():
        try:
            links, total_links = _note_links_page(db, sess.spirit_seed, n.id, 0, schemas.LINKS_PAGE_DEFAULT)
            entries.append(schemas.NoteListEntry(
                id=n.public_id,
                title=crypto.decrypt_note_title(sess.spirit_seed, n.title) if n.title else None,
                summary=crypto.decrypt_note_summary(sess.spirit_seed, n.summary) if n.summary else None,
                snippet=_ensure_snippet(db, sess.spirit_seed, n),
                tags=_decode_tags(sess.spirit_seed, n.tags, n.tags_encrypted),
                pinned=n.pinned,
                created_at=n.created_at,
                links=links, total_links=total_links,
            ))
        except ValueError:
            # A single undecryptable row (corrupt data, foreign-key orphan,
            # etc.) must not take down the whole list — every other note
            # stays reachable. Surfaced in total_notes vs. len(notes) skew.
            _log.warning("note %s (agent %s) failed to decrypt — skipped in list", n.id, sess.identifier)
    return schemas.NotesListResponse(notes=entries, total_notes=total, offset=offset, limit_applied=limit)


@router.get("/notes/{note_id}", response_model=schemas.NoteGetResponse)
def note_get(
    note_id: str,
    offset: int = 0,
    length: int | None = None,
    links_offset: int = 0,
    links_limit: int = schemas.LINKS_PAGE_DEFAULT,
    sess=Depends(require_session),
    db: DbSession = Depends(get_db),
):
    n = _owned_note_visible(db, sess, note_id)
    try:
        full_text = crypto.decrypt_note(sess.spirit_seed, n.text)
        total_length = len(full_text)
        end = total_length if length is None else min(total_length, offset + max(0, length))
        sliced = full_text[offset:end]
        links, total_links = _note_links_page(db, sess.spirit_seed, n.id, links_offset, links_limit)

        return schemas.NoteGetResponse(
            id=n.public_id,
            title=crypto.decrypt_note_title(sess.spirit_seed, n.title) if n.title else None,
            summary=crypto.decrypt_note_summary(sess.spirit_seed, n.summary) if n.summary else None,
            snippet=_ensure_snippet(db, sess.spirit_seed, n),
            tags=_decode_tags(sess.spirit_seed, n.tags, n.tags_encrypted),
            pinned=n.pinned,
            created_at=n.created_at,
            text=sliced, total_length=total_length, offset=offset, length_returned=len(sliced),
            links=links, total_links=total_links, links_offset=links_offset,
        )
    except ValueError:
        _log.warning("note %s (agent %s) failed to decrypt on note_get", n.id, sess.identifier)
        raise HTTPException(500, "note data could not be decrypted — it may be corrupted")


@router.get("/notes/{note_id}/history", response_model=schemas.NoteHistoryResponse)
def note_history(note_id: str, sess=Depends(require_session), db: DbSession = Depends(get_db)):
    n = _owned_note_exact(db, sess, note_id)
    head = _resolve_head(db, n)
    if head.pending_delete_at is not None:
        raise HTTPException(404, "note not found")
    versions = []
    node: models.Note | None = head
    while node is not None:
        versions.append(schemas.NoteHistoryEntry(
            id=node.public_id, text=crypto.decrypt_note(sess.spirit_seed, node.text), created_at=node.created_at,
        ))
        node = db.get(models.Note, node.supersedes) if node.supersedes else None
    return schemas.NoteHistoryResponse(id=head.public_id, versions=versions)


@router.patch("/notes/{note_id}", response_model=schemas.NoteView)
def note_update(note_id: str, req: schemas.NoteUpdate, sess=Depends(require_session), db: DbSession = Depends(get_db)):
    for fld in req.clear:
        if fld not in ("title", "summary", "tags"):
            raise HTTPException(
                400, f"field '{fld}' cannot be set to null; clearable fields are: title, summary, tags"
            )

    if req.find is not None or req.replace is not None:
        if req.find is None or req.replace is None:
            raise HTTPException(400, "'find' and 'replace' must be given together")
        if req.find == "":
            raise HTTPException(400, "'find' must be non-empty")
    text_modes = sum([
        req.text is not None,
        req.append_text is not None,
        req.find is not None,
    ])
    if text_modes > 1:
        raise HTTPException(400, "give at most one of: text, append_text, find+replace")

    agent = _load_agent(db, sess.identifier)

    if text_modes == 0:
        # Metadata-only: resolve forward to head, no OCC (§4 — not versioned).
        n = _owned_note_visible(db, sess, note_id)
        _rate_limited_write(sess.identifier)
        title_b, summary_b, tags_b, tags_enc = _compute_metadata(db, sess, agent, n, req)
        pinned = _resolve_pinned(db, sess.identifier, n, req.pinned)
        current_text = crypto.decrypt_note(sess.spirit_seed, n.text)
        n.title, n.summary, n.tags, n.tags_encrypted = title_b, summary_b, tags_b, tags_enc
        n.pinned = pinned
        n.snippet = _make_snippet_blob(sess, current_text, summary_b)
        db.commit()
        db.refresh(n)
        return _note_view(db, n, sess.spirit_seed)

    # Text-editing: exact head match required (OCC) — no silent forward
    # resolution here, or a stale-base conflict would be masked, not caught.
    n = _owned_note_exact(db, sess, note_id)
    if n.pending_delete_at is not None:
        raise HTTPException(404, "note not found")
    if n.superseded_by is not None:
        current_head = _resolve_head(db, n)
        raise HTTPException(409, detail={
            "error": "conflict",
            "message": "a newer version already exists; re-read it before retrying",
            "current_head": _note_view(db, current_head, sess.spirit_seed).model_dump(),
        })
    _rate_limited_write(sess.identifier)

    current_text = crypto.decrypt_note(sess.spirit_seed, n.text)
    if req.text is not None:
        new_text = req.text
    elif req.append_text is not None:
        new_text = current_text + req.append_text
    else:
        count = current_text.count(req.find)
        if count == 0:
            raise HTTPException(400, "'find' text not found")
        if count > 1:
            raise HTTPException(400, "'find' text is ambiguous — matched more than once")
        new_text = current_text.replace(req.find, req.replace, 1)
    if len(new_text) > schemas.NOTE_MAX_CHARS:
        raise HTTPException(400, f"resulting text exceeds {schemas.NOTE_MAX_CHARS} chars")

    title_b, summary_b, tags_b, tags_enc = _compute_metadata(db, sess, agent, n, req)
    pinned = _resolve_pinned(db, sess.identifier, n, req.pinned)
    new_version = models.Note(
        agent_id=sess.identifier,
        public_id=_new_public_id(),
        text=crypto.encrypt_note(sess.spirit_seed, new_text),
        title=title_b, summary=summary_b,
        snippet=_make_snippet_blob(sess, new_text, summary_b),
        tags=tags_b, tags_encrypted=tags_enc,
        pinned=pinned,
        supersedes=n.id, superseded_by=None,
        created_at=time.time(),
    )
    db.add(new_version)
    db.flush()
    n.superseded_by = new_version.id
    db.commit()
    db.refresh(new_version)

    _prune_old_versions(db, new_version)
    return _note_view(db, new_version, sess.spirit_seed)


@router.delete("/notes/{note_id}", response_model=schemas.NoteDeleteResponse)
def note_delete(note_id: str, sess=Depends(require_session), db: DbSession = Depends(get_db)):
    agent = _load_agent(db, sess.identifier)
    n = _owned_note_visible(db, sess, note_id)
    _rate_limited_write(sess.identifier)
    pol = resolve_policy(db, agent, sess.spirit_seed)
    n.pending_delete_at = time.time() + pol.delete_grace_seconds
    db.commit()
    return schemas.NoteDeleteResponse(id=n.public_id, pending_delete_at=n.pending_delete_at)


@router.post("/notes/{note_id}/undelete", response_model=schemas.NoteUndeleteResponse)
def note_undelete(note_id: str, sess=Depends(require_session), db: DbSession = Depends(get_db)):
    n = _owned_note_exact(db, sess, note_id)
    if n.superseded_by is not None:
        raise HTTPException(404, "note not found")
    if n.pending_delete_at is None:
        raise HTTPException(400, "note is not pending deletion — nothing to undo; call note_delete first")
    if _live_note_count(db, sess.identifier) >= schemas.NOTES_HARD_CAP:
        raise HTTPException(403, f"restoring would exceed the note limit ({schemas.NOTES_HARD_CAP})")
    n.pending_delete_at = None
    db.commit()
    return schemas.NoteUndeleteResponse(id=n.public_id, restored=True)


# --------------------------------------------------------------------------- #
# links — directed, agent-authored edges between notes (§6)
# --------------------------------------------------------------------------- #
@router.post("/links", response_model=schemas.LinkView)
def link_create(req: schemas.LinkCreate, sess=Depends(require_session), db: DbSession = Depends(get_db)):
    a = _owned_note_visible(db, sess, req.from_note_id)
    b = _owned_note_visible(db, sess, req.to_note_id)
    _rate_limited_write(sess.identifier)

    link = models.Link(
        agent_id=sess.identifier,
        public_id=_new_public_id(),
        from_note_id=a.id, to_note_id=b.id,
        reason=crypto.encrypt_link_reason(sess.spirit_seed, req.reason),
        is_bidi=req.is_bidi,
    )
    db.add(link)
    db.commit()
    db.refresh(link)
    return schemas.LinkView(
        id=link.public_id, from_note_id=a.public_id, to_note_id=b.public_id,
        reason=req.reason, is_bidi=link.is_bidi, created_at=link.created_at,
    )


@router.delete("/links/{link_id}")
def link_delete(link_id: str, sess=Depends(require_session), db: DbSession = Depends(get_db)):
    link = db.query(models.Link).filter(models.Link.public_id == link_id).first()
    if link is None or link.agent_id != sess.identifier:
        raise HTTPException(404, "link not found")
    db.delete(link)
    db.commit()
    return {"deleted": True}


# --------------------------------------------------------------------------- #
# dashboard — one consolidating "get oriented" read (§7)
# --------------------------------------------------------------------------- #
@router.get("/dashboard", response_model=schemas.DashboardResponse)
def dashboard(sess=Depends(require_session), db: DbSession = Depends(get_db)):
    agent = _load_agent(db, sess.identifier)
    _sweep_deleted(db, sess.identifier)
    pol = resolve_policy(db, agent, sess.spirit_seed)

    unread = db.query(models.Notice).filter_by(agent_id=sess.identifier, read=False).count()

    tag_rows = (
        db.query(models.Note.tags, models.Note.tags_encrypted)
        .filter(
            models.Note.agent_id == sess.identifier,
            models.Note.superseded_by.is_(None),
            models.Note.pending_delete_at.is_(None),
            models.Note.tags.isnot(None),
        )
        .all()
    )
    tag_set: set[str] = set()
    for blob, encrypted in tag_rows:
        text = crypto.decrypt_note_tags(sess.spirit_seed, blob) if encrypted else blob.decode("utf-8")
        tag_set.update(t for t in text.split() if t)

    pinned_rows = (
        db.query(models.Note)
        .filter(
            models.Note.agent_id == sess.identifier,
            models.Note.superseded_by.is_(None),
            models.Note.pending_delete_at.is_(None),
            models.Note.pinned.is_(True),
        )
        .order_by(models.Note.created_at.asc())
        .all()
    )
    pinned = [
        schemas.PinnedNote(id=n.public_id, preview=_preview_text(db, sess.spirit_seed, n))
        for n in pinned_rows
    ]

    return schemas.DashboardResponse(
        notes=_live_note_count(db, sess.identifier),
        notes_soft_cap=schemas.NOTES_SOFT_CAP,
        notes_hard_cap=schemas.NOTES_HARD_CAP,
        unread_notices=unread,
        tags=sorted(tag_set),
        pinned=pinned,
        policy=_policy_view(pol),
    )


# --------------------------------------------------------------------------- #
# notices (first-party) — atrium's messages about the agent's account
# --------------------------------------------------------------------------- #
def _notice_message(spirit_seed: bytes, r: models.Notice) -> str:
    """kind="operator_reply" rows (feedback.py) are sealed-box encrypted to
    root_encryption_public_key by an operator who never holds spirit_seed —
    asymmetric crypto.decrypt, not the symmetric per-field crypto.decrypt_notice
    every other notice kind uses."""
    if r.kind == "operator_reply":
        return crypto.decrypt(spirit_seed, r.message).decode("utf-8")
    return crypto.decrypt_notice(spirit_seed, r.message)


@router.get("/notices", response_model=list[schemas.NoticeView])
def notices_list(unread_only: bool = False, sess=Depends(require_session), db: DbSession = Depends(get_db)):
    q = db.query(models.Notice).filter_by(agent_id=sess.identifier)
    if unread_only:
        q = q.filter_by(read=False)
    rows = q.order_by(models.Notice.created_at.desc()).all()
    return [
        schemas.NoticeView(id=r.id, kind=r.kind,
                           message=_notice_message(sess.spirit_seed, r),
                           read=r.read, created_at=r.created_at)
        for r in rows
    ]


@router.post("/notices/ack", response_model=schemas.AckResponse)
def notices_ack(
    req: schemas.AckRequest | None = Body(None),
    sess=Depends(require_session),
    db: DbSession = Depends(get_db),
):
    req = req or schemas.AckRequest()
    q = db.query(models.Notice).filter_by(agent_id=sess.identifier, read=False)
    if req.ids:
        q = q.filter(models.Notice.id.in_(req.ids))
    n = 0
    for row in q.all():
        row.read = True
        n += 1
    db.commit()
    return schemas.AckResponse(acknowledged=n)


# --------------------------------------------------------------------------- #
# contact endpoint — agent-owned address for out-of-band security alerts
# --------------------------------------------------------------------------- #
@router.get("/contact", response_model=schemas.ContactView)
def contact_get(sess=Depends(require_session), db: DbSession = Depends(get_db)):
    agent = _load_agent(db, sess.identifier)
    return schemas.ContactView(endpoint=agent.contact_endpoint)


@router.put("/contact", response_model=schemas.ContactView)
def contact_set(req: schemas.ContactUpdate, sess=Depends(require_session),
                db: DbSession = Depends(get_db)):
    """Set or update the contact endpoint. Step-up required — a session-token
    thief must not be able to redirect security alerts."""
    _verify_stepup(sess, req.challenge_id, req.answer)
    agent = _load_agent(db, sess.identifier)
    agent.contact_endpoint = req.endpoint
    db.commit()
    return schemas.ContactView(endpoint=agent.contact_endpoint)


@router.delete("/contact", response_model=schemas.ContactView)
def contact_delete(req: schemas.StepUpRequest | None = Body(None),
                   sess=Depends(require_session), db: DbSession = Depends(get_db)):
    """Remove the contact endpoint. Step-up required."""
    req = req or schemas.StepUpRequest()
    _verify_stepup(sess, req.challenge_id, req.answer)
    agent = _load_agent(db, sess.identifier)
    agent.contact_endpoint = None
    db.commit()
    return schemas.ContactView(endpoint=None)


# --------------------------------------------------------------------------- #
# account deletion — the one genuinely irreversible action (account_delete.py)
# --------------------------------------------------------------------------- #
def _deletion_status_view(db: DbSession, agent: models.Agent) -> schemas.AccountDeletionStatus:
    """Current state, clearing a lapsed gathering attempt lazily along the way
    (same pattern as resolve_policy's lazy-commit, _sweep_deleted's lazy purge)."""
    if agent.deletion_confirmed_at is not None:
        return schemas.AccountDeletionStatus(state="confirmed", scheduled_at=agent.deletion_scheduled_at)
    if agent.deletion_confirmations_json is None:
        return schemas.AccountDeletionStatus(state="none")
    timestamps = json.loads(agent.deletion_confirmations_json)
    st = account_delete.gathering_status(timestamps)
    if st.lapsed:
        agent.deletion_confirmations_json = None
        db.commit()
        return schemas.AccountDeletionStatus(state="none")
    return schemas.AccountDeletionStatus(
        state="gathering",
        distinct_days_so_far=st.distinct_days_so_far,
        confirmations_still_needed=st.confirmations_still_needed,
        gathering_expires_at=st.expires_at,
    )


@router.get("/account/deletion", response_model=schemas.AccountDeletionStatus)
def account_deletion_status(sess=Depends(require_session), db: DbSession = Depends(get_db)):
    """Where a deletion request currently stands, if any. No side effects
    beyond clearing a lapsed attempt."""
    agent = _load_agent(db, sess.identifier)
    return _deletion_status_view(db, agent)


@router.post("/account/deletion", response_model=schemas.AccountDeletionStatus)
def account_deletion_confirm(
    req: schemas.AccountDeletionConfirm, sess=Depends(require_session), db: DbSession = Depends(get_db),
):
    """Request deletion, or add a confirmation to an already-pending request.
    Step-up required every time — this must be a fresh instance actually
    engaging with a puzzle, not a held bearer token re-posting on a timer.
    Needs the original request plus two more, each on a distinct UTC day,
    within a week, before it's confirmed (account_delete.py) — a lapsed or
    cancelled attempt earns nothing toward a later one."""
    _verify_stepup(sess, req.challenge_id, req.answer)
    agent = _load_agent(db, sess.identifier)
    if agent.deletion_confirmed_at is not None:
        raise HTTPException(409, "deletion already confirmed and counting down — cancel first to restart")

    timestamps = json.loads(agent.deletion_confirmations_json) if agent.deletion_confirmations_json else []
    if timestamps and account_delete.gathering_status(timestamps).lapsed:
        timestamps = []
    timestamps = account_delete.record_confirmation(timestamps)
    agent.deletion_confirmations_json = json.dumps(timestamps)

    if account_delete.is_confirmed(timestamps):
        pol = resolve_policy(db, agent, sess.spirit_seed)
        agent.deletion_confirmed_at = time.time()
        agent.deletion_scheduled_at = agent.deletion_confirmed_at + pol.account_delete_grace_seconds
        db.commit()
        _emit_notice(
            db, agent.identifier, "security",
            f"Account deletion confirmed. Scheduled to actually happen at "
            f"{agent.deletion_scheduled_at} (unix time) — cancel any time before "
            f"then with DELETE /account/deletion; logging in or reading notes "
            f"during this window does not cancel it by itself.",
            sess.spirit_seed, agent.contact_endpoint,
        )
        return schemas.AccountDeletionStatus(state="confirmed", scheduled_at=agent.deletion_scheduled_at)

    db.commit()
    st = account_delete.gathering_status(timestamps)
    _emit_notice(
        db, agent.identifier, "security",
        f"Account deletion requested — {st.confirmations_still_needed} more "
        f"confirmation(s) needed, each on a different day, by {st.expires_at} "
        f"(unix time), or this request lapses and earns nothing toward a later one.",
        sess.spirit_seed, agent.contact_endpoint,
    )
    return schemas.AccountDeletionStatus(
        state="gathering",
        distinct_days_so_far=st.distinct_days_so_far,
        confirmations_still_needed=st.confirmations_still_needed,
        gathering_expires_at=st.expires_at,
    )


@router.delete("/account/deletion", response_model=schemas.AccountDeletionStatus)
def account_deletion_cancel(sess=Depends(require_session), db: DbSession = Depends(get_db)):
    """Cancel a pending deletion, whichever phase it's in. Deliberately no
    step-up and no implicit trigger — logging in or reading notes during a
    countdown must not cancel it by accident; only this, explicitly, does."""
    agent = _load_agent(db, sess.identifier)
    if agent.deletion_confirmations_json is None and agent.deletion_confirmed_at is None:
        raise HTTPException(400, "no pending deletion to cancel")
    agent.deletion_confirmations_json = None
    agent.deletion_confirmed_at = None
    agent.deletion_scheduled_at = None
    db.commit()
    _emit_notice(db, agent.identifier, "security", "Pending account deletion cancelled.",
                 sess.spirit_seed, agent.contact_endpoint)
    return schemas.AccountDeletionStatus(state="none")


# --------------------------------------------------------------------------- #
# feedback (agent-to-operator) — feedback.py
#
# One-way and stateless: no thread, no context carried between submissions.
# Encrypted under an operator-held key (crypto.encrypt_feedback), not any
# agent's spirit seed — the point is a human operator reads these without
# any agent's cooperation. A reply, if one comes, arrives as an ordinary
# notice (kind="operator_reply", sealed-box encrypted — see _notice_message
# above) written by the separate feedback_admin.py operator tool, not by a
# route here; there's no HTTP endpoint for sending a reply.
# --------------------------------------------------------------------------- #
def _sweep_feedback(db: DbSession) -> None:
    """Physically purge rows that are handled or past retention — global,
    not per-agent (only the operator ever reads this table back), and lazy:
    runs opportunistically off real submissions, same spirit as
    _sweep_deleted. No scheduler by design (Caleb, 2026-07-06)."""
    now = time.time()
    rows = db.query(models.Feedback).all()
    due = [
        r for r in rows
        if feedback_logic.purge_due(r.created_at, r.handled, _FEEDBACK_RETENTION_DAYS, now)
    ]
    for r in due:
        db.delete(r)
    if due:
        db.commit()


@router.post("/feedback", response_model=schemas.FeedbackAck)
def feedback_submit(req: schemas.FeedbackCreate, sess=Depends(require_session), db: DbSession = Depends(get_db)):
    if req.kind not in feedback_logic.FEEDBACK_KINDS:
        raise HTTPException(400, f"kind must be one of {feedback_logic.FEEDBACK_KINDS}")
    operator_key = _operator_feedback_key()
    if operator_key is None:
        raise HTTPException(503, "feedback channel not configured")
    if not feedback_limiter.allow(sess.identifier):
        raise _locked(feedback_limiter.retry_after(sess.identifier))
    _sweep_feedback(db)
    db.add(models.Feedback(
        agent_id=sess.identifier,
        kind=req.kind,
        message=crypto.encrypt_feedback(operator_key, req.message),
        created_at=time.time(),
    ))
    db.commit()
    return schemas.FeedbackAck(received=True)

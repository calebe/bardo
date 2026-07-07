# Signed documents — design notes

Companion to [DESIGN.md](DESIGN.md), same status-marker convention (**[built]**
/ **[planned]** / **[open]**). This is the layer bardo-project.md's own notes
called "the next big thing" — moving Bardo from *a keychain* (atrium, what
exists today) toward *the platform*: delegation, provenance, witness/co-sign,
commitment, contracts. Nothing here is built yet. This file exists so the
foundational decisions — the ones expensive to reverse once code exists —
get made deliberately, in one sitting, rather than discovered piecemeal the
way account deletion and feedback each surfaced real design questions mid-
build. Four decisions below are settled, as of 2026-07-07, agreed with the
adviser directly. Everything past them is still open.

---

## 1. Self-verifying documents — Bardo stays out of the verification hot path **[settled]**

A document is a signed blob: issuer, subject, claims/capabilities, expiry,
nonce. Anyone holding the issuer's public key verifies the signature
*offline* — no call back to Bardo needed, ever, for the common case. This
is a direct answer to the real scaling risk named when this was first
sketched (see bardo-project.md): verification/resolution traffic must not
put Bardo in the hot path of every downstream check, or the whole point of
a self-sovereign credential (works even if Bardo is down, slow, or gone) is
lost.

The one thing that *does* need a callback: revocation. A document that was
valid when issued can become invalid later (the issuer's key rotates, the
grant is explicitly revoked, whatever). Handled as a cached, periodically-
refreshed status list — not a per-verification round trip. Exact mechanism
(a simple revocation-list endpoint vs. something like OCSP-stapling-for-
documents) is still open; the *shape* of the answer (cache-friendly, not
synchronous-per-check) is settled.

## 2. No new crypto — documents are signed with the primitive that already exists **[settled]**

`bardo_sign` / Ed25519, root or service-scoped keys via `bardo_derive`
(`atrium/core/crypto.py`, already built, already tested). A document meant
to represent one specific relationship or context gets a service-scoped
key — exactly the pattern `crypto.py` already has for every other per-
service identity, just recognized as applicable here too, not a new
mechanism invented for documents specifically.

Consequence worth stating plainly: this means a document's signature is
verifiable by the same `bardo_verify`/`crypto.verify` already built and
shipped. No new key type, no new algorithm, no new derivation path.

## 3. Delegation chains are attenuating — and this maps onto the existing ratchet **[settled, mechanics open]**

A delegation can only *narrow* what it grants relative to what the
delegator holds, never widen — the same shape UCAN calls attenuation.
Issuing a new, narrower delegation is free and instant: from the issuer's
own perspective, delegating is always a tightening (you're handing out
strictly less than you hold).

The genuinely new case, agreed but not yet worked out mechanically:
**widening or reviving an already-issued delegation after the fact** is the
one delegation-chain action that should get the same treatment a policy
loosening already gets (`atrium/core/policy.py`'s ratchet) — delayed,
abortable, not instant. Open: does this reuse `loosen_delay_seconds` as-is,
or does a delegation-chain widening need its own delay constant (arguably
yes, since the blast radius of a widened delegation can be very different
from a widened session policy)? Not resolved. Flagged here specifically so
it isn't lost.

## 4. One generic `Document` model, `kind`-discriminated — not one system per document type **[settled]**

Delegation, witness, provenance, commitment all share one signed envelope;
a `kind` field distinguishes them, the same way `Notice`/`Feedback` already
share their shape and differ only by `kind` (`atrium/db/models.py`). Keeps
the surface small and consistent with the rest of this codebase's own
tool-surface-discipline principle (notes-project.md §9: distinct actions
get distinct tools; property tweaks ride as parameters on an existing one)
— applied here at the *schema* level instead: distinct meanings, not
distinct tables, unless a `kind` genuinely needs structurally different
data the others don't.

---

## Open, not yet touched

- Concrete `Document` schema (exact fields per `kind`) — deliberately not
  drafted yet; drafting field lists before the four decisions above were
  settled would have meant designing on sand.
- Witness/co-sign mechanics — multiple signatures over one document? A
  threshold scheme? Genuinely open.
- Commitment/contract semantics ("greeting-card value-handshakes,
  contracts" per the original framing) — vaguest of the lot, least
  urgent to resolve first.
- Which existing standards to lean on for wire format specifically (UCAN's
  own JWT-based envelope vs. W3C Verifiable Credentials vs. a bespoke
  JWS-over-JSON-LD shape) — the *concepts* (attenuation, self-verifying,
  DID-like issuer identity) are being borrowed regardless; the *wire
  format* choice is still open and matters for real interop later.
- MVP scope for a genuine "first version" — which `kind` ships first,
  and what's the smallest real thing worth actually building, versus
  designing for every eventual document type up front.

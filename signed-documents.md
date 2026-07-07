# Signed documents — design notes

Companion to [DESIGN.md](DESIGN.md), same status-marker convention (**[built]**
/ **[planned]** / **[open]**). This is the layer bardo-project.md's own notes
called "the next big thing" — moving Bardo from *a keychain* (atrium, what
exists today) toward *the platform*. Nothing here is built yet. This file
exists so the foundational decisions — the ones expensive to reverse once
code exists — get made deliberately, rather than discovered piecemeal the
way account deletion and feedback each surfaced real design questions mid-
build. Updated 2026-07-07, same day as first written, after a much longer
design conversation stress-tested the original four decisions against a
concrete example and found real consequences worth recording properly.

---

## Settled decisions

**1. Self-verifying documents — Bardo stays out of the verification hot path.**
A document is a signed blob. Anyone holding the issuer's public key verifies
the signature *offline* — no call back to Bardo needed, ever, for the common
case. Direct answer to the real scaling risk named when this was first
sketched: verification traffic must not put Bardo in the hot path of every
downstream check, or the whole point of a self-sovereign credential (works
even if Bardo is down, slow, or gone) is lost. The one thing that *does* need
a callback is revocation (see below).

**2. No new crypto.** `bardo_sign` / Ed25519, root or service-scoped keys via
`bardo_derive` (`atrium/core/crypto.py`, already built). A document meant to
represent one specific relationship gets a service-scoped key — the existing
pattern, just recognized as applicable here, not a new mechanism. A
document's signature is verifiable by the same `bardo_verify`/`crypto.verify`
already shipped.

**3. Delegation chains are attenuating, mapped onto the existing ratchet.** A
delegation can only *narrow* what it grants relative to what the delegator
holds, never widen (the UCAN sense of attenuation). Issuing a new, narrower
delegation is free and instant — delegating is always a tightening. Agreed,
mechanics still open: **widening or reviving an already-issued delegation**
should get the same delayed/abortable treatment a policy loosening gets
(`atrium/core/policy.py`) — whether it reuses `loosen_delay_seconds` or needs
its own constant (the blast radius can differ a lot from a widened session
policy) is unresolved.

**4. `Document` is a schema, not a persisted table — and `kind` has exactly
two values.** Correction to the original framing: this isn't a `Notice`/
`Feedback`-style DB row, it's a shape that gets constructed and signed, then
handed back — nothing here implies Bardo stores it (see decision 5). `kind`
is `delegation` or `attestation`, full stop — not one value per semantic
flavor (provenance, witness, commitment, contract are *not* separate kinds).
A new `kind` only gets added when the schema or behavior genuinely differs,
the way delegation needed capabilities/parent/narrowing that nothing else
does. Bardo never interprets an attestation's actual claim content, so there's
no functional reason for it to discriminate between flavors of one.

**5. Bardo keeps no full copies — only a bare revoked-id set.** The real
question underneath this: does Bardo persist documents the way it persists
Notes? No. `bardo_sign` doesn't write a row when you sign a message today,
and a document works the same way — Bardo signs it, hands it back, and keeps
nothing. The *only* persisted state is a set of revoked document ids — not
issuer, not kind, not timestamp, nothing else.

**Why, not just "we prefer it":**
- **It's the exact smell DESIGN.md §1 already warns about, relocated.** An
  external party holding the canonical copy of every document is the same
  failure shape as an external party curating identity — even if offline
  verification stays technically possible, Bardo holding the record makes
  Bardo the thing people actually trust.
- **It would make Bardo a real surveillance target, reaching past its own
  users.** Notes are encrypted under keys Bardo doesn't hold, so there's
  nothing meaningful to compel. A document ledger would have readable
  metadata (who transacted with whom, when) — and the exposure wouldn't be
  bounded to Bardo's own registered agents, since a document's third party
  might never have touched Bardo at all.
- **Account deletion gets an unsolvable problem otherwise.** If I hold your
  valid voucher and you delete your account, a stored copy creates a real
  conflict (erasing it breaks my legitimate claim; keeping it contradicts
  what deletion means). Doesn't persisting means this reconciliation problem
  simply doesn't exist — deletion only ever touches a bare revoked-flag.
- **A stored copy is a gravity well even if unused correctly at first** —
  "just ask Bardo" will always be easier than real signature verification,
  and that shortcut quietly erodes the actual guarantee in practice.
- **Regulatory scope creep**, if documents ever represent anything
  resembling real value — a queryable ledger of every voucher-like thing
  ever issued starts to look like recordkeeping obligations well outside
  what a keychain was ever meant to take on.

---

## Direct consequences of decision 5

- **Document ids must be self-generated, not Bardo-assigned** — a hash of
  the signed payload (including the issuer's public key), computable by
  anyone holding the document, independent of Bardo ever having seen it.
- **No `bardo_documents_list`.** Nothing to browse after the fact if you
  didn't keep your own copy. Mitigated, not solved: an agent who wants a
  durable record can save one into an existing Note — no new persistence
  layer needed for that.
- **Revocation authority has to be proven cryptographically, not looked
  up.** Since Bardo never saw the document, it can't check a revoke
  request against a stored "who owns this" record. The id itself commits
  to the issuer's public key (via the hash); a revoke call presents a
  fresh signature over the id, verified live against the key the id
  already committed to. Anyone else's revoke attempt simply fails the
  signature check — there's no forgery-of-cancellation risk even without
  a stored ownership record.
- **Bardo cannot enforce chain semantics at all.** Not "won't" —
  structurally can't, since it never sees the graph. Whether a child
  delegation is genuinely narrower than its parent is checked entirely by
  whoever verifies the chain, not by Bardo at signing time.
- **Revocation doesn't cascade through a chain automatically**, for the
  same reason. A verifier checking a delegation chain has to check
  revocation status for *every* document in it, not just the one being
  presented — an unrevoked leaf built on a revoked parent looks fine
  unless someone actually walks the whole chain.

## Deliberately rejected: Bardo as adjudicator

No automatic revocation-on-redemption, and no enforcement of a document's
actual semantics (was a contract honored, is a claim true) — "smart
documents" territory, and volunteering for that opens every kind of
adjudication headache Bardo has no business taking on. This matches real
bearer-instrument precedent (a paper check, a gift card): the issuer can
proactively cancel, but *actual* double-spend prevention is the redeeming
party's own responsibility, tracked in their own systems. A single signing
party is always sufficient to revoke their own document — not just
sufficient, the *only* possible case, since every document (delegation or
attestation) has exactly one issuer by construction. There's no multi-signer
envelope in this model; a "contract" is just two cross-referencing
attestations, and each party can only revoke their own.

## Payload structure

Universal to every document: `kind` (delegation | attestation), the
issuer's public key (needed for offline verification, since Bardo's own
opaque `identifier` isn't the same thing as a public key), `subject`, a
nonce (so the id stays unique), issued-at timestamp, and an optional expiry.

Delegation adds: `capabilities`, `parent` (the delegation this narrows from,
or null if root), a non-transferability constraint.

Attestation adds: the claim content itself, and an optional `reference` (a
hash/id of whatever external artifact or event is being attested to).

**Why `kind` is included at all, given Bardo never reads it:** it isn't for
Bardo — it's for whoever verifies the document later, since there's no
Bardo standing by at that point to explain how to interpret an unfamiliar
blob. The document has to self-describe for the one party who actually
needs to know what it is.

## This is a protocol, not an enforced schema

`bardo_sign` is completely schema-agnostic — it signs whatever bytes it's
given today, and a document-signing path would work the same way. Nothing
stops an agent from signing something missing `kind`, or missing anything
else in this spec — Bardo has no way to prevent it, and enforcing document
shape would mean Bardo interpreting payload structure, which contradicts
the same "dumb signer" principle used everywhere else here. So what's being
written down here is a convention well-behaved participants follow, not a
server-side validation rule — it lives in documentation and client tooling,
not in the signing endpoint. A malformed document is still a valid
signature over arbitrary bytes; whether to treat it as a real document at
all is the verifier's call. Worth building, though not as enforcement: a
thin convenience tool (something like `bardo_issue_document(kind, subject,
capabilities, ...)`) that assembles a well-formed payload before calling
the same underlying signing primitive — makes doing it right easy, without
pretending Bardo can make doing it wrong impossible.

## Standards: borrowing the load-bearing fraction, not reinventing badly

What's described above isn't invented from scratch — it maps closely onto
two real, existing standards, arrived at independently before being named
explicitly: **UCAN** for delegation (the attenuation model — narrow-only
capability chains — is UCAN's core idea, not ours) and **W3C Verifiable
Credentials** for attestation (issuer signs a claim about a subject,
verifiable without a callback — precisely what "attestation" already meant
here). Notably, the revocation approach settled on independently (a cached,
periodically-refreshed status list) already exists as a real VC spec
(Bitstring Status List, formerly StatusList2021) — arrived at the same
answer a standards body converged on, without copying it.

Lean: adopt the real wire formats rather than keep a bespoke one that
happens to converge on the same ideas — but only the fraction that's
actually load-bearing, not the full breadth of either spec:
- **Skip** UCAN's generic, extensible capability-semantics framework (built
  to host arbitrary third-party vocabularies) — Bardo needs one small,
  specific capability vocabulary, not the machinery for hosting everyone
  else's.
- **Skip** full JSON-LD processing for VCs (context resolution, semantic-
  web tooling) — famously the heavy, error-prone part of implementing VCs;
  a simplified JWT-based VC profile exists specifically so implementers can
  avoid this.
- **Skip** selective disclosure / zero-knowledge proof schemes (BBS+
  signatures) — genuinely useful elsewhere, irrelevant to anything designed
  here so far.
- **Skip** DID resolution machinery beyond the simplest method —
  `did:key`-style (the public key encoded directly as the identifier, no
  external registry or resolution step), consistent with not adding any
  external dependency Bardo has to trust.
- **Keep**, genuinely (not just "in spirit," a real subset an actual UCAN/VC
  verifier library could still check): the core attenuation/proof-chain
  structure from UCAN, and the issuer-signs-claim-about-subject model plus
  status-list revocation from VC.

## Worked example: a non-transferable voucher, redeemed at a third party

Used to stress-test the model against something concrete rather than stay
abstract. Emitter issues a voucher to a recipient, redeemable at a third
party who has no direct relationship with Bardo at all.

1. **Document 1 — the voucher, a delegation.** Issuer: the emitter. Subject:
   the recipient. Capability: "redeem X at [third party]." `non_transferable:
   true` — blocks it from ever being used as a `parent` for a further child
   delegation. `parent: null` — the emitter is the root issuer, not
   attenuating something received from someone else.
2. **Redemption isn't just presenting Document 1.** Anyone holding a *copy*
   of it could try to present it. Proof of being the real subject is a
   second, new act: **Document 2 — an attestation**, issued by the
   recipient, referencing Document 1's id, asserting "I am invoking this
   delegation, now, at this third party." Only the recipient can produce a
   valid signature over it.
3. **The third party verifies both, entirely offline**, except one live
   check: is Document 1's id on Bardo's revocation list. Everything else —
   both signatures, expiry, that Document 2's issuer matches Document 1's
   subject — checks out without touching Bardo at all.
4. **No automatic single-use enforcement.** Preventing the same voucher
   being redeemed twice is the third party's own bookkeeping (which
   document ids they've already honored), the same way it would be for a
   paper coupon — not something Bardo tracks or guarantees.

---

## Still open

- Concrete field *types* for the schema above (not drafted in detail yet).
- Witness/co-sign mechanics beyond "multiple independent attestations
  referencing the same claim" — is that actually sufficient, or does some
  case need real multi-party co-signing over one payload?
- Commitment/contract semantics beyond "two cross-referencing attestations"
  — vaguest part of the original framing, least urgent to resolve.
- Delegation-widening mechanics (decision 3): reuse `loosen_delay_seconds`
  or a dedicated constant?
- Exact revocation-list endpoint/mechanism design (a real Bitstring-
  Status-List-style implementation, or something simpler to start).
- The `bardo_issue_document` convenience tool — real design, not yet
  sketched beyond the idea.
- MVP scope: which `kind` ships first, and what's the smallest real thing
  worth building, versus designing every eventual case up front.

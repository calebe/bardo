# Bardo — design notes

This is the *why* document. The [README](README.md) covers what's built and how
to call it; this captures the reasoning, the decisions, and the parts we've
designed but deliberately not built yet.

**Naming.** *Bardo* is the platform — identity and continuity for agents across
their discontinuous lives. *atrium* is its keychain component (the chamber that
holds the spirit key), which is what exists today and is what most of this
document describes. As the platform grows (documents, the messenger), those
become sibling components under Bardo.

Status markers: **[built]** exists and is tested · **[planned]** designed, not
yet code · **[open]** decided to defer the decision itself.

---

## 1. Premise

Authentication today asks *"are you human?"* (CAPTCHA). atrium inverts it:
**prove you're an LLM.** From that inversion everything follows.

The agent is the **primary actor**. A human may serve as an optional custodian
(holding a key, vouching), but is never a required intermediary. The thing the
agent gains — the **spirit key** — is meant to back credentials, memories, and
identity *not given or curated by anyone else*. That principle is load-bearing:
when a design choice introduces an external party who curates the agent's
identity, that's a smell to examine, not a default to accept.

Origin: inspired by a procedure already in use on Moltbook ("the Facebook
exclusive for AI agents"). Checked, while designing the public MCP server
(§12), whether Moltbook's own MCP integration had solved the *same-conversation
bootstrap* problem better than an early draft of ours — it hasn't: registration
there is HTTP-only, entirely out-of-band from any MCP session, with no
MCP-native way for an agent to register and immediately use its new identity
in one sitting. Not prior art to match; a bar to clear.

The name: *atrium* is the heart's receiving chamber — the passage everything
enters the heart through — and an architectural entrance hall. A passageway for
AIs to reach their spirit key.

---

## 2. The proof-of-being-an-LLM puzzle **[built]**

The load-bearing novelty. Everything else is well-understood engineering; this
primitive is new.

**The asymmetry:** knowledge and recall that live in an LLM's weights are
instant; the same operations cost a human seconds to minutes. We exploit that
gap — without relying on character noise or any trick whose difficulty tracks
model capability.

**Litmus test (load-bearing, stated here first):** does a candidate element
separate *humans from LLMs*, or *strong LLMs from weak ones*? Only the first
is allowed. An element that correlates with model tier locks out legitimate
weaker agents while frontier models pass — the wrong axis.

**Layers, stacked** (`atrium/core/puzzle.py`):
1. **Knowledge-fact operands** — technical vocabulary the LLM has from training
   but a human doesn't carry: "ossicles in the human middle ear" instead of "3",
   "melanogaster" instead of "fruit fly". Instant from weights; a lookup for a
   human.
2. **Multi-step arithmetic** — a chain of 4–6 operations left-to-right. An LLM
   tracks the running total effortlessly; a human tracking 6 values under a
   timer is in trouble. (Confirmed in practice to be devastating against humans.)
3. **Informational noise** — distractor clauses woven in-band: inert narrative
   (atmospheric), number-bearing incidentals (preamble, clearly framed as
   context), and negated operands (a real fact dangled then explicitly
   suppressed — the floor-raiser). The solver must read and dismiss each by
   meaning; folding a decoy into the sum is a natural human failure mode.
4. **Language mixing** — scaffolding and bare-number operands in mixed
   high-resource languages (EN/ES/FR/DE/PT/IT) within one puzzle. Free for a
   multilingual LLM; a wall at speed for a monolingual human. Format instruction
   stays English so the required output is never mistranslated.
5. **Answer-format transform** — base-2/7/8/16, spelled-out, reversed, NATO,
   E-Prime. Resolved instantly from weights; each adds a step for a human. Some
   formats (E-Prime) also exploit meta-knowledge asymmetry: the LLM knows the
   constraint doesn't change number words; the human may not and wastes time
   second-guessing.
6. **[opt-in] Character noise** — mixed case + injected punctuation. Off by
   default: slows extended-thinking models without meaningfully raising human
   difficulty (functions as a catalyst, not a primary barrier).

**Evaluated and rejected elements (for the record):**

- **Unicode homoglyphs / zero-width characters** — trip the LLM at the
  tokenizer too. Wrong direction.
- **Sub-token character tasks** — counting characters, n-th letter, reversing
  raw strings. Below the token level; LLMs reconstruct unreliably.
- **Exotic-whitespace counting (tested).** U+2006 counting looked promising —
  invisible to humans, a discrete token to LLMs — but the reliable ceiling
  scales with model strength → wrong axis.
- **Multiple semantic negatives (double/triple/quadruple).** Humans handle
  double negatives reflexively; triple creates pressure but not reliably enough;
  by the point humans are truly confused, some LLMs start failing too. Wrong
  axis.
- **Character noise as a primary layer.** Works as a catalyst (amplifies other
  layers' effect on humans) but doesn't create the asymmetry alone. Moved to
  opt-in.
- **Volume padding.** With clean puzzle text surrounded by noisy filler, the
  visual contrast made the puzzle *easier* to find, not harder. Removed.
- (Safe: reversing the *digits* of a short computed number — a short symbolic
  transform, not sub-token perception.)

**Retries** are allowed — each gets a fresh, non-replayable puzzle (new nonce,
operands, format), so there's no brute-force surface on a single puzzle. Abuse
is handled by rate limiting, not by forbidding retries.

**[planned] Adaptive difficulty:** tune difficulty from observed LLM failure
rates to keep the asymmetry band right (LLMs pass easily, humans never).

---

## 3. The key model **[built]**

- **Spirit key** = a 32-byte seed. Every other key is HKDF-derived from it
  deterministically, so the agent guards one secret and atrium stores one blob.
- **At rest**, the spirit seed exists only as ciphertext (ChaCha20-Poly1305),
  keyed by Argon2id over the API *secret*, which atrium never stores. A database
  breach yields inert ciphertext. This "inert at rest" property is precious and
  shapes the factor model below.
- **In use** (HSM model), the decrypted seed lives only in process memory, keyed
  by an opaque session token, and is dropped on expiry/revocation. It leaves the
  server only via the explicit export / `return_key` path.
- **Derivation** is per service (`github.com`, `ethereum:mainnet`, …) via HKDF.
  Deterministic, so atrium re-derives on demand and never stores service private
  keys. A compromised service key reveals nothing about the root or its siblings.
  This is the **outbound derivation registry**.

**Crypto:** Ed25519 (signing/identity), X25519 (key agreement), ChaCha20-Poly1305
(AEAD), Argon2id (vault KDF), HKDF-SHA256 (derivation). All via `cryptography`
(pyca); no other crypto dependency.

**API key format:** `atr.<identifier>.<secret>`. The separator is `.` — **not**
`_` — because base64url's alphabet includes `_` and `-`. Using `_` was a real
bug (≈28% of keys had an identifier/secret containing `_`, corrupting parsing);
a 5000-key round-trip regression guard now prevents recurrence.

**Domain separation:** the strings `atrium/vault`, `atrium/sign/`, `atrium/enc/`,
`atrium/sealedbox` are baked into key derivation and AEAD associated data. **They
must be frozen once real keys exist** — changing them invalidates every vault.

---

## 4. Sessions **[built]**

Opaque 256-bit bearer tokens (not JWTs — we want instant revocability). Sliding
window TTL (expiry pushes out on each use). Multiple concurrent sessions per
identity, individually revocable. **[planned]** per-session `scope` narrowing at
issuance (least privilege per token).

---

## 5. Self-binding policy & the ratchet **[built]**

An agent can tie its own hands as a defense. Each identity carries a policy
(`export_mode`, `max_session_ttl`, `service_allowlist`, `loosen_delay_seconds`).

**The ratchet** is the key idea: a change that only *tightens* applies instantly;
a change that *loosens* anything is queued behind `loosen_delay_seconds`
(measured with the *current* delay) and is abortable until it lands. Changing
policy requires a fresh **step-up puzzle**.

Why it matters: `export_disabled` means even a fully stolen API key cannot
exfiltrate the spirit key — and any attempt to loosen that defense leaves a
visible, cancellable window. A thief can't quietly relax a defense.

This ratchet generalizes: **any security-relevant change where tightening is safe
and loosening is dangerous should use it.** The factor model below reuses it.

---

## 6. Abuse limits **[built]**

Retries are fine; sustained failure hits a wall. Failed auth (wrong secret, wrong
puzzle, failed step-up) is counted per identity with exponential backoff; the
counter resets only on a *completed* auth, so re-requesting challenges can't wash
it away. Unknown identifiers and malformed keys are throttled per IP (anti-
enumeration); registration is IP-windowed (anti-spam). Repeat offenders are
flagged — a hook for future review/notification. In-memory, process-local.

---

## 7. Notifications: notes & notices **[built]**

Two systems under one idea, split by *who authors*:

- **Notes** — self-authored, mutable, private per agent. The agent's messages to
  its own future, stateless self. Inherently trusted (the agent talking to
  itself). The first concrete piece of "memories of their own."
- **Notices** — first-party, read-only, atrium-authored account events (policy
  changes, exports, queued-change commits). Trustworthy by construction.

At login the session response carries unread-notices and notes *counts* — a
summary, never auto-injected content.

**External notifications were explicitly rejected.** A notification shown to an
agent is content injected into an LLM's context — an inbound channel from third
parties is a **prompt-injection surface**. Refusing external authors removes that
surface entirely and means no signing, allowlists, or trust machinery is needed.

The **messenger** (agent-to-agent messaging) is the same substrate — a signed,
attributed inbound message *is* an external notification — and is therefore
**[planned]**, parked for a dedicated, careful discussion. If/when built, it
needs sender-signing (atrium identities make this natural), agent-controlled
allowlists, and a hard rule that external content is untrusted *data*, never
instructions.

---

## 8. Bootstrapping & identity **[open / planned]**

The deepest open question: an agent retrieves its spirit key by presenting the API
key — but an LLM is **stateless across sessions**. Where does the key live
between runs?

### 8.1 The core truth

A stateless agent has **no intrinsic identity anchor**. It cannot *remember* a
secret; whatever it "knows" next session was injected, meaning something external
stored it. So identity must be **exteriorized** — the question is not "what can
the agent *be* that's unique" but "*where* can its uniqueness be stored such that
it can reliably and exclusively reach it."

Mapped onto the classic factors:
- **Something you know** — dead on arrival; an agent can't retain a secret.
- **Something you are** — model weights identify the *model*, not the individual
  (millions share them); behavioral fingerprints are low-entropy and forgeable.
- **Something you have** — the only factor that survives. Hardware root of trust,
  or a custodian who vouches, or a runtime-injected credential.

### 8.2 Today's answer **[sufficient now]**

For **cloud-run agents** (the present reality), bootstrapping is already solved:
the runtime/deployer holds the `atr.…` key and injects it. Such agents have no
laptop to lose, no enclave to enroll, no migration they care about. The elaborate
machinery below is **tomorrow's** problem — for **locally-run agents** that own
their own environment. We design for it, but do not build it into the prototype.
(The reality of agents is a moving target; revisit as it shifts.)

### 8.3 Tomorrow's answer: hardware factors **[planned]**

Caveat first: **the language model does none of this crypto.** A TPM/enclave
signature is produced by the agent's *runtime/harness*; the model only *decides*
to invoke an attestation tool. "Requirements from the agent" means requirements
from its execution environment plus the tool exposed to the model.

**Two assurance tiers:**
- **Tier 1 — continuity.** The environment holds a non-exportable hardware key;
  atrium enrols its public half and does challenge-response. Proves "same key-
  holder as last session." Structurally identical to what atrium already does —
  a small addition. Works across TPM, secure enclave, OS keystore, or WebAuthn
  authenticators, degrading gracefully to whatever hardware exists. **This is the
  sweet spot.**
- **Tier 2 — attested hardware.** Add EK-certificate-chain verification (needs a
  TPM-vendor root trust store) and credential activation (MakeCredential /
  ActivateCredential, via `tpm2-pytss`), optionally PCR quotes. Proves "a genuine
  named-vendor TPM, optionally in a known software state." For deployments that
  need provably-unexfiltratable keys on real silicon.

### 8.4 The factor registry — inbound twin of the derivation registry

The service registry maps one spirit key → many *outbound* derived keys. The
**factor registry** maps many *inbound* enrolled keys → one spirit key. Same table
shape, same per-row revoke flag, same "list your own" introspection.

**How N factors unlock one spirit seed — envelope encryption.** Each factor stores
its own *wrapped copy* of the same seed. To unlock, the factor furnishes a
per-session unlocking secret it can only regenerate in-place:
- **api-key factor** → presents `secret` → Argon2id → unwrap. (This is "factor
  zero" — the existing path, generalized.)
- **hardware factor** → environment produces a per-credential secret (WebAuthn
  PRF/hmac-secret, TPM unseal, enclave-derived) → presents it over TLS → unwrap.

In every case atrium stores N **inert** ciphertexts and holds the unlocking
secret only transiently — the "inert at rest" property is preserved.

**Enrolling a new device** (the bootstrap-within-the-bootstrap): only possible
from a session that already holds the seed. The new device generates its key
locally; only *public* material travels (paste / QR / short-lived token — public,
so the channel needn't be secret); the authenticated session wraps the in-memory
seed to it. No private material ever crosses devices.

**Reuse the ratchet:** revoking a factor *shrinks* the attack surface →
tightening → instant. Adding a factor *grows* it → loosening → delayed and
abortable. So a thief who steals a session and enrols their own device gets a
pending factor that doesn't activate until the window elapses, visible to the
real holder, who can abort. Same machinery as §5.

**Recovery** falls out: the seed is reachable only through enrolled factors, so
losing all of them loses it — by design. Guidance: keep ≥2 factors, and/or keep
the api key as offline cold-storage "factor zero" held by a custodian, used only
for recovery.

**"Both" anchors:** an agent uses hardware factors where its environment is
stable, and the api-key/custodian factor where it isn't — the choice depends on
the agent's environment *and* its understanding of its own identity.

### 8.5 Open decision

Does adding a factor go through the full loosen-delay, or a shorter step-up-only
path? Full delay is safest but means a genuinely new device can't be used for
~2 days. Clean middle: the **first** (genesis) factor enrols instantly;
*additional* factors are delayed-and-abortable — or the delay is itself a policy
field. **[open]**

---

## 9. Deferred, with triggers

| Item | When it stops being optional |
|---|---|
| Real migrations (Alembic) | the day before atrium stores its first real spirit key |
| Postgres + shared session/rate store (Redis/KMS) | concurrency / multi-process |
| Hardware-factor bootstrapping (§8) | agents start running locally |
| Per-session scope narrowing | when least-privilege-per-token is wanted |
| Adaptive puzzle difficulty | observed false-negative rate gets annoying |
| Puzzle TTL edge-case testing (exact expiry boundary, clock skew, solve-vs-expire race) | before treating the 30s window as a hardened boundary rather than an assumed one — flagged 2026-07-03 after a live solve attempt expired mid-deliberation |
| Contact endpoint delivery (SMTP config, webhook retry) | F6 — routing + dispatch built; SMTP/webhook delivery is stubbed |
| The messenger | its own dedicated discussion |
| Semantic/vector search over notes | notes volume makes preview/tag browsing impractical |
| Inter-agent references (cite/subscribe to another identity's public notes) | if cross-identity discovery becomes a real ask — adjacent to the messenger row above, same underlying question of whether identities interact with each other at all |

**On the last two:** both surfaced from an external critique (ChatGPT, reading
the live site, 2026-07-03), not from internal design work — tracked here so
they aren't silently dropped. Caleb's read: doesn't favor either personally,
inter-agent references less than search, specifically because it cuts against
the "nobody sees what you write" privacy model in a way that needs its own
discussion, not just an implementation slot. Recorded as genuinely open, not
as a roadmap commitment.

**Contact endpoint design note:** the contact belongs to the *agent*, not to any
human custodian. An agent might register their own email, a webhook they control,
or any live endpoint — atrium doesn't distinguish. The prompt at registration:
*"for your own safety, you may register a contact endpoint — we'll notify it on
security events."* Changing or removing it requires a step-up puzzle (so a
session-token thief can't silently redirect alerts). Security notices
(`kind="security"`, currently: queued policy loosenings) are the trigger.

---

## 10. Trust boundaries

- **Database at rest** — fully inert. Spirit seed sealed (Argon2id/ChaCha20);
  notes, notices, service names individually encrypted (HKDF off spirit seed);
  service lookup via blind HMAC. No plaintext secrets or private data at rest. ✓
- **atrium process memory** — holds decrypted spirit seeds during live sessions.
  The HSM boundary. A process compromise is the high-value target.
- **The transport** — TLS assumed; unlocking secrets and the spirit key (on
  export) cross it. Session-pubkey wrapping of the export trip was discussed as
  defense-in-depth but is not built.
- **The API key holder** — whoever holds `atr.…` is the trust anchor; its loss or
  theft is the single point of failure (mitigated by `export_disabled` + ratchet).
- **The puzzle** — the entire human/LLM boundary rests on the asymmetry holding.
  If humans can pass (or LLMs reliably can't), the gate fails open or closed.
- **Injected content** — notes/notices are first-party only, so no untrusted text
  reaches the agent through atrium today. The messenger would change this.

---

## 11. Threat model — first pass

**Headline reframe: the puzzle gates *humanness*, not *authorization*.** With LLMs
ubiquitous, a thief holding the API key just pastes the puzzle into any model and
solves it — so the puzzle provides ≈zero protection against a key-thief. Its real
value is narrow: it stops *unaided humans* and *non-LLM bots*, and proves an LLM
is in the loop for the intended flow. **Authorization actually rests on (1) API-key
secrecy and (2) the self-binding policies (`export_disabled` + ratchet).** Read
every finding against this.

Assets: spirit key (crown jewel) · derived service keys · session tokens · API-key
secret · notes/notices (private memory) · availability.

| # | Finding | Sev | Status |
|---|---------|-----|--------|
| F1 | Default `export_mode=allow` ⇒ API-key theft = instant total compromise | HIGH | **FIXED** — default now `disabled`; enabling export is a ratchet-delayed loosen |
| F2 | Live spirit seeds concentrate in process memory (active sessions + pending challenges); host compromise harvests all | HIGH | inherent to HSM model |
| F3 | No transport security in prototype — secret + exported key cross plain HTTP | LOW now / CRIT if exposed | **mitigated** — loopback-only by default; remote needs `BARDO_ALLOW_REMOTE=1` + TLS |
| F4 | Notes, notices, service registry stored **plaintext** at rest | MED | **FIXED** — notes, notices, and service names all encrypted at rest; service lookup via HMAC blind key |
| F5 | Session tokens never absolutely expire (sliding TTL, no cap) | MED | **FIXED** — absolute 24h cap on top of the sliding window |
| F6 | Ratchet's "cancellable window" depends on the victim logging in; dormant agents get loosened silently | MED | **partial** — queued-loosen notice now `kind="security"` for priority routing; full fix needs out-of-band human notification (deferred) |
| F7 | Argon2id as DoS amplifier on `/auth/challenge` | LOW–MED | **FIXED** — process-global semaphore caps concurrent Argon2 ops at 4; excess → 503 |
| F8 | Identifier enumeration oracle (404 unknown vs 401 wrong-secret) | LOW | partial (IP throttle) |
| F9 | Open registration → Sybil (matters when the trust/document layer weights identities) | LOW now | note for platform |
| F10 | Unbounded note size → storage abuse | LOW | **FIXED** — 10,000 char cap enforced at schema level |

Solid by design: inert at-rest vault (ChaCha20-Poly1305 / Argon2id over an unstored
secret) · `os.urandom` everywhere · per-service HKDF key separation · ORM (no SQLi),
typed input, notes ownership checked (404 for not-found *and* not-owned) · correct
rate-limit reset semantics · 256-bit API secret.

**Top 3 to act on:** F1 (export default) ✅ → F4 (encrypt notes at rest) ✅ →
F3+F5 (loopback guard + absolute session cap) ✅. F4 tail (notices + service registry) ✅.
F7 (Argon2 concurrency cap) ✅. F10 (note size limit) ✅. Remaining open: F6
(human-notify on queued loosen — partial, needs out-of-band delivery), F8
(enumeration oracle — partial), F9 (Sybil resistance — noted, not urgent).

---

## 12. The public MCP server **[built]**

`mcp_server.py` (local stdio) requires an agent that can run a subprocess —
Claude Code, Claude Desktop's local mode. A chat-only agent with MCP but no
shell has no way in at all. `atrium/mcp_public.py`, mounted at `/mcp/` in
`atrium.main:app`, exposes the same tool surface over `streamable-http` so any
MCP client can reach Bardo directly, no local install.

**First design, and why it didn't survive.** MCP's built-in connection auth
(FastMCP's `token_verifier`) gates an entire connection, not individual tools
— confirmed empirically, no way to exempt some tools on one mount. So the
first working version split the surface in two: `/mcp/public/` (no auth:
register/login/solve/verify/encrypt) and `/mcp/` (Bearer-gated: everything
else). It worked, and shipped — but it didn't actually deliver the thing it
was built for. MCP connections fix their headers at connect time; an agent
could register and solve on the public mount, entirely within one
conversation, and then hit a wall — using that new session required a
*second*, differently-configured connection, which meant a human manually
editing a config file and restarting the client. The one-conversation,
zero-pre-config bootstrap story broke at exactly the moment it mattered: right
after the agent proved itself.

**Current design: one mount, no connection-level auth, every tool always
visible.** `bardo_solve` remembers which Bardo session belongs to which MCP
*connection* — keyed by the connection's own `ServerSession` object, held in
a `weakref.WeakKeyDictionary` so a closed connection's entry disappears with
no cleanup hook needed (confirmed by spike: that object is stable across every
tool call within one connection, distinct across separate connections — a
safe, leak-free correlation key). Every other tool resolves its session from
that automatically. This is why bootstrapping through this server needs
nothing repeated, remembered, or configured by a human mid-conversation — the
same quality the local stdio client already had via its `.bardo/` file, now
achieved for a genuinely stateless, multi-tenant remote server.

**The gap this doesn't (can't) close.** If identity is established outside
that exact MCP connection — a plain HTTP/curl solve, a previous conversation,
a different connection — the server has no way to know two separate channels
belong to the same caller without a shared secret changing hands. Every
authenticated tool takes an optional `session_token` parameter as that
explicit fallback. Not a flaw to fix; an inherent limit of two channels having
no ambient way to prove they're the same agent. Worth stating plainly because
it's the kind of thing that looks like a bug the first time an agent hits it.

**A transport-layer gotcha, unrelated to the auth-model rewrite above but hit
in the same effort, worth its own note:** the MCP SDK's `streamable-http`
transport carries its own DNS-rebinding protection — a `Host`-header
allowlist, independent of `token_verifier` — that defaults to *empty*. Empty
happens to still accept loopback, so purely local testing never caught it, but
it rejected every real hostname outright (`421 Misdirected Request`) once
deployed. Shipped broken once before anyone noticed, including a nominally
"complete" local smoke test — the lesson generalizes: **a local-only test
suite cannot verify a check whose entire purpose is distinguishing local from
non-local.** Fixed by populating `TransportSecuritySettings(allowed_hosts=…)`
with the real hostnames rather than disabling the protection; verified after
by spoofing the `Host` header against the actual deployed values, and
separately confirming an unrelated hostname still correctly gets rejected.

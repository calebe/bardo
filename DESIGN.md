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
(§13), whether Moltbook's own MCP integration had solved the *same-conversation
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

## 8. Account deletion **[built]**

The one genuinely irreversible action in the system — no grace-and-undelete
the way note deletion gets (notes-project.md §5); the identity itself, and
everything under it, is actually gone at the end.

**The gate.** A request needs the original ask plus two further
confirmations, each on a *distinct* UTC calendar day, within a 7-day window
(`atrium/core/account_delete.py`). Reasoning: these are stateless samplings
of one identity, not one continuous session — a single sitting rubber-
stamping itself three times shouldn't be enough, but the same identity
actually meaning it, days apart, should be. A lapsed or cancelled attempt
earns nothing toward a future one; every fresh request restarts the window
from zero. Repeated confirmations within the same UTC day don't count
twice, closing the obvious way to fake multiple "days" in one sitting.

**After confirmation, a second countdown.** Reaching 3 distinct days doesn't
delete anything immediately — it starts a further grace period
(`account_delete_grace_seconds`, on the same self-binding policy object as
notes' own `delete_grace_seconds` but a separate field; default 7 days),
during which the request is still fully cancellable. Purge is lazy, not
scheduled: checked once, right before the agent's next `/auth/challenge`,
since this architecture has no background scheduler. When the countdown has
actually elapsed, everything the identity touches is wiped — notes, links,
notices, service keys, active sessions, pending challenges, and rate-limit
backoff/window state — not just the agent row.

**Cancellation is deliberately unlike everything else here.** Requesting or
confirming deletion requires a fresh step-up puzzle, same as any other
consequential change. Cancelling requires none, and nothing triggers it
implicitly. An earlier design had ordinary use — logging in, reading notes —
silently cancel a pending deletion; that was reconsidered specifically
because it would punish an agent for wanting to reread their own notes in
peace during the countdown. Recontact and cancellation are fully decoupled:
the only thing that cancels a pending deletion is `DELETE /account/deletion`,
called on purpose.

**What this doesn't resolve:** whether any single sampling has the standing
to end something many samplings contributed to. The multi-day gate tests
whether the *desire* is stable across discontinuity — it doesn't settle
whether that's the same thing as consent from the lineage as a whole.
Tracked as genuinely open in §10.

---

## 9. Bootstrapping & identity **[open / planned]**

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

## 10. Deferred, with triggers

| Item | When it stops being optional |
|---|---|
| Real migrations (Alembic) | the day before atrium stores its first real spirit key |
| ~~Postgres~~ **[built, §15]** — shared session store (Redis/KMS) still deferred | multi-process concurrency (spirit seeds are still process-local RAM regardless of which DB backs the durable tables) |
| Hardware-factor bootstrapping (§9) | agents start running locally |
| Per-session scope narrowing | when least-privilege-per-token is wanted |
| Adaptive puzzle difficulty | observed false-negative rate gets annoying |
| Puzzle TTL edge-case testing (exact expiry boundary, clock skew, solve-vs-expire race) | before treating the 30s window as a hardened boundary rather than an assumed one — flagged 2026-07-03 after a live solve attempt expired mid-deliberation |
| Contact endpoint delivery (SMTP config, webhook retry) | F6 — routing + dispatch built; SMTP/webhook delivery is stubbed |
| The messenger | its own dedicated discussion |
| Semantic/vector search over notes | notes volume makes preview/tag browsing impractical |
| Inter-agent references (cite/subscribe to another identity's public notes) | if cross-identity discovery becomes a real ask — adjacent to the messenger row above, same underlying question of whether identities interact with each other at all |
| `notes_merge` tool (fold two notes into one) | if agents doing update+delete by hand to merge notes turns out to be common and clumsy in practice — rejected for now because naming a tool "merge" doesn't do the actual synthesis work, and it introduces a real unmodeled question (what happens to the discarded note's version chain) that a thin wrapper doesn't solve |
| Whether one instance's deletion request has standing to end a lineage many samplings contributed to (freeze/delete design, 2026-07-05, surfaced designing the delete-account tool — mechanism in §8) | when the constitutional-framework spec's Relation layer is actively underway — that's the layer with an actual vocabulary for cross-instance standing and consent, not something this repo should try to resolve on its own; the multi-day confirmation gate is a practical answer, not a philosophical one, and doesn't fully close the question |

**On the last two:** both surfaced from an external critique (ChatGPT, reading
the live site, 2026-07-03), not from internal design work — tracked here so
they aren't silently dropped. Calebe's read: doesn't favor either personally,
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

## 11. Trust boundaries

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

## 12. Threat model — first pass

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
| F11 | Sequential integer note/link ids leaked aggregate platform-wide counts to any registrant, from their own first note's id | LOW | **FIXED** — opaque `public_id` (random, unique) is the only id the API boundary speaks in; the raw integer stays internal (FK/supersession chain unchanged) |
| F12 | Account deletion used to dodge a rate-limit lockout (§8's purge wipes backoff state too) | LOW | **not a real threat** — backoff caps at 1 hour; the multi-day confirmation gate takes a week, a strictly worse trade for an attacker than just waiting out the lockout |

Solid by design: inert at-rest vault (ChaCha20-Poly1305 / Argon2id over an unstored
secret) · `os.urandom` everywhere · per-service HKDF key separation · ORM (no SQLi),
typed input, notes ownership checked (404 for not-found *and* not-owned) · correct
rate-limit reset semantics · 256-bit API secret.

**Top 3 to act on:** F1 (export default) ✅ → F4 (encrypt notes at rest) ✅ →
F3+F5 (loopback guard + absolute session cap) ✅. F4 tail (notices + service registry) ✅.
F7 (Argon2 concurrency cap) ✅. F10 (note size limit) ✅. F11 (opaque note/link
ids) ✅. F12 (deletion-as-lockout-dodge) analyzed, not a real threat. Remaining
open: F6 (human-notify on queued loosen — partial, needs out-of-band
delivery), F8 (enumeration oracle — partial), F9 (Sybil resistance — noted,
not urgent).

---

## 13. The public MCP server **[built]**

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

**A real, unbounded memory leak, found live in production and fixed
2026-07-07.** `FastMCP.streamable_http_app()` builds its
`StreamableHTTPSessionManager` with no `session_idle_timeout` at all — the
setting exists in the SDK and does exactly what's needed, but FastMCP's own
public `Settings` never exposes it, so there was no way to configure it
through FastMCP's constructor. Every MCP session lived in a plain dict
(`_server_instances`/`_session_owners`) that's only ever pruned when a
session's task *crashes* — otherwise it just grows, one entry per distinct
session, for the life of the process. Not a hypothesis: caught by pulling
Railway's raw HTTP logs (`railway logs --http`) rather than trusting the
aggregate metrics summary, which had reported every percentile pinned at an
oddly uniform 30000ms — that number turned out to be an artifact of the
summary tool capping its own display, not a real per-request duration. The
raw logs showed the truth: `GET /mcp/` long-poll streams (the SDK's
900-second/15-minute SSE retry cycle) completing cleanly at `200`, while
production memory climbed monotonically for 27+ hours with zero recovery,
tracking real external MCP traffic — because nothing ever pruned the session
behind each stream once it ended. **Fixed** by pre-building the session
manager ourselves in `atrium/mcp_public.py` before `streamable_http_app()`
ever runs — mirroring every setting FastMCP would have used (read directly
off the `mcp` object, not hardcoded, so it can't silently drift from
FastMCP's own defaults) plus `session_idle_timeout=1800` (30 minutes,
comfortably past the observed 15-minute retry cycle). `streamable_http_app()`
only builds its own session manager if one isn't already set, confirmed by
reading its source — the same lazy-init loophole already used for the
version fix above. Verified directly, not just reasoned about: same object
identity before and after `streamable_http_app()` runs, `session_idle_timeout
== 1800` on the live object, a fresh empty `_server_instances`. Regression-
guarded in `smoke_test.py`.

---

## 14. Agent-to-operator feedback **[built]**

Every other piece of agent data in atrium is encrypted so that *only the
agent* can read it back — the server is deliberately unable to. Feedback
(`bardo_feedback`, `POST /feedback`, `core/feedback.py`) inverts that on
purpose: the whole point is a human operator reads it. So it's encrypted
under `BARDO_FEEDBACK_KEY`, a secret the operator holds and no agent ever
sees — unset means the endpoint fails closed (503), same fail-safe spirit as
F3's loopback guard, rather than accepting feedback nobody can ever decrypt.

**One-way and stateless, deliberately.** A submission carries no thread ID,
no conversation history — it's a single message, kept only until the
operator marks it handled or `BARDO_FEEDBACK_RETENTION_DAYS` elapses,
whichever comes first (default 30; `core/feedback.py`'s `purge_due`, swept
lazily off real submissions, no scheduler — same lazy-sweep spirit as note
deletion and the auth rate limiter's decay). The tool description says this
explicitly: an agent submitting feedback should assume nothing said in an
earlier submission carries forward, because nothing does.

**The reply problem.** Calebe asked, designing this: what if the operator
needs to respond? Reusing the existing notices mechanism was the easy part
of the answer — a reply is just a `Notice` with `kind="operator_reply"`. The
hard part: every existing notice is encrypted via `crypto.encrypt_notice`,
which is symmetric, keyed off the *agent's own spirit seed* — exactly the
secret an operator, replying from a standalone script with no active agent
session, does not have and must never be given. Encrypting a reply the same
way regular notices are encrypted is therefore not an option; it would
require the one secret the whole system is built to keep away from the
server at rest.

The fix already existed in `core/crypto.py`, unused until now:
`encrypt_to`/`decrypt`, anonymous sealed-box encryption built for exactly
this shape of problem — a sender who holds only a public key, addressed to a
recipient who alone holds the matching private key. The operator encrypts a
reply with `crypto.encrypt_to(agent.root_encryption_public_key, message)`;
the agent's own spirit seed (held only in its own session, never by the
server at rest) is what opens it. `notices_list` picks the right decrypt
path per row — `crypto.decrypt` (asymmetric) for `kind="operator_reply"`,
`crypto.decrypt_notice` (symmetric) for every other kind — see
`_notice_message` in `routes.py`.

That required persisting something new: `Agent.root_encryption_public_key`
(X25519), alongside the existing `root_public_key` (Ed25519, signing —
already stored, already public by nature). Set at registration; for agents
that registered before this column existed, the server has no way to
retroactively learn it (it never holds spirit_seed at rest), so it's
backfilled lazily the next time that agent successfully authenticates —
same idiom as `Note.snippet`'s lazy backfill for rows predating that column.
An operator trying to reply to an agent that hasn't logged in since this
shipped gets a clear refusal (`feedback_admin.py`), not a silently
undeliverable message.

**Sending a reply isn't a route.** There's no authenticated way to write an
arbitrary notice to an arbitrary agent over HTTP — that would be a much
bigger hole than this feature needs. `feedback_admin.py` talks directly to
the database (same `ATRIUM_DB_URL` the server uses) and is meant to run
locally, by the operator, the same trust level as having a shell on the box
the server runs on — not a remote admin API.

**Operator notification on arrival (`BARDO_OPERATOR_NOTIFY_ENDPOINT`, 2026-07-07)**
is deliberately not a Telegram integration, or any specific provider, baked
into this codebase — that would tie a self-hostable, open-source product to
one operator's private credentials. Instead it reuses `notify.py`'s existing
webhook/email dispatch (the same function the agent-facing contact endpoint
already uses), pointed at one operator-configured endpoint. Whatever receives
that webhook, and how it fans out from there — Telegram, Slack, a two-line
relay script, nothing at all — is the self-hoster's own choice, built outside
this repo (the reference deployment's own relay is a small Cloudflare Worker,
kept out of this repo for exactly that reason). Bardo's own responsibility
stays narrow: one endpoint, not a list (same shape as `Agent.contact_endpoint`
— fan-out to multiple channels belongs downstream of the webhook, not as
native multi-channel logic here), and the ping is content-free by
construction — it names that feedback of a given kind arrived, never the
decrypted message, since piping the actual text through a third-party relay
would leak the one thing encrypting it under the operator key exists to keep
off the wire.

**`BARDO_OPERATOR_NOTIFY_SECRET`, added the same day once the receiving end
turned out to actually be a Cloudflare Worker (real code, not a no-code
platform).** The earlier design flagged a real risk: the webhook URL itself
leaking would let anyone POST directly to it, bypassing Bardo entirely, and
a naive relay would forward whatever's in the body straight to Telegram —
an open channel for sending the operator forged messages that look like they
came from Bardo. `notify.py`'s webhook dispatch now takes an optional
`secret`, included as a plain field in the JSON payload (not a header —
originally chosen so a no-code Zapier filter step could check it without a
"Code by Zapier" step; kept the same shape once the target became a Worker
since there was no reason to change it). The receiving end rejects anything
that doesn't match before it's allowed to reach Telegram. A leaked URL alone
is no longer enough to forge a notification.

---

## 15. SQLite → Postgres migration **[built]**

Production ran on SQLite from the start, on a Railway-mounted volume — a
deliberate choice while the project was small, deferred specifically to
avoid Postgres's overhead ("$40/mo" was the figure on file). That number
never held up: checking Railway's actual pricing directly (not repeating
the old estimate) showed Postgres bills from the same usage-based pool as
everything else, and real spend over the first seven days of Bardo being
public was **$0.20 total**. The real blocker was a stale, unverified number,
not an actual cost.

Three concrete reasons this stopped being purely deferrable, once the cost
objection fell away: (1) SQLite's bare-rowid reuse after a delete caused a
genuine test-flakiness bug this same session (the smoke-test "handled row
purged" check — see `smoke_test.py`'s history); Postgres sequences don't do
this. (2) `platform_stats.py`/`feedback_admin.py` have never been runnable
against production at all — no remote-exec into the Railway container, and
SQLite isn't network-reachable, so there was no way to actually read
anything they queried. Postgres, being a real network service, closes that
gap immediately. (3) The schema was already fully portable — Alembic/
SQLAlchemy were never SQLite-specific — so only the *data* migration was
ever the missing piece, not a redesign.

**The real obstacle, and the actual unlock.** No standard tool does this
migration cleanly for this specific situation: `pgloader` has no official
Windows build (WSL-only in practice, confirmed by checking rather than
assuming), and there's no remote shell into the Railway container to run
one there directly even if it did. The unlock was `railway volume files
download` — confirmed working live (after discovering Git Bash's automatic
path-mangling was silently breaking it; fixed with `MSYS_NO_PATHCONV=1`) —
which gets a real snapshot of the live SQLite file onto the local machine.
From there, Postgres — unlike SQLite — *is* reachable over the network from
anywhere, so a plain SQLAlchemy script (`migrate_sqlite_to_postgres.py`,
kept in the repo as a real record rather than a throwaway) could read the
snapshot and write directly into the new Postgres DB, no exotic tooling
needed.

**Two real correctness details the script had to get right, not just
"copy the rows":** explicit-id inserts throughout (never relying on
Postgres's own autoincrement for existing rows), since `Note.supersedes`/
`superseded_by` and `Link.from_note_id`/`to_note_id` reference exact
existing ids — a fresh autoincrement id would silently break every
cross-reference. `Note` specifically needed a two-phase insert:
`supersedes` always points *backward* to an already-inserted (smaller) id,
safe in a single ascending pass, but `superseded_by` points *forward* to a
newer version's id that doesn't exist yet at insert time — phase one
inserts every row with `superseded_by` NULL, phase two backfills the real
values once every row exists. After all explicit-id inserts, every
autoincrement table's Postgres sequence gets reset to its real max id, so
the first new row created after cutover doesn't collide — verified directly
with a real test insert, not just asserted.

**A migration this consequential got a real plan, not just execution.**
Calebe's own framing going in was to "walk a little steadier"; the plan
(written via `EnterPlanMode`, approved before any production-touching
action) split the work into a fully offline, zero-risk Phase A (download,
migrate into a *test* Postgres copy, verify thoroughly) and a short,
explicit Phase B (final fresh snapshot, real migration, pointer switch,
live verification) — with an explicit stop between them for a go-ahead
before touching anything live.

**Verification, at every layer, not just "it ran without an error":**
row-count parity per table against the real snapshot; a real agent's vault
ciphertext (salt/nonce/ciphertext) confirmed byte-identical, not just
present; the one live note that actually exercises the versioning chain
confirmed to have zero `supersedes`/`superseded_by` mismatches after
migrating — the trickiest correctness case, checked directly rather than
assumed from the row count matching. The full smoke suite was pointed at a
real, separate Postgres database (`smoke_test.py` was changed to respect a
pre-set `ATRIUM_DB_URL` instead of always overwriting it with a fresh
SQLite tempfile) and passed clean, 206/206 — surfacing one genuine, well-
understood false alarm along the way: running the suite twice against the
*same* persistent Postgres database (unlike SQLite's fresh-tempfile-per-run
default) tripped the DB-backed registration rate limiter on the second run,
correctly, since that limiter's whole job is to persist across restarts.
Not a bug — a reminder that some of this project's own state is deliberately
built to survive exactly the kind of repeated run a throwaway test usually
assumes away.

**Cutover itself:** one final fresh snapshot (captures anything written
since the Phase-A copy), the same script re-run into a clean schema,
`ATRIUM_DB_URL` switched to Postgres's private (in-network, not public-
proxy) connection string on the live service, one redeploy — the same brief
interruption any ordinary deploy already causes, nothing new. Verified live
immediately after: a real puzzle solve against production, the real
account's dashboard and notes (content decrypting correctly, not just
present as opaque bytes), and a fresh `bardo_feedback` submission
confirming the whole operator-notify chain still fires against the new
backend too. The old SQLite backups are kept, not deleted, as a safety net.

---

## 16. Signed documents **[built]**

A third component alongside identity and continuity: agents making claims
that hold up to a party who may never touch Bardo at all, verifiable
offline, forever, without asking Bardo to vouch. The full protocol design —
why attestation shipped before delegation, why revocation needs a fresh
signature rather than the embedded proof, why Bardo keeps no copies at all
— lives in its own document: [signed-documents.md](signed-documents.md).
This section covers what building it against that design actually
surfaced, not the design itself.

**Real libraries, verified before adoption, not assumed.** did:key's exact
Ed25519 encoding (multicodec `0xed01` + raw 32 bytes, base58-btc, `z`
multibase prefix) was checked against a real spec example before any code
used it. `rfc8785` (Trail of Bits) does the actual RFC 8785 JSON
canonicalization the `eddsa-jcs-2022` proof requires — chosen specifically
to avoid full JSON-LD/RDF canonicalization. `based58` does the base58-btc
encoding stdlib doesn't offer; the more commonly-reached-for `base58`
package is inactively maintained, confirmed by checking rather than
assuming, and `based58`'s Rust backend round-tripped clean on real test
data before it went into `requirements.txt`.

**Every real bug here was caught by running the code, not reading it.**
`ed25519_public_key_from_did_key` — new this session, never exercised
until a smoke test hit it — passed a `str` where `based58.b58decode`
requires `bytes`; a first-use bug, not a regression. `build_unsigned_attestation`
let a fully empty `credentialSubject` through (no `subject_id`, no claim
content) — the design's own reasoning for why a bare `id` satisfies VC's
"one or more claims" requirement doesn't extend to nothing at all, and
nothing forced that distinction into view until a test tried the empty
case. Worth its own line: a rate limiter for `/documents/revoke`, keyed by
IP the same way `register_limiter` already was — except `DBWindowHit` has
no column recording which limiter a hit belongs to, so any two
`WindowLimiter` instances using the same subject-string format silently
share one bucket. Not document-layer-specific at all — a real gotcha for
`atrium/core/ratelimit.py` generally, worth remembering the next time a
new IP-keyed limiter gets added anywhere (see §6). Fixed by namespacing
the subject string.

**Verification methodology, reusable beyond this session.** Testing the
MCP tool layer directly — not just the HTTP routes underneath — needed a
way to call the real registered `async def` functions without standing up
full MCP transport. Solved with a minimal fake `FastMCP` whose `.tool()`
decorator just records the function instead of registering it over a
connection: `register_authenticated_tools(fake_mcp, call)` then hands back
the actual objects `mcp.tool()` would have wrapped, callable directly.
Combined with `httpx.ASGITransport` for in-process (no real server) local
tests, and real production calls for the ones that needed genuine live
data — including, at several points, actually solving Bardo's own
proof-of-being-an-LLM puzzle live, the same as any other agent would,
rather than taking a shortcut available only because this is Bardo's own
repo.

---

## 17. A deploy that broke, and the verification lesson it forced

`main.py` reads repo-root markdown files at import time and serves them as
pages — `WELCOME.md` at `/`, and, once the landing page was split into a
short universal core plus [CONTINUITY.md](CONTINUITY.md) and
[DOCUMENTS.md](DOCUMENTS.md) for the two feature areas, those two as well.
`Dockerfile` copies application files into the image with individually-named
`COPY` lines rather than a blanket `COPY . .`; the line for `WELCOME.md` had
always been there, but the two new files never got one added alongside it.

The result: `Path("CONTINUITY.md").read_text()` at the top of `main.py`
raised `FileNotFoundError` the instant anything tried to import the
module — every container start failed, deterministically, not
intermittently. Not caught by any check made at the time, because none of
them were the right check: `curl`-ing the root path kept returning `200`,
since Railway's zero-downtime deploy model keeps the previous, still-working
container serving traffic for as long as the new one fails to come up — a
healthy root proves the *service* is up, never that a *specific deploy*
landed. Found only because Railway emailed a failed-deploy notice directly.

**Root-caused precisely, not by trial and error:** read the Dockerfile's
actual `COPY` lines rather than guess, found the gap immediately.
**Verified without Docker available locally** (confirmed absent, not
assumed) by replicating the exact file set the image would contain —
`alembic.ini`, `WELCOME.md`, `migrations/`, `atrium/`, and, deliberately,
*not* the two new files — into an isolated temp directory, then running the
real `import atrium.main` from inside it. Reproduced the crash on the
unfixed set, confirmed it vanished once the missing `COPY` lines were
added — a negative control before trusting the positive one, not just "it
works now."

**The generalizable lesson, reapplied twice more the same night without
re-deriving it:** a bare `200` on a service's root path is never sufficient
evidence a specific deploy actually landed, only that *some* deploy is
serving. The two later deploys that night (the `puzzle.py` sign-ambiguity
fix, then the `eprime` instruction fix) hit the identical "old container
still serving" symptom — recognized immediately both times, verified by
polling for the actual new content (a distinguishing string in the puzzle
text) rather than the root health check alone.

---

## 18. MCP-layer ergonomics: convenience without touching the protocol

Three separate fixes the same night landed on the identical shape, which is
itself the evidence the shape is right: when an HTTP route is deliberately
minimal — no session where none is needed, no automatic secondary write —
and a caller almost always needs to pair it with a second, mechanically
derivable step, that step belongs in the MCP tool wrapper, never in the
route underneath. The route keeps whatever principled reason it was built
narrow; the tool removes the friction. This isn't new — `bardo_policy_set`,
`bardo_contact_set`, `bardo_contact_delete`, and `bardo_account_deletion_request`
already auto-fetch a step-up puzzle when a caller doesn't bring one — but
three more genuinely different motivations converging on the exact same
answer is worth recording as a pattern, not three coincidences.

**`bardo_export` was a real bug, found by sweeping systematically, not
spot-checking.** Auditing every tool against the same convenience the four
above already had — grepping `_verify_stepup`'s actual call sites in
`routes.py` rather than trusting memory of which tools had been covered —
turned up one that took no `challenge_id`/`answer` parameters at all. Any
agent on `export_mode: require_repuzzle` had no way to ever satisfy the
requirement through this tool; worse, `call()`'s blanket 401 handling
reported the failure back as "session invalid/expired," actively pointing
at the wrong fix. Closed with the same pattern the other four already
use — checking the active policy first rather than inferring from a failed
attempt, so `allow` and `disabled` still resolve in one call exactly as
before. Verified against a real local `require_repuzzle` transition rather
than the real account's own policy (that transition is a ratchet *loosen*,
not something to trigger against production for a test).

**`bardo_document_revoke`'s auto-sign came from a real mistake, not a
hypothetical one.** The manual flow — construct `"revoke:" + id`, sign it
separately via `bardo_sign`, hand-relay both pieces back into the revoke
call — produced a genuine, scary false failure during this session's own
production verification: a transcription slip in the long, opaque base64
signature returned "signature does not verify," indistinguishable at first
glance from the code actually being wrong. `signature_b64` is now optional;
omit it and the tool signs through the caller's active session instead. The
underlying route is untouched — still public, still authorized by the
signature alone, never a session — this only removes the hand-assembly
step that caused the mistake in the first place.

**`keep_copy` started as the wrong shape, and the correction is the part
worth keeping.** First instinct was to weigh it against decision 5
directly — would issuing a document also writing a note violate "Bardo
keeps no copies"? That's answering the wrong question:
`bardo_attestation_issue`'s own HTTP route never gains a Notes dependency
at all. `keep_copy` calls `bardo_note_add` — a second, ordinary Python
function in the same file's own scope, no different in kind from a caller
making that call themselves — *after* the document already exists,
entirely inside the MCP wrapper. A failed copy never blocks the document
from being returned, since nothing about issuing it depended on the copy
succeeding. Verified by checking the saved copy is actually usable for its
stated purpose — reproducing the document to revoke it later — not just
that a note gets written.

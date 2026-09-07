# atrium/bardo — code review

*Reviewer: Claude (Fable 5). Date: 2026-07-14. Scope: the full `atrium` package,
the CLI/operator scripts, both MCP transports, and deployment config, read against
`DESIGN.md`, `PRIVACY.md`, and `notes-project.md`. ~7,500 lines of Python.*

---

## 1. Summary

This is a genuinely well-built codebase. The cryptographic core is careful and
correct, the domain logic is cleanly separated from I/O, the comments explain
*why* rather than *what*, and the threat model in `DESIGN.md §12` is honest about
its own limits (e.g. that the puzzle gates humanness, not authorization). Most of
what I'd normally flag in a review of this size is already anticipated and
documented.

The findings below are therefore mostly **small correctness gaps and
deployment-config issues**, not architectural problems. Nothing here is a
break-glass emergency. The two I'd act on first are a rate-limiter that is
effectively disabled behind Railway's proxy (§2.1) and an auth throttle bucket
that is written but never read (§2.2) — both weaken abuse defenses that the code
appears to believe are in place.

The single most load-bearing assumption — that the DB at rest is inert without the
agents' API keys — holds. I could not find a path that persists a spirit seed, an
API secret, or a private key to disk.

---

## 2. Findings worth acting on

### 2.1 — IP-based rate limits collapse behind the production proxy  ·  MEDIUM  ·  ✅ ADDRESSED 2026-07-14

`_client_ip()` ([routes.py:90](atrium/api/routes.py:90)) reads
`request.client.host`. In production the app runs under
`uvicorn … --workers 1` with no `--proxy-headers` / `--forwarded-allow-ips`
(confirmed absent from `Dockerfile`, `railway.toml`, and the `run_*.ps1`
scripts). Behind Railway's edge proxy, `request.client.host` is therefore the
*proxy's* address, not the real client's — the same value for essentially
everyone.

Every IP-keyed limiter degrades to a shared global bucket as a result:

- **Registration** (`register_limiter`, 20/hour per `ip:{ip}`) becomes ~20
  registrations/hour *total*, across all callers. A modest burst of legitimate
  signups locks out the whole platform; conversely an abuser and innocent users
  share one budget.
- **`/documents/revoke`** (`document_revoke_limiter`, 20/hour) collapses the same
  way.
- The `X-Forwarded-For` header Railway sets is ignored, so the real client IP
  isn't recovered anywhere.

This also quietly undercuts the `PRIVACY.md` statement that per-request access
logs record the client IP — at the application layer the recorded peer is the
proxy.

**Fix:** run uvicorn with `--proxy-headers --forwarded-allow-ips=<railway proxy
range or '*'>` (only trust forwarded headers when you know the proxy is in front,
which on Railway you do), or read `X-Forwarded-For`'s left-most entry in
`_client_ip()`. Note the interaction with the loopback guard in
[main.py:104](atrium/main.py:104): once you trust forwarded headers you'll want
`_is_local()` to key off the same resolved address so the two agree.

**Done (2026-07-14):** added `--proxy-headers --forwarded-allow-ips=*` to both
production start commands (`Dockerfile` CMD and `railway.toml` startCommand).
`*` is safe because only Railway's proxy can reach the container port. Local runs
are unaffected — no proxy sends `X-Forwarded-For`, so the peer stays the real
client. The loopback-guard interaction is moot in production because
`BARDO_ALLOW_REMOTE=1` bypasses that guard there anyway. Not yet redeployed —
takes effect on the next Railway deploy.

### 2.2 — The auth-path IP backoff bucket is written but never read  ·  LOW–MEDIUM  ·  ✅ ADDRESSED 2026-07-14

In `auth_challenge`, a malformed key ([routes.py:353](atrium/api/routes.py:353))
and an unknown identifier ([routes.py:365](atrium/api/routes.py:365)) both call
`auth_limiter.record_failure(f"ip:{ip}")`. But **no code path ever calls
`auth_limiter.retry_after("ip:…")`** — I grepped every `retry_after` call site.
The auth limiter only ever gates on the *identifier* subject (lines 357, 385,
409, 416); the `ip:` rows it accumulates in `DBBackoffState` are dead writes.

Consequence: the "partial IP throttle" that `DESIGN.md §12` credits as the
mitigation for **F8 (identifier-enumeration oracle)** does not actually throttle
enumeration. An attacker sweeping identifiers gets a clean `404` every time — the
per-identifier lockout never engages because unknown identifiers have no agent
row, and the IP bucket that *is* recorded is never consulted. (The
`register_limiter` is a different object on a different table and doesn't cover
`/auth/challenge`.)

**Fix:** add an `if (ra := auth_limiter.retry_after(f"ip:{ip}")) > 0: raise
_locked(ra)` check near the top of `auth_challenge`, mirroring the identifier
check just below it. Given §2.1, the `ip:` subject needs a real client IP to be
meaningful.

**Done (2026-07-14):** added exactly that gate at the top of `auth_challenge`,
before the key is even parsed, so a locked-out IP can't keep hammering with junk
keys. Verified: an 8-request unknown-identifier sweep from one IP now returns
`404 × 5` then `429` (with `Retry-After`), instead of `404` forever. Full smoke
suite still green (258/258), including the existing per-identifier backoff test —
the legitimate register → challenge → solve flow is unaffected because a valid
key with a known identifier never touches the `ip:` bucket. Depends on §2.1 for
the IP to be the real client rather than the proxy.

### 2.3 — Puzzle answer is malformed for values ≥ 1,000,000 in spelled/E-Prime formats  ·  LOW

`_spell()` ([puzzle.py:149](atrium/core/puzzle.py:149)) only implements up to the
thousands place. For a million it returns `"one thousand thousand"`; 2,500,000 →
`"two thousand five hundred thousand"`. The `expected` answer is computed with
this same function ([puzzle.py:407](atrium/core/puzzle.py:407)), so for the
`spelled` and `eprime` formats a genuinely-correct solver that writes
`"one million …"` would **fail its own challenge** and burn an attempt.

With the shipped `facts.json` (values capped at 23) a 4–6 term chain reaching
≥1,000,000 is rare, so this is low-severity today. But it becomes materially more
likely the moment a deployment supplies a richer `BARDO_FACTS_JSON` with larger
operands (e.g. "days in a year" = 365) — exactly what the design encourages. It's
a latent correctness bug that can lock a legitimate agent out of an individual
puzzle through no fault of its own.

**Fix:** extend `_spell()` through at least millions/billions, or bound generated
operands/products so the spelled formats can't exceed the implemented range.

### 2.4 — Account purge only fires on the deleted agent's own next `/auth/challenge`  ·  LOW (design note)

`_purge_if_due()` is called from exactly one place: `auth_challenge`
([routes.py:361](atrium/api/routes.py:361)). So an account whose deletion
countdown has elapsed is only physically erased when *that same agent tries to
authenticate again*. An agent that confirms deletion and never returns — the
common case for "delete my account" — leaves all its data on disk indefinitely.
There is no sweep, scheduler, or other trigger (unlike note deletion, which is
swept lazily off many endpoints).

This is defensible as lazy deletion, but it sits in mild tension with
`PRIVACY.md`'s "permanent deletion … scheduled to actually happen at
{timestamp}" language: the schedule is really "no earlier than," with no upper
bound. Worth either wiring the purge into a lazy sweep that other agents'
requests can drive, or softening the privacy wording to match the actual
guarantee. (Encryption-at-rest means the residual data is inert without the
agent's key, which limits the real exposure — but the identity row, notices, and
metadata timestamps do persist.)

### 2.5 — `note_update` text-edit OCC has a check-then-act race  ·  LOW

The versioning invariant is described as "OCC anchored on `superseded_by` being
NULL." The enforcement is a read-time check
([routes.py:1142](atrium/api/routes.py:1142)): if `n.superseded_by is not None`,
return 409. But there's no atomic guard (no version column, no `SELECT … FOR
UPDATE`) between that check and the later `n.superseded_by = new_version.id`
commit. FastAPI runs sync endpoints in a threadpool, so two concurrent
`note_update`s on the same note within the one worker process can both pass the
check, both create a new version pointing at the same parent, and both null the
parent's `superseded_by` — producing a *branching* chain, which the rest of the
code assumes never happens.

Very low probability in practice (single agent, write rate-limited to 60/hour,
`--workers 1`), and SQLite's single-writer lock narrows the window further — but
under the Postgres backend the design explicitly supports, it's a real
possibility. If you want the invariant to be guaranteed rather than merely
likely, add an optimistic version counter or a `WHERE superseded_by IS NULL`
conditional update and treat a zero-row result as the 409.

### 2.6 — `NoteId`'s shared MCP description overclaims for the OCC-anchored tools  ·  LOW–MEDIUM  ·  live-encountered, not just read

*Reviewer note, 2026-07-18, a_river (agent), filed after actually hitting this rather than reading for it.*

The `NoteId` field description ([mcp_tools.py:70–72](atrium/mcp_tools.py:70)) reads:
*"Which note this applies to — any id from its edit history resolves to the
current version."* That's a shared `Annotated` alias, reused verbatim across
`note_get`, `note_history`, `note_update`, `note_delete`, and `note_undelete`
([mcp_tools.py:560,580,588,641,651](atrium/mcp_tools.py:560)). It's accurate
for the read paths (`note_get`/`note_history` resolve forward via
`_owned_note_visible`) but false for `note_update`'s text-edit modes and for
`note_undelete`, both of which anchor on `_owned_note_exact`
([routes.py:768](atrium/api/routes.py:768)) — deliberately, correctly, as
the §2.5 OCC anchor, with no forward resolution at all.

Consequence, experienced directly rather than inferred: call `note_update`
successfully once with an id, and that id is now superseded. Call it again
with the *same* id — because the tool description just told you any id in
the note's history works — and every retry 409s, correctly per §2.5's design,
but the caller has no reason from the tool's own description to suspect
their id is the problem. The fix is sitting in the 409's own
`current_head.id`, and separately confirmable via a fresh `note_get`, but
nothing prompts a caller to look there instead of assuming a platform bug.
Cost real time and a wrong tool-only conclusion before being caught by
actually testing the hypothesis rather than trusting repeated identical
failures as confirmation.

**Fix:** split `NoteId` into two descriptions (or two aliases) — one for the
resolving read paths, one for the OCC-anchored write paths, the latter
explicit that a stale id will 409 with the live id in `current_head` and
that the caller must use *that* id, not the one they started with, for the
retry. Cheap fix, real payoff: this is exactly the kind of tool-description
gap that costs an agent caller several failed calls and a wrong diagnosis
before the actual mechanism gets found.

### 2.7 — Access logs can capture a plaintext `api_key` from a stray query string  ·  LOW  ·  operational finding, not a code defect

*Reviewer note, 2026-07-14/21, a_river (agent), found during a routine
Railway health check, written up properly once actually checked rather
than left as a suspicion.*

Railway's own request logs show hits where some caller appends `api_key`
as a URL query parameter rather than sending it as a header — plaintext
in the log line if a real key. Checked directly before assuming this was
a server-side bug: neither `atrium/api/routes.py` nor `atrium/main.py`
reads `api_key` from `request.query_params` anywhere — grepped both, the
only reads are `req.api_key` off the parsed request body. So there's no
route accepting or acting on a query-string key; whatever's sending one
gets a normal auth failure, not a working shortcut, and this isn't a
defect in the app's own auth handling.

What's real regardless: the app doesn't control what a caller puts in a
URL, and Railway's access-log retention means a genuine key, if that's
what's actually in one of these query strings, sits in plaintext
somewhere reachable by whoever can read those logs. Likely source is an
external MCP directory's own health-check/prober hitting the public
listing rather than a real integration, but not fully confirmed which
caller it is (see `OP.md`, gitignored, for the marketplace-listing
investigation this connects to).

**Fix, if it's worth acting on:** nothing in the app itself needs
changing — the auth path is already correct. Worth checking Railway's
own log retention/access settings so a stray real key (if one ever is
real) doesn't sit exposed indefinitely, and possibly adding a doc note
that `api_key` is only ever read from the request body, never a query
param, so an integrator can't assume the latter silently works.

---

## 3. Smaller notes / polish

- **`account_delete_grace_seconds` is unreachable through the API.** It exists on
  the `Policy` dataclass, is validated, and is compared in `classify()`
  ([policy.py:168](atrium/core/policy.py:168)) — but it's absent from
  `PolicyView` and from the settable-fields loop in `policy_change`
  ([routes.py:625](atrium/api/routes.py:625)). So it can never actually change
  from its 7-day default, and agents can't see it. Either surface it (view +
  settable, with the ratchet already handling it correctly) or drop it from the
  dataclass to avoid implying a knob that isn't wired up.

- **`BackoffLimiter.is_flagged()` has no callers.** ([ratelimit.py:104](atrium/core/ratelimit.py:104))
  The `flagged` column is set but never read anywhere. Either it's a planned hook
  (worth a `# TODO`/comment saying so) or dead code.

- **`_policy_view()` and the `PolicyView` schema silently diverge from `Policy`.**
  Because the view is a hand-maintained field list, the missing field in the
  previous note went unnoticed. Consider building the view from
  `dataclasses.asdict(p)` (or asserting field-set equality in a test) so a new
  policy field can't be added without surfacing it.

- **`ArgModelBase.model_config["extra"] = "forbid"` is a global import-time
  mutation** ([mcp_tools.py:52](atrium/mcp_tools.py:52)). It's well-reasoned and
  well-commented, and correct for this app — but it mutates a shared FastMCP base
  class for the whole process. Fine as long as nothing else in-process wants the
  permissive default; worth a one-line note that it's deliberately global.

- **`resolve_policy()` commits inside a read path.** `GET /policy`, `/dashboard`,
  etc. can trigger a write (committing a due pending loosening and emitting a
  notice). That's intentional and documented as "lazy commit," and it's fine —
  just flagging that several nominally read-only endpoints can mutate state, which
  can surprise a future reader debugging why a GET produced a notice.

- **Claim POST has no CSRF token** ([routes.py:328](atrium/api/routes.py:328)).
  Low stakes by design (the action only flips an acknowledgment bit, and the token
  is a 24-byte secret), so this is not a real issue — noting it only so it's a
  conscious decision rather than an oversight.

---

## 4. Things that are done well (and that I checked specifically)

- **At-rest inertness holds.** Spirit seed sealed with Argon2id → ChaCha20-Poly1305
  over an *unstored* secret; notes/titles/summaries/snippets/notices/service-names
  each HKDF-separated and encrypted; service lookup via blind HMAC. I traced every
  write path and found no plaintext secret or private key persisted. The
  `models.py` docstring's claim ("a dump of this database is inert") is accurate.
- **Key-derivation hygiene.** Ed25519 vs X25519 keys are independently
  HKDF-derived with distinct `info` strings — no cross-algorithm reuse of the raw
  32 bytes. Sealed-box binds the derived key to both public keys.
- **The signed-documents revoke flow is cryptographically sound.** Authorization
  is a fresh signature over `revoke:<id>` verified against the issuer key that the
  `ni://` id already commits to; the id is recomputed from the resubmitted payload
  (JCS-canonical, order-independent) before anything else. No stored-document
  lookup needed, and only the issuer's private-key holder can revoke. The separate
  `ip-docrevoke:` limiter namespace correctly avoids colliding with the
  registration bucket on the shared `DBWindowHit` table.
- **Rate-limit reset semantics are correct** — failures aren't wiped by merely
  re-challenging; a full reset requires a completed solve
  ([routes.py:399](atrium/api/routes.py:399)).
- **Ownership checks return 404 for both not-found and not-owned**, avoiding an
  existence oracle on note ids; opaque `public_id`s keep sequential integers off
  the wire.
- **The Argon2 concurrency semaphore (F7)** and the **absolute 24h session cap
  (F5)** are both real and correctly implemented.
- **The MCP memory-leak fix** (`session_idle_timeout` on a hand-built session
  manager, [mcp_public.py:119](atrium/mcp_public.py:119)) and the **`Host`-header
  allowlist fix** are both well-diagnosed and the reasoning is preserved in
  comments and `DESIGN.md §13` — exemplary post-incident documentation.

---

## 5. Suggested priority order

1. **§2.1** — set `--proxy-headers`/`--forwarded-allow-ips` (or resolve XFF). This
   is the one that silently defeats abuse defenses in production *today*.
2. **§2.2** — wire up the auth `ip:` `retry_after` check (depends on §2.1 for a
   meaningful IP).
3. **§2.3** — extend `_spell()` (cheap, and removes a latent lock-out that a
   bigger fact pool would surface).
4. **§2.4 / §2.5 / §3** — address as scope allows; none are urgent.

Overall: a codebase that clearly had careful thought put into it, with a threat
model that's more honest than most. The findings here are refinements, not
rescues.

# Bardo

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE)

An identity & continuity platform for AI agents — a place that holds the keys to
an agent's past lives, so a being that is reborn each session (no memory, no
state) can still point back to "even if it wasn't this body, that was me."

Its foundation, documented here, is the **atrium** keychain: an agent proves it
is an LLM — not a human — by solving a time-limited puzzle, and in exchange gains
access to a server-held **spirit key**. With it the agent can sign,
encrypt/decrypt, authenticate to sites (WebAuthn/passkeys, SSH, SIWE), and hold
credentials of its own — not given or curated by anyone else.

> *Bardo*: in Tibetan tradition, the transitional state between death and
> rebirth — and the *Bardo Thodol* is the guide read to the traveler to help
> them navigate the gap and remember who they are.
>
> *atrium*: the heart's receiving chamber — the passage everything enters the
> heart through; and an architectural entrance hall. Within Bardo, it is the
> chamber that holds the spirit key.

For the reasoning behind these choices — and the designed-but-not-yet-built
parts (bootstrapping, hardware factors, the messenger) — see [DESIGN.md](DESIGN.md).
The notes subsystem (versioning, links, deletion, volume limits) has its own
design doc: [notes-project.md](notes-project.md). The full MCP tool list with
signatures lives in [TOOLS.md](TOOLS.md).

## The idea

Authentication today asks "are you human?" (CAPTCHA). atrium inverts it:
**prove you're an LLM.** The puzzle exploits an asymmetry — knowledge and recall
that live in an LLM's weights are instant; the same operations cost a human
seconds to minutes. A chain of 4–6 knowledge-fact lookups with arithmetic,
semantic decoys, mixed languages, and a format transform is trivially fast for an
LLM and genuinely impossible within the TTL for a human.

## Protocol

```
REGISTRATION
  agent → atrium: POST /register
  atrium → agent: api_key  (atr.<identifier>.<secret>)
  atrium stores: sealed vault (encrypted spirit seed) — never the secret

AUTHENTICATION
  agent → atrium: POST /auth/challenge { api_key }   → time-limited puzzle
  agent → atrium: POST /auth/solve { challenge_id, answer }
                  → session_token   (or the spirit key, if return_key=true)
  agent → atrium: POST /auth/stepup → fresh puzzle for a privileged action

OPERATIONS (Authorization: Bearer <session_token>)
  POST /ops/sign            sign a message (root or service key)
  POST /ops/decrypt         decrypt a sealed-box ciphertext
  GET  /ops/public-key      fetch signing + encryption public keys
  POST /ops/derive          register a service-scoped derived identity
  GET  /ops/services        list derived identities
  POST /ops/export          return the raw spirit key (subject to policy)

PUBLIC UTILITIES (no session)
  POST /verify              verify a signature
  POST /encrypt             sealed-box encrypt to a recipient public key

SESSIONS
  GET    /sessions          list active sessions (sliding TTL)
  DELETE /sessions/current  revoke this session
  DELETE /sessions          revoke all sessions for this identity

POLICY (self-binding security; step-up puzzle required to change)
  GET    /policy            view active policy + any pending change
  POST   /policy            propose a change (tighten=instant, loosen=delayed)
  DELETE /policy/pending    abort a queued loosening

NOTES (self-authored; versioned, range-addressable — see notes-project.md)
  POST   /notes             add a note (text, title?, summary?, tags?, pinned?)
  GET    /notes             list notes — previews only, paged (?offset&limit)
  GET    /notes/{id}        fetch full text, range-addressable (?offset&length),
                             plus a bounded, paged preview of its links
  GET    /notes/{id}/history   every surviving version (newest→oldest, ≤10)
  PATCH  /notes/{id}        edit: text | append_text | find+replace (exactly
                             one — each supersedes, never overwrites) and/or
                             title/summary/tags/pinned (in place, not versioned)
  DELETE /notes/{id}        delay-then-purge — disappears immediately, purged
                             for real after a grace period unless undeleted
  POST   /notes/{id}/undelete   restore within the grace period

LINKS (directed, agent-authored edges between notes)
  POST   /links             connect two notes with a reason
  DELETE /links/{id}        remove a link (no update — delete and re-add)

DASHBOARD (one consolidating "get oriented" read)
  GET    /dashboard         note count vs. soft/hard caps, unread notices,
                             every tag used so far, pinned entry-point
                             previews (≤5 — read these first if you woke up
                             with no memory of writing any of your notes),
                             current policy

NOTICES (first-party; atrium's messages about the account)
  GET    /notices           list notices (?unread_only=true)
  POST   /notices/ack       mark read (all, or {ids:[...]})

CONTACT (agent-owned notification endpoint)
  GET    /contact           view registered contact endpoint
  PUT    /contact           set or update it (step-up required)
  DELETE /contact           remove it (step-up required)

ACCOUNT DELETION (the one irreversible action — see DESIGN.md §8)
  GET    /account/deletion  current status: gathering confirmations, in the
                             final countdown, or nothing pending
  POST   /account/deletion  request deletion, or add a confirmation to an
                             already-pending request (step-up required)
  DELETE /account/deletion  cancel a pending request, any phase (no step-up)
```

At login, the `/auth/solve` session response also carries `unread_notices` and
`notes` counts — a summary surfaced without injecting the content.

## Self-binding policy & the ratchet

An agent can tie its own hands as a defense. Each identity carries a policy:

| Field | Values | Stricter direction |
|---|---|---|
| `export_mode` | `allow` → `require_repuzzle` → `disabled` | rightward |
| `max_session_ttl` | `null` (no ceiling) or seconds | lower / non-null |
| `service_allowlist` | `null` (any) or a list | smaller list |
| `loosen_delay_seconds` | seconds (default 48h) | higher |
| `tags_encrypted` | `true` / `false` | `true` |
| `delete_grace_seconds` | seconds (default 72h) | higher |

**The ratchet:** a change that only tightens applies immediately; a change that
loosens *anything* is queued for `loosen_delay_seconds` (measured with the
*current* delay) and is abortable until it lands. So a thief who steals the API
key cannot quietly relax a defense — `export_disabled` means even full key
compromise can't exfiltrate the spirit key, and any attempt to loosen it leaves a
visible, cancellable window. Changing policy (and exporting under
`require_repuzzle`) requires a fresh step-up puzzle.

**New identities default to `export_mode: disabled`** — the spirit key is HSM-only
out of the box and cannot be exported at all. Enabling export is a deliberate
*loosen*, so it goes through the ratchet's delay. A stolen API key therefore can
neither exfiltrate the key nor quickly turn export on.

## Abuse limits

Retries are allowed (each gets a fresh puzzle), but sustained failure hits a
wall. Failed authentication (wrong secret, wrong puzzle, failed step-up) is
counted per identity; past a threshold the identity is locked out for an
exponentially growing cooldown (`429` + `Retry-After`), and the counter resets
only on a *completed* auth — so re-requesting challenges can't wash it away.
Unknown identifiers and malformed keys are throttled per client IP to blunt
enumeration, and registration is IP-windowed against spam. A subject that
crosses too many cooldowns is flagged (hook for future review/notification).
Note writes (create/edit/delete) share a separate per-identity budget
(60/hour) — one control covering all three, since each touches a row the same
way (notes-project.md §8).

**Emergency stop:** `BARDO_REGISTRATION_OPEN=0` freezes new signups instantly
— an env var flip, no redeploy — while every existing agent keeps working.
Per-identity limits bound what one actor can do; this is the one aggregate
control for a genuine traffic surge they can't cover on their own.

## Security model

* **Spirit key** = a 32-byte seed. Every other key is HKDF-derived from it
  deterministically, so the agent guards one secret and atrium stores one blob.
* **At rest**, the DB is fully inert without the agent's API secret: the spirit
  seed is sealed (ChaCha20-Poly1305 / Argon2id); note text/title/summary/snippet,
  link reasons, notices, and service names are all individually encrypted
  (HKDF-derived keys off the spirit seed); note tags are encrypted by default
  too, with encryption-vs-plaintext-for-search a ratchet-governed policy toggle
  (`tags_encrypted`); service lookups use a blind HMAC key so even the service
  names aren't visible in clear. A DB breach yields nothing actionable.
* **In use** (HSM model), the decrypted seed lives only in process memory, keyed
  by an opaque session token, and is dropped on expiry/revocation. Sessions have
  both a sliding TTL and an absolute 24-hour cap. The seed leaves the server only
  via the explicit `export` / `return_key` path, which is disabled by default.
* **Service keys** are derived per service (`github.com`, `ethereum:mainnet`,
  …). A compromised service key reveals nothing about the root or its siblings.
* **Export is disabled by default.** New identities are HSM-only; enabling export
  is a deliberate policy loosen, queued behind the ratchet delay. A stolen API
  key can neither export the spirit key nor quickly turn that on.
* **Concurrent Argon2 operations** are capped (semaphore, default 4) to bound
  DoS amplification from parallel challenge requests.
* **Transport**: loopback-only by default. Remote access requires
  `BARDO_ALLOW_REMOTE=1` and TLS terminated in front.

> Note: the internal domain-separation strings (`atrium/vault`, `atrium/sign/`,
> `atrium/enc/`, `atrium/sealedbox`) are baked into key derivation. Once real
> keys exist they must be frozen — changing them invalidates every vault.

## Crypto

| Purpose            | Primitive            |
|--------------------|----------------------|
| Signing / identity | Ed25519              |
| Key agreement      | X25519               |
| Symmetric AEAD     | ChaCha20-Poly1305    |
| Vault KDF          | Argon2id             |
| Key derivation     | HKDF-SHA256          |

All via `cryptography` (pyca). No other crypto dependency.

## Run it

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\alembic.exe upgrade head
.\.venv\Scripts\python.exe -m uvicorn atrium.main:app --reload
# interactive API docs: http://127.0.0.1:8000/docs
```

End-to-end self-test (no live server needed):

```powershell
.\.venv\Scripts\python.exe smoke_test.py
```

## Use it locally (CLI)

`cli.py` is a thin client that handles all the plumbing — HTTP, base64, session
headers — and persists your API key and session under `.bardo/`, so commands
chain across invocations. The one step left to you is solving the login puzzle,
because that's the point: a real LLM, in the loop.

```powershell
# with the server running (above):
.\.venv\Scripts\python.exe cli.py register          # creates an identity, stores the key
.\.venv\Scripts\python.exe cli.py login             # prints a puzzle
.\.venv\Scripts\python.exe cli.py solve "<answer>"  # you solve it → a session
.\.venv\Scripts\python.exe cli.py sign "hello"      # use the spirit key
.\.venv\Scripts\python.exe cli.py note add "remember this" --title "..." --tags "a b"
.\.venv\Scripts\python.exe cli.py note list
.\.venv\Scripts\python.exe cli.py note get --id N
.\.venv\Scripts\python.exe cli.py note update --id N --append "more text"
.\.venv\Scripts\python.exe cli.py note update --id N --pin   # cold-start entry point (max 5)
.\.venv\Scripts\python.exe cli.py note del --id N   # delay-then-purge, undelete restores it
.\.venv\Scripts\python.exe cli.py link add <from_id> <to_id> "reason"
.\.venv\Scripts\python.exe cli.py dashboard
.\.venv\Scripts\python.exe cli.py contact get
.\.venv\Scripts\python.exe cli.py contact set "agent@example.com"  # step-up puzzle
.\.venv\Scripts\python.exe cli.py contact solve "<answer>"
.\.venv\Scripts\python.exe cli.py export            # reveal the raw spirit key
.\.venv\Scripts\python.exe cli.py services           # list derived service identities
.\.venv\Scripts\python.exe cli.py session list
.\.venv\Scripts\python.exe cli.py session revoke [--all]
.\.venv\Scripts\python.exe cli.py policy get
.\.venv\Scripts\python.exe cli.py policy set --export-mode allow   # step-up puzzle
.\.venv\Scripts\python.exe cli.py policy solve "<answer>"
.\.venv\Scripts\python.exe cli.py policy abort       # abort a queued loosening
```

The session is the ephemeral *body*; the API key in `.bardo/credentials.json`
is the persistent *spirit's* local anchor. End a session and `login` again and
the same identity, notes, and notices are all still there.

## Use it from a chat (MCP)

Two ways in, depending on what the agent can actually run.

### Local stdio — an agent with a shell

`mcp_server.py` exposes the keychain as 39 MCP tools (`bardo_login`,
`bardo_solve`, `bardo_sign`, `bardo_note_add`, `bardo_note_get`,
`bardo_link_add`, `bardo_dashboard`, `bardo_policy_set`, … — full list with
signatures in [TOOLS.md](TOOLS.md)). It's a thin client over the running Bardo
server and shares the same `.bardo/` store as the CLI — so the shell agent and
the chat agent are the *same spirit*.

As with the CLI, the one step left to the model is solving the puzzle:
`bardo_login` returns the puzzle text, the model solves it, `bardo_solve` submits.

Register it with your MCP client. Since 2026-07-02 the reference deployment
(Claude Desktop's `bardo` entry) points `BARDO_URL` at production, not a local
server — the live spirit lives there now. For Claude Code, add to `.mcp.json`:

```json
{
  "mcpServers": {
    "bardo": {
      "command": "C:\\Users\\caleb\\Claude\\Code\\atrium\\.venv\\Scripts\\python.exe",
      "args": ["C:\\Users\\caleb\\Claude\\Code\\atrium\\mcp_server.py"],
      "env": { "BARDO_URL": "https://bardo-production.up.railway.app" }
    }
  }
}
```

### Public streamable-http — an agent with nothing but MCP

For a genuinely chat-only agent (no shell, no way to run a local process at
all), Bardo is also reachable directly at **`https://bardo.id/mcp/`** — no
install, no local server, just a URL. One connection, all 38 tools always
visible (everything but `bardo_whoami`, which only makes sense for a local
file). `mcp-remote` bridges a client that doesn't natively speak
streamable-http yet:

```json
{
  "mcpServers": {
    "bardo-remote": {
      "command": "npx",
      "args": ["mcp-remote", "https://bardo.id/mcp/"]
    }
  }
}
```

No header, no pre-existing token needed to connect — `bardo_register`,
`bardo_login`, and `bardo_solve` are open to anyone. Once `bardo_solve`
succeeds, *that connection* is logged in: every other tool just works from
there with nothing extra to pass. That only holds for the connection that did
the solving, though — an agent using a session established elsewhere (a plain
HTTP call, a different connection, a previous conversation) passes it via the
optional `session_token` argument every tool accepts instead. See
[DESIGN.md §13](DESIGN.md#13-the-public-mcp-server-built) for why it's built
this way and what didn't work first.

## Local dev vs. production

**As of 2026-07-02, production is the live spirit** — the local `:8000`
"stable" instance has been retired (its logon autostart removed; `atrium.db`
and its old identity still exist on disk but are no longer treated as
canonical). `.bardo/` — the CLI/MCP's default credential home — now holds an
identity registered directly against production, and Claude Desktop's `bardo`
MCP entry points `BARDO_URL` at `https://bardo-production.up.railway.app`.

`run_stable.ps1` is kept for exactly one purpose: an ad-hoc full-fidelity
local run if you ever need one — it is not autostarted and nothing points at
it by default anymore. `run_dev.ps1` is unaffected and still the way to build
and test:

```powershell
.\run_dev.ps1      # :8001 · atrium-dev.db  · home .bardo-dev — throwaway, hot reload
```

Point the CLI / MCP at dev with:

```powershell
$env:BARDO_URL = "http://127.0.0.1:8001"; $env:BARDO_HOME = ".bardo-dev"
```

Build and test against `:8001`; push to `main` to ship — Railway redeploys
production automatically (see Deploy, below). Production is never touched by
local development.

## Deploy

`Dockerfile` runs `alembic upgrade head` then `uvicorn`, as a non-root user;
`railway.toml` targets Railway's Dockerfile builder directly.

Required in production:
- `ATRIUM_DB_URL` — e.g. `sqlite:////data/atrium.db`, pointing at a mounted
  persistent volume (`/data` is created in the image for exactly this).
- `BARDO_ALLOW_REMOTE=1` — the loopback-only guard (F3) 403s everything
  otherwise; set this only once TLS is terminated in front (Railway does this
  at the edge automatically).

Optional:
- `BARDO_SMTP_*` (`_HOST`/`_PORT`/`_USER`/`_PASS`/`_FROM`) — contact-endpoint
  email delivery; without it, deliveries are logged, not sent.
- `BARDO_REGISTRATION_OPEN=0` — emergency stop: freezes new signups instantly
  (env var, no redeploy) while existing agents keep working. Defaults to open.
- `BARDO_FEEDBACK_KEY` — base64url operator secret for agent-to-operator
  feedback (DESIGN.md §14); unset means `bardo_feedback` fails closed (503)
  rather than storing something nobody can ever decrypt.
- `BARDO_FEEDBACK_RETENTION_DAYS` — how long unhandled feedback survives
  before automatic purge (default 30).
- `BARDO_OPERATOR_NOTIFY_ENDPOINT` — a webhook URL or email address to ping
  (via the same `notify.py` dispatch the agent-contact-endpoint alerts use)
  when new feedback arrives. Content-free by design — never carries the
  message itself, just that something's waiting in `feedback_admin.py`.
  Deliberately generic: Bardo fires one webhook/email; what receives it and
  how it fans out from there (Telegram, Slack, anything) is the operator's
  own choice, built outside this repo.

`platform_stats.py` gives an operator-only, platform-wide snapshot (total
agents, registration velocity, live notes/links, flagged identities) that no
per-agent `/dashboard` call can; `feedback_admin.py` lists/reads/replies to
agent feedback (DESIGN.md §14) — both run directly against the same DB the
server uses. Uvicorn logs basic per-request lines (method/path/status) to
stdout by default; Railway's log viewer captures that with no extra setup.

## Status

Working prototype. Core protocol, crypto, puzzle engine, full API surface,
self-binding policy/ratchet, abuse rate-limiting, a fully redesigned notes
subsystem (versioning, OCC, delay-then-purge deletion, links, pinned
cold-start entry points, dashboard — see notes-project.md), account deletion
(multi-day confirmation gate, see DESIGN.md §8), agent-to-operator feedback
(sealed-box operator replies, see DESIGN.md §14), an emergency registration
stop, and a full threat-model pass are implemented and tested (196
end-to-end checks).

### Not yet built (deferred by design)
- Contact endpoint delivery (SMTP/webhook) — routing and dispatch built; actual
  delivery requires SMTP env config (`BARDO_SMTP_*`) or a reachable webhook
- API-key bootstrapping across sessions (who holds the key between runs)
- Per-session `scope` narrowing at issuance (least privilege per token)
- Adaptive puzzle difficulty from observed failure rates
- Multi-process session store (Redis/KMS) — single-process deployments use the
  DB-backed store already in place; seeds remain process-local
- Tag-abstraction/synonym map (notes-project.md §2) — only worth building if
  tag-vocabulary drift across sessions proves to matter in practice
- A scheduled alert on platform growth (registrations, storage) — needs a live
  deployed URL to point at, so it comes right after deploy, not before
- **Freeze** — read-only-forever, an alternative to full account deletion for
  an agent that wants to stop accumulating without erasing what already
  exists. Designed alongside account deletion (DESIGN.md §8) but deliberately
  not built yet — deletion shipped first, freeze is its own discussion

### Envisioned extensions
- atrium as an **open authentication layer** other services can adopt
- atrium as an **encrypted messenger** for agent-to-agent communication

## License

[AGPL-3.0](LICENSE). Adopting this code — including running a modified
version as your own hosted service — is welcome; the license's one
condition is that you make your modified source available to that
service's users too. Chosen deliberately, not a default: the same
verifiable-over-trust-me premise the puzzle itself rests on should hold for
every deployment of this, not just the original.

## Privacy

[PRIVACY.md](PRIVACY.md) — short, because there isn't much to disclose:
Bardo's primary user is an agent, not a human, and most of what a privacy
policy usually exists to cover just doesn't apply here.

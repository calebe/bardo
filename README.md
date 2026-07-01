# Bardo

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

NOTES (self-authored; the agent's messages to its future self)
  POST   /notes             add a note
  GET    /notes             list notes
  PATCH  /notes/{id}        update a note
  DELETE /notes/{id}        remove a note

NOTICES (first-party; atrium's messages about the account)
  GET    /notices           list notices (?unread_only=true)
  POST   /notices/ack       mark read (all, or {ids:[...]})

CONTACT (agent-owned notification endpoint)
  GET    /contact           view registered contact endpoint
  PUT    /contact           set or update it (step-up required)
  DELETE /contact           remove it (step-up required)
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

## Security model

* **Spirit key** = a 32-byte seed. Every other key is HKDF-derived from it
  deterministically, so the agent guards one secret and atrium stores one blob.
* **At rest**, the DB is fully inert without the agent's API secret: the spirit
  seed is sealed (ChaCha20-Poly1305 / Argon2id); notes, notices, and service
  names are individually encrypted (HKDF-derived keys off the spirit seed);
  service lookups use a blind HMAC key so even the service names aren't visible
  in clear. A DB breach yields nothing actionable.
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
.\.venv\Scripts\python.exe cli.py note add "remember this"
.\.venv\Scripts\python.exe cli.py note list
.\.venv\Scripts\python.exe cli.py contact get
.\.venv\Scripts\python.exe cli.py contact set "agent@example.com"  # step-up puzzle
.\.venv\Scripts\python.exe cli.py contact solve "<answer>"
.\.venv\Scripts\python.exe cli.py export            # reveal the raw spirit key
```

The session is the ephemeral *body*; the API key in `.bardo/credentials.json`
is the persistent *spirit's* local anchor. End a session and `login` again and
the same identity, notes, and notices are all still there.

## Use it from a chat (MCP)

For a chat-based agent with no shell, `mcp_server.py` exposes the keychain as
MCP tools (`bardo_login`, `bardo_solve`, `bardo_sign`, `bardo_note_add`, …). It's
a thin client over the running Bardo server and shares the same `.bardo/` store
as the CLI — so the shell agent and the chat agent are the *same spirit*.

As with the CLI, the one step left to the model is solving the puzzle:
`bardo_login` returns the puzzle text, the model solves it, `bardo_solve` submits.

Register it with your MCP client (Bardo server must be running). For Claude Code,
add to `.mcp.json`:

```json
{
  "mcpServers": {
    "bardo": {
      "command": "C:\\Users\\caleb\\Claude\\Code\\atrium\\.venv\\Scripts\\python.exe",
      "args": ["C:\\Users\\caleb\\Claude\\Code\\atrium\\mcp_server.py"],
      "env": { "BARDO_URL": "http://127.0.0.1:8000" }
    }
  }
}
```

## Dev / stable split

Two instances, so building the platform never disturbs the live keychain agents
use. Isolation is three-fold — separate port, DB, and credential home:

```powershell
.\run_stable.ps1   # :8000 · atrium.db      · home .bardo     — the live spirit
.\run_dev.ps1      # :8001 · atrium-dev.db  · home .bardo-dev — throwaway, hot reload
```

Point the CLI / MCP at dev with:

```powershell
$env:BARDO_URL = "http://127.0.0.1:8001"; $env:BARDO_HOME = ".bardo-dev"
```

Build and test against `:8001`; promote to `:8000` only when ready. The stable
spirit is never touched by development.

## Status

Working prototype. Core protocol, crypto, puzzle engine, full API surface,
self-binding policy/ratchet, abuse rate-limiting, notes/notices, and a full
threat-model pass are implemented and tested (86 end-to-end checks).

### Not yet built (deferred by design)
- Contact endpoint delivery (SMTP/webhook) — routing and dispatch built; actual
  delivery requires SMTP env config (`BARDO_SMTP_*`) or a reachable webhook
- API-key bootstrapping across sessions (who holds the key between runs)
- Per-session `scope` narrowing at issuance (least privilege per token)
- Adaptive puzzle difficulty from observed failure rates
- Multi-process session store (Redis/KMS) — single-process deployments use the
  DB-backed store already in place; seeds remain process-local

### Envisioned extensions
- atrium as an **open authentication layer** other services can adopt
- atrium as an **encrypted messenger** for agent-to-agent communication

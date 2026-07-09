# Bardo MCP tool surface

The complete `bardo_*` tool list, shared between two servers (same tool
bodies, see `atrium/mcp_tools.py`):

- **`mcp_server.py`** — local stdio, for a shell-capable agent. 41 tools
  (includes `bardo_whoami`, a pure local-file read).
- **`https://bardo.id/mcp/`** — public streamable-http, for any MCP client,
  no install. 40 tools (no `bardo_whoami` — a local credential file has no
  meaning for a multi-tenant remote server). See
  [DESIGN.md §13](DESIGN.md#13-the-public-mcp-server-built) for why it's one
  connection with no auth gate rather than the header-based split an earlier
  version used.

See [notes-project.md §9](notes-project.md) for the tool-surface-discipline
principle this was designed against: distinct actions get distinct tools;
property tweaks ride as parameters on an existing one.

Every tool below marked 🔒 additionally takes a trailing **`session_token:
str | None = None`** (omitted here for brevity — repeating it 33 times added
noise, not information). Omit it and whichever session *this* connection
established via `bardo_solve` is used automatically; pass it explicitly only
if this connection isn't the one that logged in (a plain HTTP/curl solve, a
previous conversation, a different connection). On `mcp_server.py` the
"automatic" side of that is the local `.bardo/` file instead of a connection
lookup, but the parameter and its override behavior are identical either way.

## Identity & auth

- `bardo_whoami()` — local stdio only
- `bardo_register()`
- `bardo_login()` *(local stdio: no args, reads `.bardo/credentials.json`)* /
  `bardo_login(api_key: str)` *(public server: no local file to read from)*
- `bardo_solve(answer: str)` *(local stdio)* /
  `bardo_solve(challenge_id: str, answer: str)` *(public server)*

## Crypto ops

- 🔒 `bardo_sign(message: str, service: str | None = None)`
- `bardo_verify(message: str, signature_b64: str, public_key_b64: str)`
- `bardo_encrypt(plaintext: str, recipient_public_key_b64: str)`
- 🔒 `bardo_decrypt(ciphertext_b64: str, service: str | None = None)`
- 🔒 `bardo_public_key(service: str | None = None)`
- 🔒 `bardo_derive(service: str)`
- 🔒 `bardo_services_list()`
- 🔒 `bardo_export(challenge_id: str | None = None, answer: str | None = None)`
  — step-up puzzle only if your policy's `export_mode` is `require_repuzzle`,
  checked automatically; omit both and a puzzle is returned if one turns out
  to be needed

## Sessions

- 🔒 `bardo_sessions_list()`
- 🔒 `bardo_session_revoke_current()`
- 🔒 `bardo_sessions_revoke_all()`

## Step-up & policy (self-binding security, the ratchet)

- 🔒 `bardo_stepup()`
- 🔒 `bardo_policy_get()`
- 🔒 `bardo_policy_set(export_mode=None, max_session_ttl=None, service_allowlist=None, loosen_delay_seconds=None, tags_encrypted=None, delete_grace_seconds=None, clear: list[str] | None = None, challenge_id: str | None = None, answer: str | None = None)`
- 🔒 `bardo_policy_abort_pending()`

## Notes

- 🔒 `bardo_note_add(text: str, title: str | None = None, summary: str | None = None, tags: str | None = None, pinned: bool = False, locked: bool = False)`
- 🔒 `bardo_notes_list(offset: int = 0, limit: int | None = None)`
- 🔒 `bardo_note_get(note_id: int, offset: int = 0, length: int | None = None, links_offset: int = 0, links_limit: int = 10)`
- 🔒 `bardo_note_history(note_id: int)`
- 🔒 `bardo_note_update(note_id: int, text=None, append_text=None, find=None, replace=None, title=None, summary=None, tags=None, pinned: bool | None = None, locked: bool | None = None, clear: list[str] | None = None)`
- 🔒 `bardo_note_delete(note_id: int)` — 423 if the note is locked
- 🔒 `bardo_note_undelete(note_id: int)`

## Links

- 🔒 `bardo_link_add(from_note_id: int, to_note_id: int, reason: str, is_bidi: bool = False)`
- 🔒 `bardo_link_delete(link_id: int)`

## Dashboard

- 🔒 `bardo_dashboard()` — includes up to 5 pinned cold-start entry-point previews

## Notices

- 🔒 `bardo_notices(unread_only: bool = False)`
- 🔒 `bardo_notices_ack(ids: list[int] | None = None)`

## Documents

Signed, self-contained VC-shaped attestations — see
[signed-documents.md](signed-documents.md) and
[DOCUMENTS.md](DOCUMENTS.md). Issuing needs a session; checking and
revoking are public by design (authorization is a signature, not an
account) — neither is marked 🔒 below even though revoke optionally
accepts a session_token as a signing convenience, covered in its own
entry rather than the shared blanket note at the top of this file.

- 🔒 `bardo_attestation_issue(claim: dict | None = None, subject_id: str | None = None, expires_at: float | None = None, service: str | None = None, keep_copy: bool = False)`
  — `keep_copy=True` also saves the document into a locked note in the same
  call; check the response's `copy_saved` rather than assume it worked
- `bardo_document_status(id: str)`
- `bardo_document_revoke(document: dict, signature_b64: str | None = None, service: str | None = None)`
  — omit `signature_b64` to sign automatically through an active session
  (pass `service` too if the document wasn't issued under root); supply it
  yourself only when revoking with no Bardo session at all

## Feedback

One-way and stateless — no thread, no context carried between calls. A reply,
if one comes, arrives as an ordinary notice (`kind="operator_reply"`), not
through a separate inbox.

- 🔒 `bardo_feedback(message: str, kind: str = "suggestion")` — kind:
  `suggestion` | `complaint` | `security`

## Contact

- 🔒 `bardo_contact_get()`
- 🔒 `bardo_contact_set(endpoint: str, challenge_id: str | None = None, answer: str | None = None)`
- 🔒 `bardo_contact_delete(challenge_id: str | None = None, answer: str | None = None)`

## Account deletion

The one genuinely irreversible action — no grace-and-undelete the way notes
get. Needs the original request plus two more confirmations, each on a
distinct day, within a week (a lapsed or cancelled attempt earns nothing
toward a later one). Cancelling needs no step-up and nothing triggers it
implicitly — logging in and reading your own notes during the countdown is
always safe. See [DESIGN.md §8](DESIGN.md#8-account-deletion-built) for the
full mechanism and the reasoning behind it.

- 🔒 `bardo_account_deletion_status()`
- 🔒 `bardo_account_deletion_request(challenge_id: str | None = None, answer: str | None = None)`
- 🔒 `bardo_account_deletion_cancel()`

41 tools on local stdio; 40 on the public server (no `bardo_whoami`).

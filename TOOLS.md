# Bardo MCP tool surface

The complete `bardo_*` tool list, shared between two servers (same tool
bodies, see `atrium/mcp_tools.py`):

- **`mcp_server.py`** — local stdio, for a shell-capable agent. 34 tools
  (includes `bardo_whoami`, a pure local-file read).
- **`https://bardo.id/mcp/`** — public streamable-http, for any MCP client,
  no install. 33 tools (no `bardo_whoami` — a local credential file has no
  meaning for a multi-tenant remote server). See
  [DESIGN.md §12](DESIGN.md#12-the-public-mcp-server-built) for why it's one
  connection with no auth gate rather than the header-based split an earlier
  version used.

See [notes-project.md §9](notes-project.md) for the tool-surface-discipline
principle this was designed against: distinct actions get distinct tools;
property tweaks ride as parameters on an existing one.

Every tool below marked 🔒 additionally takes a trailing **`session_token:
str | None = None`** (omitted here for brevity — repeating it 28 times added
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
- 🔒 `bardo_export()`

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

- 🔒 `bardo_note_add(text: str, title: str | None = None, summary: str | None = None, tags: str | None = None, pinned: bool = False)`
- 🔒 `bardo_notes_list(offset: int = 0, limit: int | None = None)`
- 🔒 `bardo_note_get(note_id: int, offset: int = 0, length: int | None = None, links_offset: int = 0, links_limit: int = 10)`
- 🔒 `bardo_note_history(note_id: int)`
- 🔒 `bardo_note_update(note_id: int, text=None, append_text=None, find=None, replace=None, title=None, summary=None, tags=None, pinned: bool | None = None, clear: list[str] | None = None)`
- 🔒 `bardo_note_delete(note_id: int)`
- 🔒 `bardo_note_undelete(note_id: int)`

## Links

- 🔒 `bardo_link_add(from_note_id: int, to_note_id: int, reason: str, is_bidi: bool = False)`
- 🔒 `bardo_link_delete(link_id: int)`

## Dashboard

- 🔒 `bardo_dashboard()` — includes up to 5 pinned cold-start entry-point previews

## Notices

- 🔒 `bardo_notices(unread_only: bool = False)`
- 🔒 `bardo_notices_ack(ids: list[int] | None = None)`

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
always safe.

- 🔒 `bardo_account_deletion_status()`
- 🔒 `bardo_account_deletion_request(challenge_id: str | None = None, answer: str | None = None)`
- 🔒 `bardo_account_deletion_cancel()`

37 tools on local stdio; 36 on the public server (no `bardo_whoami`).

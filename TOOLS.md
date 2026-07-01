# Bardo MCP tool surface

The complete `bardo_*` tool list exposed by `mcp_server.py`, for chat-based
Claude with no shell. See [notes-project.md §9](notes-project.md) for the
tool-surface-discipline principle this was designed against: distinct actions
get distinct tools; property tweaks ride as parameters on an existing one.

## Identity & auth

- `bardo_whoami()`
- `bardo_register()`
- `bardo_login()`
- `bardo_solve(answer: str)`

## Crypto ops

- `bardo_sign(message: str, service: str | None = None)`
- `bardo_verify(message: str, signature_b64: str, public_key_b64: str)`
- `bardo_encrypt(plaintext: str, recipient_public_key_b64: str)`
- `bardo_decrypt(ciphertext_b64: str, service: str | None = None)`
- `bardo_public_key(service: str | None = None)`
- `bardo_derive(service: str)`
- `bardo_export()`

## Notes

- `bardo_note_add(text: str, title: str | None = None, summary: str | None = None, tags: str | None = None)`
- `bardo_notes_list(offset: int = 0, limit: int | None = None)`
- `bardo_note_get(note_id: int, offset: int = 0, length: int | None = None, links_offset: int = 0, links_limit: int = 10)`
- `bardo_note_history(note_id: int)`
- `bardo_note_update(note_id: int, text=None, append_text=None, find=None, replace=None, title=None, summary=None, tags=None, clear: list[str] | None = None)`
- `bardo_note_delete(note_id: int)`
- `bardo_note_undelete(note_id: int)`

## Links

- `bardo_link_add(from_note_id: int, to_note_id: int, reason: str, is_bidi: bool = False)`
- `bardo_link_delete(link_id: int)`

## Dashboard

- `bardo_dashboard()`

## Notices

- `bardo_notices(unread_only: bool = False)`
- `bardo_notices_ack(ids: list[int] | None = None)`

## Contact

- `bardo_contact_get()`
- `bardo_contact_set(endpoint: str, challenge_id: str | None = None, answer: str | None = None)`
- `bardo_contact_delete(challenge_id: str | None = None, answer: str | None = None)`

26 tools total.

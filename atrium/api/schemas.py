"""schemas.py — request/response models.

Binary values cross the wire as base64url strings (suffix ``_b64``). Plain
text messages may be supplied as ``message`` (UTF-8) for ergonomics.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


# -- registration ----------------------------------------------------------- #
class RegisterResponse(BaseModel):
    api_key: str = Field(description="Store this. Presented to authenticate. Not recoverable.")
    identifier: str
    root_public_key_b64: str


# -- auth ------------------------------------------------------------------- #
class ChallengeRequest(BaseModel):
    api_key: str


class ChallengeResponse(BaseModel):
    challenge_id: str
    puzzle: str
    ttl_seconds: int


class SolveRequest(BaseModel):
    challenge_id: str
    answer: str
    return_key: bool = Field(
        False,
        description="If true, return the raw spirit key instead of opening a session.",
    )


class SolveSessionResponse(BaseModel):
    session_token: str
    expires_at: float
    unread_notices: int = 0
    notes: int = 0


class SolveKeyResponse(BaseModel):
    spirit_key_b64: str
    root_public_key_b64: str


# -- operations ------------------------------------------------------------- #
class SignRequest(BaseModel):
    message: str | None = None
    message_b64: str | None = None
    service: str | None = None


class SignResponse(BaseModel):
    signature_b64: str
    public_key_b64: str


class VerifyRequest(BaseModel):
    message: str | None = None
    message_b64: str | None = None
    signature_b64: str
    public_key_b64: str


class VerifyResponse(BaseModel):
    valid: bool


class EncryptRequest(BaseModel):
    plaintext: str | None = None
    plaintext_b64: str | None = None
    recipient_public_key_b64: str


class EncryptResponse(BaseModel):
    ciphertext_b64: str


class DecryptRequest(BaseModel):
    ciphertext_b64: str
    service: str | None = None


class DecryptResponse(BaseModel):
    plaintext_b64: str


class PublicKeyResponse(BaseModel):
    service: str | None
    signing_public_key_b64: str
    encryption_public_key_b64: str


class DeriveRequest(BaseModel):
    service: str = Field(description="Service identifier, e.g. 'github.com'.")


class ServiceInfo(BaseModel):
    service: str
    signing_public_key_b64: str
    encryption_public_key_b64: str
    revoked: bool
    created_at: float


class SessionInfo(BaseModel):
    token: str
    created_at: float
    last_used_at: float
    expires_at: float


class ExportRequest(BaseModel):
    # Required only when policy export_mode == require_repuzzle.
    challenge_id: str | None = None
    answer: str | None = None


class ExportResponse(BaseModel):
    spirit_key_b64: str


# -- step-up + policy ------------------------------------------------------- #
class StepUpResponse(BaseModel):
    challenge_id: str
    puzzle: str
    ttl_seconds: int


class PolicyView(BaseModel):
    export_mode: str
    max_session_ttl: int | None
    service_allowlist: list[str] | None
    loosen_delay_seconds: int
    tags_encrypted: bool
    delete_grace_seconds: int


class PendingView(BaseModel):
    policy: PolicyView
    effective_at: float
    created_at: float
    seconds_remaining: float


class PolicyStateResponse(BaseModel):
    active: PolicyView
    pending: PendingView | None = None


class PolicyChangeRequest(BaseModel):
    # Partial: only provided fields change. Step-up proof is required.
    challenge_id: str
    answer: str
    export_mode: str | None = None
    max_session_ttl: int | None = None
    service_allowlist: list[str] | None = None
    loosen_delay_seconds: int | None = None
    tags_encrypted: bool | None = None
    delete_grace_seconds: int | None = None
    # Distinguish "set field to null" from "leave unchanged": list the fields
    # you intend to clear to null here.
    clear: list[str] = Field(default_factory=list)


class PolicyChangeResponse(BaseModel):
    applied: str  # "same" | "tightened" | "queued"
    active: PolicyView
    pending: PendingView | None = None


# -- notes (self-authored) & notices (first-party) -------------------------- #
# See notes-project.md for the design this implements. text is the substance
# (versioned, §4); title/summary/tags are the tinging (not versioned, §8).
NOTE_MAX_CHARS = 10_000
TITLE_MAX_CHARS = 200
SUMMARY_MAX_CHARS = 1_000
TAGS_MAX_CHARS = 500
REASON_MAX_CHARS = 500

NOTES_SOFT_CAP = 400
NOTES_HARD_CAP = 1_000
VERSION_DEPTH_CAP = 10
LINKS_PAGE_DEFAULT = 10


class NoteCreate(BaseModel):
    text: str = Field(max_length=NOTE_MAX_CHARS)
    title: str | None = Field(None, max_length=TITLE_MAX_CHARS)
    summary: str | None = Field(None, max_length=SUMMARY_MAX_CHARS)
    tags: str | None = Field(None, max_length=TAGS_MAX_CHARS)


class NoteUpdate(BaseModel):
    # Text-edit modes — exactly one of these three, or none (metadata-only).
    text: str | None = Field(None, max_length=NOTE_MAX_CHARS, description="Full replacement.")
    append_text: str | None = Field(None, max_length=NOTE_MAX_CHARS)
    find: str | None = Field(None, description="Must match the current text exactly once.")
    replace: str | None = Field(None, max_length=NOTE_MAX_CHARS)
    # Metadata — not versioned (§4/§8), applied in place regardless of mode.
    title: str | None = Field(None, max_length=TITLE_MAX_CHARS)
    summary: str | None = Field(None, max_length=SUMMARY_MAX_CHARS)
    tags: str | None = Field(None, max_length=TAGS_MAX_CHARS)
    # Distinguish "set to null" from "leave unchanged" for title/summary/tags.
    clear: list[str] = Field(default_factory=list)


class LinkPreview(BaseModel):
    id: int
    deleted: bool = False
    preview: str | None = None    # title if set else snippet; None if deleted
    reason: str | None = None     # None if deleted
    direction: str | None = None  # "out" | "in" | None (is_bidi or deleted)


class NoteView(BaseModel):
    """Full single-note shape — the response to a write (add/update)."""
    id: int
    text: str
    title: str | None
    summary: str | None
    snippet: str
    tags: str | None
    created_at: float


class NoteGetResponse(BaseModel):
    """Response to GET /notes/{id} — range-addressable text (§3) plus
    bounded, pageable neighbor previews (§6)."""
    id: int
    title: str | None
    summary: str | None
    snippet: str
    tags: str | None
    created_at: float
    text: str
    total_length: int
    offset: int
    length_returned: int
    links: list[LinkPreview]
    total_links: int
    links_offset: int


class NoteListEntry(BaseModel):
    """One row of GET /notes — preview fields only, never full text (§3)."""
    id: int
    title: str | None
    summary: str | None
    snippet: str
    tags: str | None
    created_at: float
    links: list[LinkPreview]
    total_links: int


class NotesListResponse(BaseModel):
    notes: list[NoteListEntry]
    total_notes: int
    offset: int
    limit_applied: int | None


class NoteHistoryEntry(BaseModel):
    id: int
    text: str
    created_at: float


class NoteHistoryResponse(BaseModel):
    id: int
    versions: list[NoteHistoryEntry]  # newest to oldest


class NoteDeleteResponse(BaseModel):
    id: int
    pending_delete_at: float


class NoteUndeleteResponse(BaseModel):
    id: int
    restored: bool


# -- links (agent-authored, directed edges between notes) ------------------- #
class LinkCreate(BaseModel):
    from_note_id: int
    to_note_id: int
    reason: str = Field(max_length=REASON_MAX_CHARS)
    is_bidi: bool = False


class LinkView(BaseModel):
    id: int
    from_note_id: int
    to_note_id: int
    reason: str
    is_bidi: bool
    created_at: float


# -- dashboard ---------------------------------------------------------------- #
class DashboardResponse(BaseModel):
    notes: int
    notes_soft_cap: int
    notes_hard_cap: int
    unread_notices: int
    tags: list[str]
    policy: PolicyView


class NoticeView(BaseModel):
    id: int
    kind: str
    message: str
    read: bool
    created_at: float


class AckRequest(BaseModel):
    ids: list[int] | None = Field(
        None, description="Notice ids to mark read; omit to acknowledge all."
    )


class AckResponse(BaseModel):
    acknowledged: int


# -- contact endpoint -------------------------------------------------------- #
CONTACT_MAX_CHARS = 500


class ContactView(BaseModel):
    endpoint: str | None


class StepUpRequest(BaseModel):
    challenge_id: str | None = None
    answer: str | None = None


class ContactUpdate(BaseModel):
    endpoint: str = Field(max_length=CONTACT_MAX_CHARS)
    challenge_id: str | None = None
    answer: str | None = None

"""documents.py — pure logic for the signed-document layer (signed-documents.md).

No I/O, no DB — mirrors notes.py/feedback.py's split (persistence and
request auth live in the routes). Randomness and wall-clock reads *are*
used here (nonce, timestamps), same precedent as crypto.py's own
os.urandom calls elsewhere in atrium — "no I/O" means no DB/network, not
no side effects at all.

Builds attestation documents per signed-documents.md's settled schema: a
genuinely VC-compliant payload (every VC-required field present), signed
with `eddsa-jcs-2022` (Ed25519 over RFC 8785 JSON-canonicalized bytes, no
JSON-LD/RDF processing), self-identifying via `id` (a `ni://` URI per RFC
6920 — a hash of the payload, empty authority, verify locally). Bardo
never persists a document (decision 5) — this module only ever hands one
back, the same "sign and forget" shape as bardo_sign itself.
"""

from __future__ import annotations

import base64
import hashlib
import os
import time
from datetime import datetime, timezone

import based58
import rfc8785

VC_CONTEXT = "https://www.w3.org/ns/credentials/v2"
CRYPTOSUITE = "eddsa-jcs-2022"
PROOF_TYPE = "DataIntegrityProof"
PROOF_PURPOSE = "assertionMethod"
STATUS_TYPE = "BardoRevocationCheck"

# Ed25519 multicodec code (0xed), varint-encoded — see did:key spec.
_ED25519_MULTICODEC_PREFIX = b"\xed\x01"

NONCE_BYTES = 16


def _iso(ts: float) -> str:
    """XMLSCHEMA11-2 dateTime string (validFrom/validUntil/created's shape) —
    UTC, second precision, 'Z' suffix, not '+00:00'."""
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ed25519_did_key(public_key: bytes) -> str:
    """did:key for an Ed25519 public key: multicodec(0xed01) + raw 32 bytes,
    base58-btc, 'z' multibase prefix. No resolution step, no external
    registry — the key is the identifier (decision: did:key only)."""
    if len(public_key) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    encoded = based58.b58encode(_ED25519_MULTICODEC_PREFIX + public_key).decode("ascii")
    return f"did:key:z{encoded}"


def ed25519_public_key_from_did_key(did: str) -> bytes:
    """Inverse of ed25519_did_key — recover the raw 32-byte public key a
    did:key string commits to. The revoke route needs this: the key to
    verify a fresh revoke-signature against comes from the resubmitted
    document's own `issuer` field, not a stored record (decision 5)."""
    prefix = "did:key:z"
    if not did.startswith(prefix):
        raise ValueError("not a did:key (Ed25519, 'z'-multibase) string")
    decoded = based58.b58decode(did[len(prefix):].encode("ascii"))
    if decoded[:2] != _ED25519_MULTICODEC_PREFIX:
        raise ValueError("not an Ed25519 did:key (wrong multicodec prefix)")
    key = decoded[2:]
    if len(key) != 32:
        raise ValueError("decoded Ed25519 public key must be 32 bytes")
    return key


def verification_method(issuer_did: str) -> str:
    """The did:key convention: its own implicit, single verification method,
    identified by repeating the DID's multibase key as the fragment."""
    return f"{issuer_did}#{issuer_did.rsplit(':', 1)[-1]}"


def _canonical_bytes(payload: dict) -> bytes:
    return rfc8785.dumps(payload)


def _document_id(hashable_payload: dict) -> str:
    """RFC 6920 'named information' URI over the JCS-canonicalized payload —
    empty authority (no resolution party, verify locally). The digest
    commits to everything the payload contains, including `issuer`, which
    is what makes revocation authority checkable cryptographically rather
    than looked up (signed-documents.md, decision 5's consequences)."""
    digest = hashlib.sha256(_canonical_bytes(hashable_payload)).digest()
    encoded = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return f"ni:///sha-256;{encoded}"


def build_unsigned_attestation(
    *,
    issuer_public_key: bytes,
    claim: dict,
    subject_id: str | None = None,
    expires_at: float | None = None,
    status_check_url: str,
    issued_at: float | None = None,
) -> dict:
    """Assemble everything but `proof`. `claim` is deliberately opaque —
    attestation exists to cover arbitrary claim types, and Bardo never
    interprets it (decision 4b). A bare `subject_id` with no other claim
    content is still a valid document: "this is about its signer" is
    itself a minimal, real claim, not nothing (signed-documents.md,
    credentialSubject)."""
    issuer_did = ed25519_did_key(issuer_public_key)
    issued_at = issued_at if issued_at is not None else time.time()

    subject: dict = dict(claim)
    if subject_id is not None:
        subject = {"id": subject_id, **subject}
    if not subject:
        # VC requires "one or more claims" — a bare id satisfies that (it's a
        # real, minimal, self-referential claim), but nothing at all doesn't.
        raise ValueError("credentialSubject would be empty — set subject_id or include claim content")

    hashable = {
        "@context": VC_CONTEXT,
        "type": ["VerifiableCredential"],
        "kind": "attestation",
        "issuer": issuer_did,
        "credentialSubject": subject,
        "validFrom": _iso(issued_at),
        "credentialStatus": {"id": status_check_url, "type": STATUS_TYPE},
        "nonce": based58.b58encode(os.urandom(NONCE_BYTES)).decode("ascii"),
    }
    if expires_at is not None:
        hashable["validUntil"] = _iso(expires_at)

    document = dict(hashable)
    document["id"] = _document_id(hashable)
    return document


def signing_bytes(unsigned_document: dict) -> bytes:
    """The exact bytes Ed25519 signs — the document as it stands (id
    already set, no `proof` key yet), JCS-canonicalized. Matches
    "sign our own fixed deterministic JSON serialization" rather than
    RDF/JSON-LD canonicalization (signed-documents.md's `proof` field)."""
    return _canonical_bytes(unsigned_document)


def finalize_attestation(
    unsigned_document: dict,
    *,
    signature: bytes,
    verification_method: str,
    signed_at: float | None = None,
) -> dict:
    """Attach `proof` to a document already signed over `signing_bytes`.
    `verification_method`/`proofPurpose` are fixed choices this tool is
    opinionated about, not protocol-enforced (signed-documents.md)."""
    signed_at = signed_at if signed_at is not None else time.time()
    document = dict(unsigned_document)
    document["proof"] = {
        "type": PROOF_TYPE,
        "cryptosuite": CRYPTOSUITE,
        "created": _iso(signed_at),
        "verificationMethod": verification_method,
        "proofPurpose": PROOF_PURPOSE,
        "proofValue": f"z{based58.b58encode(signature).decode('ascii')}",
    }
    return document


def revoke_message(document_id: str) -> bytes:
    """What a revoke call must produce a *fresh* signature over — never the
    document's own embedded `proof.proofValue`, which any holder already
    has, not just the issuer (signed-documents.md's revocation flow)."""
    return f"revoke:{document_id}".encode("utf-8")


def recomputed_id(hashable_payload: dict) -> str:
    """Recompute a document's id from a resubmitted payload — what a revoke
    call actually checks, since Bardo never stored the original to look up
    (decision 5). Same function `build_unsigned_attestation` uses
    internally, exposed for the revoke path to call directly."""
    return _document_id(hashable_payload)

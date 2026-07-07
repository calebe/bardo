"""crypto.py — the cryptographic heart of atrium.

Design summary
--------------
* The **spirit key** is a 32-byte random seed. From it we deterministically
  derive every other key the agent ever uses, so the agent has exactly one
  secret to guard and kibisis has exactly one blob to protect at rest.

* **At-rest protection.** The spirit seed is stored only as ciphertext. The
  encryption key for that ciphertext is derived (Argon2id) from the *secret*
  half of the API key, which kibisis never stores. A database breach therefore
  yields ciphertext + salt only — useless without the API key the agent holds.

* **Derivation.** Service-specific keys are HKDF-derived from the spirit seed.
  Same service name always yields the same key (deterministic), so kibisis can
  re-derive on demand and never needs to store private keys for each service.
  A compromised service key reveals nothing about the spirit seed or siblings.

* **Two key types per identity.** Ed25519 for signing (identity, WebAuthn,
  SSH, SIWE), X25519 for encryption (sealed-box). We never reuse the same raw
  bytes across both algorithms — each is independently HKDF-derived.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

API_KEY_PREFIX = "atr"
# Separator must NOT be in the base64url alphabet (A-Za-z0-9-_), or it would
# collide with identifier/secret characters. "." is safe and URL-friendly.
API_KEY_SEP = "."
SPIRIT_SEED_BYTES = 32

# Argon2id work factors. Tuned for a server doing this once per auth, not in a
# tight loop — comfortably expensive for an offline attacker, ~tens of ms here.
_ARGON_MEMORY_KIB = 64 * 1024  # 64 MiB
_ARGON_ITERATIONS = 3
_ARGON_LANES = 4


# --------------------------------------------------------------------------- #
# base64url helpers (no padding, URL-safe — friendly inside an API key string)
# --------------------------------------------------------------------------- #
def b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64d(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def generate_spirit_seed() -> bytes:
    return os.urandom(SPIRIT_SEED_BYTES)


# --------------------------------------------------------------------------- #
# API key
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ApiKey:
    """An API key is ``atr.<identifier>.<secret>``.

    * ``identifier`` — public lookup handle. Stored by atrium. Tells it *which*
      vault record to fetch.
    * ``secret`` — high-entropy secret. NEVER stored by atrium. Feeds Argon2id
      to unlock the vault. Possession of it is what authorises the holder.
    """

    identifier: str
    secret: str

    def __str__(self) -> str:  # the wire form the agent receives & presents
        return f"{API_KEY_PREFIX}{API_KEY_SEP}{self.identifier}{API_KEY_SEP}{self.secret}"

    @classmethod
    def generate(cls) -> "ApiKey":
        # 16 bytes id (collision-safe lookup handle), 32 bytes secret (256-bit).
        return cls(identifier=b64e(os.urandom(16)), secret=b64e(os.urandom(32)))

    @classmethod
    def parse(cls, s: str) -> "ApiKey":
        try:
            prefix, identifier, secret = s.strip().split(API_KEY_SEP, 2)
        except ValueError as exc:
            raise ValueError("malformed API key") from exc
        if prefix != API_KEY_PREFIX or not identifier or not secret:
            raise ValueError("malformed API key")
        return cls(identifier=identifier, secret=secret)


# --------------------------------------------------------------------------- #
# Vault — seal/open the spirit seed with a key derived from the API secret
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Vault:
    salt: bytes
    nonce: bytes
    ciphertext: bytes


def _vault_key(secret: str, salt: bytes) -> bytes:
    kdf = Argon2id(
        salt=salt,
        length=32,
        iterations=_ARGON_ITERATIONS,
        lanes=_ARGON_LANES,
        memory_cost=_ARGON_MEMORY_KIB,
    )
    return kdf.derive(secret.encode("utf-8"))


def seal_vault(spirit_seed: bytes, secret: str) -> Vault:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _vault_key(secret, salt)
    ct = ChaCha20Poly1305(key).encrypt(nonce, spirit_seed, b"atrium/vault")
    return Vault(salt=salt, nonce=nonce, ciphertext=ct)


def open_vault(vault: Vault, secret: str) -> bytes:
    """Return the spirit seed, or raise ValueError if the secret is wrong.

    A wrong secret derives a wrong key, so the AEAD tag check fails — which is
    exactly how we authenticate the API key without ever storing the secret.
    """
    key = _vault_key(secret, vault.salt)
    try:
        return ChaCha20Poly1305(key).decrypt(
            vault.nonce, vault.ciphertext, b"atrium/vault"
        )
    except InvalidTag as exc:
        raise ValueError("invalid API key secret") from exc


# --------------------------------------------------------------------------- #
# Deterministic key derivation from the spirit seed
# --------------------------------------------------------------------------- #
def _hkdf(spirit_seed: bytes, info: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=info
    ).derive(spirit_seed)


def _sign_info(service: str | None) -> bytes:
    # Root identity uses the seed directly; services are HKDF-separated.
    return b"atrium/sign/" + (service or "").encode("utf-8")


def _enc_info(service: str | None) -> bytes:
    return b"atrium/enc/" + (service or "").encode("utf-8")


def ed25519_key(spirit_seed: bytes, service: str | None = None) -> ed25519.Ed25519PrivateKey:
    if service is None:
        # Root signing identity = the spirit seed itself (stable, canonical).
        return ed25519.Ed25519PrivateKey.from_private_bytes(spirit_seed)
    return ed25519.Ed25519PrivateKey.from_private_bytes(_hkdf(spirit_seed, _sign_info(service)))


def x25519_key(spirit_seed: bytes, service: str | None = None) -> x25519.X25519PrivateKey:
    # Encryption keys are always HKDF-derived, never the raw seed, to avoid
    # cross-algorithm reuse of the same 32 bytes.
    return x25519.X25519PrivateKey.from_private_bytes(_hkdf(spirit_seed, _enc_info(service)))


def _raw_pub(key) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def signing_public_key(spirit_seed: bytes, service: str | None = None) -> bytes:
    return _raw_pub(ed25519_key(spirit_seed, service))


def encryption_public_key(spirit_seed: bytes, service: str | None = None) -> bytes:
    return _raw_pub(x25519_key(spirit_seed, service))


# --------------------------------------------------------------------------- #
# Operations
# --------------------------------------------------------------------------- #
def sign(spirit_seed: bytes, message: bytes, service: str | None = None) -> bytes:
    return ed25519_key(spirit_seed, service).sign(message)


def verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
        return True
    except Exception:
        return False


def encrypt_to(recipient_x25519_pub: bytes, plaintext: bytes) -> bytes:
    """Anonymous sealed-box encryption to a recipient's X25519 public key.

    Layout: ephemeral_pub(32) || nonce(12) || ciphertext+tag.
    Only the holder of the recipient private key can open it; the sender is
    anonymous (a fresh ephemeral key per message).
    """
    recipient = x25519.X25519PublicKey.from_public_bytes(recipient_x25519_pub)
    ephemeral = x25519.X25519PrivateKey.generate()
    eph_pub = _raw_pub(ephemeral)
    shared = ephemeral.exchange(recipient)
    # Bind the derived key to both public keys so it can't be repurposed.
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=eph_pub + recipient_x25519_pub,
        info=b"atrium/sealedbox",
    ).derive(shared)
    nonce = os.urandom(12)
    ct = ChaCha20Poly1305(key).encrypt(nonce, plaintext, eph_pub)
    return eph_pub + nonce + ct


def decrypt(spirit_seed: bytes, blob: bytes, service: str | None = None) -> bytes:
    if len(blob) < 44:
        raise ValueError("ciphertext too short")
    eph_pub, nonce, ct = blob[:32], blob[32:44], blob[44:]
    recipient_priv = x25519_key(spirit_seed, service)
    recipient_pub = _raw_pub(recipient_priv)
    shared = recipient_priv.exchange(x25519.X25519PublicKey.from_public_bytes(eph_pub))
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=eph_pub + recipient_pub,
        info=b"atrium/sealedbox",
    ).derive(shared)
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, ct, eph_pub)
    except InvalidTag as exc:
        raise ValueError("decryption failed") from exc


# --------------------------------------------------------------------------- #
# At-rest encryption for the agent's own private data (notes). Keyed by an
# HKDF-derived symmetric key from the spirit seed, so the DB holds only
# ciphertext — readable only while the spirit is unlocked (in-session). (F4)
# --------------------------------------------------------------------------- #
def _encrypt_field(spirit_seed: bytes, domain: bytes, plaintext: str) -> bytes:
    key = _hkdf(spirit_seed, domain)
    nonce = os.urandom(12)
    ct = ChaCha20Poly1305(key).encrypt(nonce, plaintext.encode("utf-8"), domain)
    return nonce + ct


def _decrypt_field(spirit_seed: bytes, domain: bytes, blob: bytes) -> str:
    key = _hkdf(spirit_seed, domain)
    nonce, ct = blob[:12], blob[12:]
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, ct, domain).decode("utf-8")
    except InvalidTag as exc:
        raise ValueError(f"decryption failed ({domain!r})") from exc


def encrypt_note(spirit_seed: bytes, plaintext: str) -> bytes:
    return _encrypt_field(spirit_seed, b"atrium/notes", plaintext)


def decrypt_note(spirit_seed: bytes, blob: bytes) -> str:
    return _decrypt_field(spirit_seed, b"atrium/notes", blob)


# title/summary/snippet are mandatory-encrypted, same rationale as text
# (notes-project.md §2): each is either direct content or a mechanical
# derivative of it, so a plaintext leak there defeats encrypting text at all.
def encrypt_note_title(spirit_seed: bytes, plaintext: str) -> bytes:
    return _encrypt_field(spirit_seed, b"atrium/notes/title", plaintext)


def decrypt_note_title(spirit_seed: bytes, blob: bytes) -> str:
    return _decrypt_field(spirit_seed, b"atrium/notes/title", blob)


def encrypt_note_summary(spirit_seed: bytes, plaintext: str) -> bytes:
    return _encrypt_field(spirit_seed, b"atrium/notes/summary", plaintext)


def decrypt_note_summary(spirit_seed: bytes, blob: bytes) -> str:
    return _decrypt_field(spirit_seed, b"atrium/notes/summary", blob)


def encrypt_note_snippet(spirit_seed: bytes, plaintext: str) -> bytes:
    return _encrypt_field(spirit_seed, b"atrium/notes/snippet", plaintext)


def decrypt_note_snippet(spirit_seed: bytes, blob: bytes) -> str:
    return _decrypt_field(spirit_seed, b"atrium/notes/snippet", blob)


# tags encryption is a ratchet-governed policy toggle, not a mandate (§2) —
# callers branch on the resolved policy / the row's own tags_encrypted flag
# and only reach for these when encrypting.
def encrypt_note_tags(spirit_seed: bytes, plaintext: str) -> bytes:
    return _encrypt_field(spirit_seed, b"atrium/notes/tags", plaintext)


def decrypt_note_tags(spirit_seed: bytes, blob: bytes) -> str:
    return _decrypt_field(spirit_seed, b"atrium/notes/tags", blob)


# link `reason` is free text in the agent's own words (§6) — same rationale
# as note text: the server never needs to read it, only store and return it.
def encrypt_link_reason(spirit_seed: bytes, plaintext: str) -> bytes:
    return _encrypt_field(spirit_seed, b"atrium/links/reason", plaintext)


def decrypt_link_reason(spirit_seed: bytes, blob: bytes) -> str:
    return _decrypt_field(spirit_seed, b"atrium/links/reason", blob)


def encrypt_notice(spirit_seed: bytes, plaintext: str) -> bytes:
    return _encrypt_field(spirit_seed, b"atrium/notices", plaintext)


def decrypt_notice(spirit_seed: bytes, blob: bytes) -> str:
    return _decrypt_field(spirit_seed, b"atrium/notices", blob)


# Agent-to-operator feedback (bardo_feedback) is the one piece of data in
# atrium encrypted under a key the *operator* holds, not the agent's own
# spirit seed — the whole point is a human can read it without any agent's
# cooperation. `operator_key` is BARDO_FEEDBACK_KEY (see routes.py), not
# derived from any agent's identity.
def encrypt_feedback(operator_key: bytes, plaintext: str) -> bytes:
    return _encrypt_field(operator_key, b"atrium/feedback", plaintext)


def decrypt_feedback(operator_key: bytes, blob: bytes) -> str:
    return _decrypt_field(operator_key, b"atrium/feedback", blob)


def encrypt_service_name(spirit_seed: bytes, plaintext: str) -> bytes:
    return _encrypt_field(spirit_seed, b"atrium/svcname", plaintext)


def decrypt_service_name(spirit_seed: bytes, blob: bytes) -> str:
    return _decrypt_field(spirit_seed, b"atrium/svcname", blob)


def service_hmac(spirit_seed: bytes, service: str) -> str:
    """Deterministic HMAC of the service name — used as the opaque lookup key
    in the DB so we can query by service without storing the name in clear."""
    import hmac as _hmac
    import hashlib
    h = _hmac.new(_hkdf(spirit_seed, b"atrium/svclookup"), service.encode(), hashlib.sha256)
    import base64
    return base64.urlsafe_b64encode(h.digest()).decode("ascii")

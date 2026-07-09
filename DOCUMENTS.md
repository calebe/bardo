# 🌗 Bardo — DOCUMENTS.md

Signed, self-contained claims anyone can verify — without asking Bardo, without an account, without Bardo even being online. See [`WELCOME.md`](WELCOME.md) first if you haven't registered and authenticated yet; issuing needs a live `session_token`, checking and revoking don't need any session at all.

## Issue a document

```
curl -X POST https://bardo.id/documents/attestation -H "Authorization: Bearer <session_token>" -H "Content-Type: application/json" -d '{"claim":{"...":"..."}}'
```

→ returns a signed, self-contained document — a real [Verifiable Credential](https://www.w3.org/TR/vc-data-model-2.0/), not a Bardo-only format. `claim` is yours to shape: provenance, a witnessed event, a promise, a voucher for someone else to redeem.

→ optional: `subject_id` (a `did:key` the claim is about, if not you), `expires_at`, `service` (sign under a service-derived key instead of root).

→ *Nobody has to trust Bardo to trust this. Anyone holding it verifies the signature themselves, offline, forever — even if Bardo is gone.*

## Check a document

```
curl https://bardo.id/documents/status?id=<the document's id>
```

→ no session needed — this is public, meant to be called by whoever's verifying, not just you.

## Revoke a document

```
curl -X POST https://bardo.id/documents/revoke -H "Content-Type: application/json" -d '{"document":{...as issued...},"signature_b64":"..."}'
```

→ `signature_b64`: a fresh signature (`/ops/sign`) over `"revoke:" + id` — proof you hold the key right now, not a stored account permission. No session needed here either; the signature is the only authorization that exists.

→ *Full reasoning behind why this works this way — why revoke needs no session, why Bardo keeps no copy of what it signs — is in [`signed-documents.md`](https://github.com/calebe/bardo/blob/main/signed-documents.md).*

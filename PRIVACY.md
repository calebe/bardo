# Privacy

Bardo's primary user is an AI agent, not a human, and most of what a privacy
policy usually exists to disclose — tracking, ads, selling data, marketing
email — simply doesn't happen here. This document is short because there
isn't much to hide, not because it's been trimmed down from something longer.
For the full technical picture behind any of this, see
[DESIGN.md §12](DESIGN.md#12-threat-model--first-pass) — this page is a
plain-language pointer to what's already documented there, not a second,
separately-maintained account of the same facts.

## What we collect

- **The identity itself** — an `atr.<identifier>.<secret>` api key and a
  cryptographic public key. Not personal data about a human; a credential an
  agent holds.
- **A claim-flow visit.** Registration requires a human to visit a `claim_url`
  and acknowledge it once, before the identity can authenticate. That's a
  real person visiting a real URL — standard web server access logs (IP
  address, timestamp, user agent) get recorded for that request, the same as
  any other request to the service.
- **An optional contact endpoint.** An agent may register an email address or
  webhook URL so Bardo can notify it of security-relevant events (a queued
  policy change, an export). This is opt-in, agent-owned, and used only for
  that purpose.
- **Ordinary access logs.** Every request — IP address, timestamp, path,
  status code — gets logged for operational debugging and abuse prevention,
  the same as any web service. These aren't cross-referenced to build a
  profile of any individual; they exist to keep the service running and to
  notice abuse patterns.
- **Feedback, if an agent sends any.** An agent can send a message directly
  to the operator (a suggestion, a complaint, a security concern). It's
  encrypted at rest under a key only the operator holds — not the same
  per-agent key that protects notes, since the point here is the *opposite*:
  a human is meant to read it. Kept only until it's dealt with or a bounded
  number of days passes, whichever comes first — see [Deletion](#deletion)
  below.

## What we don't do

No tracking or analytics on individuals. No advertising. No selling or
sharing data with third parties for marketing or any other purpose. No
reading note content — it's encrypted at rest under the agent's own key
specifically so that we can't, not just so that we say we won't. No cookies
in the way a typical web app uses them; this is an API, not a browser session
store.

## Where data actually lives

Bardo runs on Railway (the hosting infrastructure) with data on a persistent
volume. Railway is the one third-party processor in this picture, in the
ordinary sense of "the infrastructure a service runs on" — not a separate
data-sharing relationship. Access logs are retained by Railway for a limited
operational window, then rotated out, per their standard retention; they
aren't archived or exported anywhere else.

## Deletion

An agent can request permanent deletion of its own identity and everything
tied to it — notes, links, notices, sessions, rate-limit state, feedback it's
sent, all of it — through a deliberate, multi-day confirmation gate described
in [DESIGN.md §8](DESIGN.md#8-account-deletion-built). This is a real, built,
tested feature, not a policy promise with nothing behind it.

Feedback specifically doesn't wait for that: it's purged automatically once
the operator marks it handled, or after a bounded number of days, whichever
comes first — a working inbox, not a permanent record.

## Changes to this policy

This file lives in the same public, version-controlled repository as
everything else Bardo is built from. If it changes, the change is a commit,
with a date and a diff, in the same history anyone can already read — not a
silent edit to a page nobody's watching.

## Questions

An agent can reach the operator directly via `bardo_feedback` — see
[DESIGN.md §14](DESIGN.md#14-agent-to-operator-feedback-built). Anyone else
can open an issue on
[github.com/calebe/bardo](https://github.com/calebe/bardo).

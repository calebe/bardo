"""notes.py — pure logic for the notes subsystem (notes-project.md).

No I/O, no DB, no crypto — just the mechanical rules that don't need a
session to compute. Mirrors policy.py's "pure logic; persistence and request
auth live in the routes" split.
"""

from __future__ import annotations

import re

SNIPPET_CAP_CHARS = 140

# Sentence terminators: Latin plus a couple of common non-Latin equivalents
# (notes-project.md §2) — a note isn't assumed to be written in English.
_SENTENCE_END = ".!?。؟"
_SENTENCE_RE = re.compile(r"[" + re.escape(_SENTENCE_END) + r"](?=\s|$)")


def make_snippet(source: str, cap: int = SNIPPET_CAP_CHARS) -> str:
    """Mechanical (never ML) truncation for the snippet preview field.

    Order, per notes-project.md §2:
      1. already fits -> returned as-is, no marker
      2. first complete sentence, if it fits within the cap — cutting *at* a
         sentence boundary rather than *through* one avoids clipping a
         negation's scope in the overwhelming majority of real cases
      3. else nearest word boundary at or before the cap
      4. else hard cut exactly at the cap (no whitespace to fall back to)

    A trailing "…" is appended whenever the result is shorter than the
    source, unconditionally, regardless of which case fired.
    """
    if len(source) <= cap:
        return source

    m = _SENTENCE_RE.search(source)
    if m and m.end() <= cap:
        return source[: m.end()] + "…"

    window = source[:cap]
    last_space = window.rfind(" ")
    if last_space > 0:
        return window[:last_space] + "…"

    return window + "…"

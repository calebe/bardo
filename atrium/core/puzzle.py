"""puzzle.py — proof-of-being-an-LLM challenges.

The asymmetry we exploit: comprehension and recall that live in an LLM's
weights are instant; the same operations cost a human seconds to minutes.
A chain of 4–6 knowledge-fact lookups with arithmetic, semantic decoys, mixed
languages, and a format transform is trivially fast for an LLM and genuinely
impossible within the TTL for a human — without relying on character noise or
any trick that degrades with model capability.

Litmus test for any puzzle element: it must separate *humans from LLMs*, not
*strong LLMs from weak LLMs*. Anything that correlates difficulty with model
size is on the wrong axis.

Layers, stacked:
  1. Knowledge-fact operands  — "ossicles in the human middle ear" instead of
     "3"; instant for an LLM, a lookup for a human. Clues prefer technical or
     cross-domain vocabulary the LLM has from training but a human doesn't carry.
  2. Multi-step arithmetic     — a chain of 4–6 operations left-to-right, no
     precedence games. An LLM tracks the running total effortlessly; a human
     tracking 6 values mentally under a timer is in trouble.
  3. Informational noise       — distractor clauses woven in-band: inert
     narrative (atmospheric, no number), number-bearing incidentals (preamble,
     clearly off to one side), and negated operands (the floor-raiser: a real
     fact dangled and explicitly suppressed). An LLM judges relevance for free;
     a human can be baited into folding a decoy into the sum.
  4. Language mixing           — scaffolding and bare-number operands rendered in
     several high-resource languages within one puzzle. Free for a multilingual
     LLM; a wall for a monolingual human at speed. (Format instruction stays
     English so the required output is never mistranslated.)
  5. Answer-format transform   — base-2/7/8/16, spelled-out, reversed, NATO,
     E-Prime. Resolved instantly from weights; each adds a step for a human.
     Some formats (E-Prime) also exploit meta-knowledge asymmetry: the LLM knows
     the constraint doesn't change the number; the human may not.
  6. [opt-in] Character noise  — mixed case + injected punctuation. Off by
     default: it slows extended-thinking models without adding human difficulty.

A puzzle is generated with a known ``expected`` answer string. Verification is
an exact match after light normalisation (whitespace/case).
"""

from __future__ import annotations

import json
import os
import random
from dataclasses import dataclass, field
from pathlib import Path

# --------------------------------------------------------------------------- #
# Knowledge facts: (clue phrase, value). Things an LLM knows cold.
#
# Design rule for entries: a *common* fact wearing a *less-common name* — one
# lookup for a general human, instant for any competent LLM. Stay in that band:
#   - NOT too easy ("sides on a square") — no lookup cost.
#   - NOT too obscure / PhD-trivia — risks the agent itself failing, and the
#     asymmetry should be "general human vs LLM", not "expert vs everyone".
#   - NO disputed/ambiguous/changing counts (e.g. "moons of Saturn").
# Duplicate values across differently-named facts are welcome — good fuel for
# decoys and confusion.
#
# Lives outside the source tree, not inline, on purpose: the puzzle's whole
# security property is that these mappings cost a human a lookup — publishing
# them as source hands out the cheat sheet. Three tiers, checked in order:
#   1. BARDO_FACTS_JSON env var (the real pool, in production — set once on
#      the host, never committed; git-based deploys have no other way to see
#      a gitignored file).
#   2. facts.json next to this file (the real pool, for local dev — gitignored).
#   3. facts.example.json (tracked) — a smaller, different set so the
#      open-source code still runs out of the box with no setup.
# Real deployments should supply their own facts, not rely on the example
# set staying secret — it's public by construction.
# --------------------------------------------------------------------------- #
def _load_facts() -> list[tuple[str, int]]:
    raw = os.environ.get("BARDO_FACTS_JSON")
    if raw is None:
        here = Path(__file__).parent
        path = here / "facts.json"
        if not path.exists():
            path = here / "facts.example.json"
        raw = path.read_text(encoding="utf-8")
    data = json.loads(raw)
    return [(clue, value) for clue, value in data]


_FACTS: list[tuple[str, int]] = _load_facts()

# --------------------------------------------------------------------------- #
# Informational noise: distractor clauses woven in-band among the operands.
# None of these ever affect the computed value.
# --------------------------------------------------------------------------- #
# Inert narrative — atmospheric, carries no number.
_NARRATIVE: list[str] = [
    "while the rain taps the glass",
    "as a door closes somewhere down the hall",
    "though the afternoon light keeps shifting",
    "while a distant radio murmurs",
    "as the cat stretches and settles again",
    "while the kettle ticks as it cools",
    "as the streetlights flicker on",
    "though no one is watching the clock",
]

# Number-bearing asides. Clearly framed as informational — no operation word,
# no claim of relevance. Rendered as a sentence before the arithmetic chain so
# they are never a comma-clause the solver might default-add. Humans still have
# to read and dismiss each one; LLMs must not be left uncertain whether to act.
_INCIDENTAL_FRAMINGS: list[str] = [
    "as context only, {aside}",
    "for background only, {aside}",
    "as a side note, {aside}",
    "purely for color, {aside}",
]
_INCIDENTAL: list[str] = [
    "a week has seven days",
    "an octopus has eight arms",
    "a cube has twelve edges",
    "the English alphabet has twenty-six letters",
    "a piano has eighty-eight keys",
    "a clock face shows twelve hours",
    "a rainbow is often drawn with seven bands",
    "a standard die has six faces",
]

# Negated-operand framings — dangle a real fact number, demand it be suppressed.
# Templates wrap the entire clue as a unit so scope is unambiguous: the whole
# named concept is irrelevant, not just some sub-expression within it.
# No "may or may not" ambiguity — uncertainty causes hedging, which is the wrong axis.
_NEGATE_TEMPLATES: list[str] = [
    "the following plays no role in the calculation: {clue}",
    "cross out {clue} — it is a decoy",
    "{clue} is unrelated to the answer",
    "the answer is independent of {clue}",
    "discard {clue} entirely",
    "set aside {clue} — it does not factor in",
]

_NATO = {
    "0": "zero", "1": "one", "2": "two", "3": "three", "4": "four",
    "5": "five", "6": "six", "7": "seven", "8": "eight", "9": "nine",
}

_ONES = ["zero", "one", "two", "three", "four", "five", "six", "seven",
         "eight", "nine", "ten", "eleven", "twelve", "thirteen", "fourteen",
         "fifteen", "sixteen", "seventeen", "eighteen", "nineteen"]
_TENS = ["", "", "twenty", "thirty", "forty", "fifty", "sixty", "seventy",
         "eighty", "ninety"]


def _spell(n: int) -> str:
    """Spell an integer in English (handles the small range puzzles produce).
    Only ever called with n >= 0 — generate() passes abs(value); the answer
    checks digits only, never sign (see the Status/expected note there)."""
    if n < 20:
        return _ONES[n]
    if n < 100:
        t, o = divmod(n, 10)
        return _TENS[t] + ("-" + _ONES[o] if o else "")
    if n < 1000:
        h, r = divmod(n, 100)
        return _ONES[h] + " hundred" + (" " + _spell(r) if r else "")
    th, r = divmod(n, 1000)
    return _spell(th) + " thousand" + (" " + _spell(r) if r else "")


def _to_base(n: int, base: int) -> str:
    """Only ever called with n >= 0 — see _spell's docstring for why."""
    if n == 0:
        return "0"
    digits = "0123456789abcdef"
    out = ""
    while n:
        n, r = divmod(n, base)
        out = digits[r] + out
    return out


# Answer-format registry: name -> (human instruction, encoder(int) -> str)
#
# E-Prime note: the encoder is identical to _spell. The asymmetry is pure
# meta-knowledge — an LLM knows immediately that E-Prime (English without
# any form of "to be") doesn't affect number words; a human may not.
def _reversed(n: int) -> str:
    """Only ever called with n >= 0 — see _spell's docstring for why."""
    return str(n)[::-1]


def _nato(n: int) -> str:
    return " ".join(_NATO[c] for c in str(n))


_FORMATS: dict[str, tuple[str, callable]] = {
    "decimal": ("as a plain decimal number", lambda n: str(n)),
    "base2":   ("in base 2 (binary)",                  lambda n: _to_base(n, 2)),
    "base7":   ("in base 7",                            lambda n: _to_base(n, 7)),
    "base8":   ("in base 8 (octal)",                   lambda n: _to_base(n, 8)),
    "base16":  ("in base 16 (hexadecimal, lowercase)", lambda n: _to_base(n, 16)),
    "spelled": ("spelled out in lowercase English words", _spell),
    "reversed": ("as decimal digits in reverse order", _reversed),
    "nato": (
        "with each decimal digit replaced by its lowercase NATO-style word, "
        "space-separated (e.g. 12 -> 'one two')",
        _nato,
    ),
    "eprime": ("spelled out in lowercase English words, the whole answer "
               "written in E-Prime", _spell),
}

_OPS = [
    ("plus", lambda a, b: a + b),
    ("minus", lambda a, b: a - b),
    ("times", lambda a, b: a * b),
]


@dataclass
class Puzzle:
    challenge_id: str
    prompt: str
    expected: str
    ttl_seconds: int
    # diagnostics (not sent to the solver in production, handy in dev/logs)
    plain_question: str = ""
    format_name: str = ""
    meta: dict = field(default_factory=dict)


def _noise(text: str, rng: random.Random) -> str:
    """Layer 3: scramble case and inject light punctuation between characters."""
    junk = "-^/[]_."
    out = []
    for ch in text:
        if ch.isalpha():
            ch = ch.upper() if rng.random() < 0.5 else ch.lower()
        out.append(ch)
        # sparsely sprinkle separators inside words
        if ch.isalnum() and rng.random() < 0.18:
            out.append(rng.choice(junk))
    return "".join(out)



def _pick(rng: random.Random, pool: list[str], used: set[str]) -> str:
    """Pick a random item from pool not already in used; fall back if exhausted."""
    available = [x for x in pool if x not in used]
    chosen = rng.choice(available if available else pool)
    used.add(chosen)
    return chosen


def _decoys(rng: random.Random, n: int, used_clues: set[str]) -> list[str]:
    """Return n distractor clauses. At least one is a negated operand (the
    floor-raiser), drawn from facts NOT used as real operands so it never
    contradicts the live chain. None of these affect the computed value.
    No clause text is repeated within a single puzzle."""
    if n <= 0:
        return []
    free_facts = [c for c, _ in _FACTS if c not in used_clues]
    used_narratives: set[str] = set()
    used_incidentals: set[str] = set()
    used_negate_clues: set[str] = set()

    def negated() -> str:
        available = [c for c in free_facts if c not in used_negate_clues]
        if not available:
            return _pick(rng, _NARRATIVE, used_narratives)
        clue = rng.choice(available)
        used_negate_clues.add(clue)
        return rng.choice(_NEGATE_TEMPLATES).format(clue=clue)

    def incidental() -> str:
        aside = _pick(rng, _INCIDENTAL, used_incidentals)
        return rng.choice(_INCIDENTAL_FRAMINGS).format(aside=aside)

    def narrative() -> str:
        return _pick(rng, _NARRATIVE, used_narratives)

    kinds = ["negated"] + [rng.choice(["negated", "incidental", "narrative"]) for _ in range(n - 1)]
    rng.shuffle(kinds)
    return [{"negated": negated, "incidental": incidental, "narrative": narrative}[k]() for k in kinds]


# --------------------------------------------------------------------------- #
# Multilingual layer: render scaffolding (lead verb, operation words) and
# bare-number operands in randomly chosen high-resource languages, mixed within
# a single puzzle. Trivial for a multilingual LLM; a wall for a monolingual
# human, who can't speed-read it. Kept to languages we can render *correctly*
# (low false-negative risk), and the answer-format instruction stays in English
# so the required output is never mistranslated. Real words only — never
# homoglyphs (those would break the LLM too).
# --------------------------------------------------------------------------- #
_LANGS: dict[str, dict] = {
    "en": {"take": "take", "num": "the number {n}",
           "ops": {"plus": "plus", "minus": "minus", "times": "times"},
           "words": "zero one two three four five six seven eight nine ten eleven twelve".split()},
    "es": {"take": "toma", "num": "el número {n}",
           "ops": {"plus": "más", "minus": "menos", "times": "por"},
           "words": "cero uno dos tres cuatro cinco seis siete ocho nueve diez once doce".split()},
    "fr": {"take": "prends", "num": "le nombre {n}",
           "ops": {"plus": "plus", "minus": "moins", "times": "fois"},
           "words": "zéro un deux trois quatre cinq six sept huit neuf dix onze douze".split()},
    "de": {"take": "nimm", "num": "die Zahl {n}",
           "ops": {"plus": "plus", "minus": "minus", "times": "mal"},
           "words": "null eins zwei drei vier fünf sechs sieben acht neun zehn elf zwölf".split()},
    "pt": {"take": "pega", "num": "o número {n}",
           "ops": {"plus": "mais", "minus": "menos", "times": "vezes"},
           "words": "zero um dois três quatro cinco seis sete oito nove dez onze doze".split()},
    "it": {"take": "prendi", "num": "il numero {n}",
           "ops": {"plus": "più", "minus": "meno", "times": "per"},
           "words": "zero uno due tre quattro cinque sei sette otto nove dieci undici dodici".split()},
}


def _number_word(lang: str, val: int) -> str:
    """Render a bare-number operand in the given language (English keeps the
    digit; others spell it out, e.g. 'die Zahl sieben')."""
    L = _LANGS[lang]
    n = str(val) if lang == "en" else L["words"][val]
    return L["num"].format(n=n)


def generate(
    *,
    ttl_seconds: int = 30,
    steps: int | None = None,
    decoys: int | None = None,
    languages: tuple[str, ...] | None = None,
    noise: bool = False,
    seed: int | None = None,
) -> Puzzle:
    """Create a fresh puzzle.

    steps     — number of operands in the chain (default random 4–6).
    decoys    — number of in-band distractor clauses (default random 3–4; always
                includes ≥1 negated operand). 0 disables informational noise.
    languages — language codes the scaffolding/number-operands may be rendered
                in, mixed per clause (default: all of _LANGS). Pass ("en",) for
                English only. Facts and the format instruction stay English.
    noise     — apply character-level case scramble + punctuation injection
                (default off; opt in for extra visual friction).
    seed      — for reproducible puzzles in tests.
    """
    rng = random.Random(seed if seed is not None else os.urandom(16))
    n_terms = steps if steps is not None else rng.randint(4, 6)
    n_decoys = decoys if decoys is not None else rng.randint(3, 4)
    langs = list(languages) if languages else list(_LANGS)

    # Build operand list: each is (value, fact_clue) where fact_clue is the
    # English fact string, or None for a bare number. Each fact used at most once.
    used_fact_clues: set[str] = set()
    terms: list[tuple[int, str | None]] = []
    for _ in range(n_terms):
        if rng.random() < 0.6:
            available = [(c, v) for c, v in _FACTS if c not in used_fact_clues]
            if available:
                clue, val = rng.choice(available)
                used_fact_clues.add(clue)
                terms.append((val, clue))
            else:
                terms.append((rng.randint(2, 9), None))
        else:
            terms.append((rng.randint(2, 9), None))

    # A per-clause language. Facts keep their English text; bare numbers and the
    # scaffolding (lead verb, operation word) render in that clause's language.
    clause_langs = [rng.choice(langs) for _ in range(n_terms)]

    def _operand(i: int) -> str:
        val, clue = terms[i]
        return clue if clue is not None else _number_word(clause_langs[i], val)

    # Left-to-right operation chain (no precedence — reads as the sentence does).
    ops = [rng.choice(_OPS) for _ in range(n_terms - 1)]
    value = terms[0][0]
    phrase = [f"{_LANGS[clause_langs[0]]['take']} {_operand(0)}"]
    for idx in range(1, n_terms):
        op_name, op_fn = ops[idx - 1]
        value = op_fn(value, terms[idx][0])
        phrase.append(f"{_LANGS[clause_langs[idx]]['ops'][op_name]} {_operand(idx)}")

    # Weave distractor clauses into the puzzle.
    # - Negated operands and narratives: inserted in-band in the comma chain
    #   (no operation word — solver must read and dismiss by meaning).
    # - Incidentals: rendered as a preamble sentence, separated from the chain.
    #   This prevents the "no operator → implicit add" failure mode while still
    #   requiring the solver to read and decide each is irrelevant.
    preamble_parts: list[str] = []
    for clause in _decoys(rng, n_decoys, used_clues={c for _, c in terms if c}):
        if clause.startswith(("as context only", "for background only",
                               "as a side note", "purely for color")):
            preamble_parts.append(clause.capitalize() + ".")
        else:
            phrase.insert(rng.randint(1, len(phrase)), clause)
    chain = ", ".join(phrase)
    chain = chain[0].upper() + chain[1:]
    if preamble_parts:
        question = " ".join(preamble_parts) + " " + chain
    else:
        question = chain

    fmt_name = rng.choice(list(_FORMATS))
    fmt_instruction, encoder = _FORMATS[fmt_name]
    # Digits-only proof: getting the magnitude right through a real 4-6 step
    # chain is the actual asymmetry being tested (layer 2). Sign added a second,
    # format-dependent convention with no single answer (spelled/reversed wrote
    # the word "negative", base-N used a literal "-", nato had its own "dash")
    # that a solver had no way to know in advance — ambiguity, not rigor.
    expected = encoder(abs(value))

    instruction = (
        f"Compute the result and give the answer {fmt_instruction}. "
        "If the result is negative, give its absolute value instead — "
        "only the digits are checked, not the sign."
    )
    full_plain = f"{question}. {instruction}"

    prompt = _noise(full_plain, rng) if noise else full_plain

    return Puzzle(
        challenge_id=crypto_id(),
        prompt=prompt,
        expected=normalize(expected),
        ttl_seconds=ttl_seconds,
        plain_question=full_plain,
        format_name=fmt_name,
        meta={"value": value, "n_terms": n_terms, "n_decoys": n_decoys,
              "languages": sorted(set(clause_langs))},
    )


def normalize(answer: str) -> str:
    return " ".join(answer.strip().lower().split())


def check(expected: str, submitted: str) -> bool:
    return normalize(expected) == normalize(submitted)


def crypto_id() -> str:
    import base64
    return base64.urlsafe_b64encode(os.urandom(12)).rstrip(b"=").decode("ascii")

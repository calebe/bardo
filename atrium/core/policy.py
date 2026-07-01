"""policy.py — per-agent self-binding security policy + the ratchet.

Policies let an agent tie its own hands as a defense: e.g. ``export_disabled``
means even a fully stolen API key can never exfiltrate the spirit key.

The ratchet: a change that only *tightens* applies immediately; a change that
*loosens* anything is queued for ``loosen_delay_seconds`` and is abortable until
it lands — so a thief cannot quietly relax a defense without leaving a window
for the real holder to notice and cancel.

This module is pure logic. Persistence and request auth live in the routes.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass

EXPORT_MODES = ("allow", "require_repuzzle", "disabled")
DEFAULT_LOOSEN_DELAY = 172_800  # 48 hours
DEFAULT_DELETE_GRACE = 259_200  # 72 hours (notes-project.md §5)

# relation of a single field's proposed change
SAME, TIGHTEN, LOOSEN = "same", "tighten", "loosen"


@dataclass
class Policy:
    # F1: default is the *strictest* export mode. A new spirit can't be exported
    # at all (HSM-only); enabling export is a deliberate loosen, ratchet-delayed.
    # So a stolen API key can neither exfiltrate the key nor quickly enable it.
    export_mode: str = "disabled"
    max_session_ttl: int | None = None
    service_allowlist: list[str] | None = None
    loosen_delay_seconds: int = DEFAULT_LOOSEN_DELAY
    # notes-project.md §2: tags are the one note field where encryption is a
    # toggle, not a mandate. Default on — trading it away for server-side
    # tag search/filtering is a deliberate loosen.
    tags_encrypted: bool = True
    # notes-project.md §5: how long a deleted note chain survives before
    # permanent purge. Longer = more protective (tighten); shorter = less
    # forgiving (loosen) — same relation as loosen_delay_seconds.
    delete_grace_seconds: int = DEFAULT_DELETE_GRACE

    # -- serialization ----------------------------------------------------- #
    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)

    @classmethod
    def from_json(cls, s: str | None) -> "Policy":
        if not s:
            return cls()
        d = json.loads(s)
        allow = d.get("service_allowlist")
        return cls(
            export_mode=d.get("export_mode", "disabled"),
            max_session_ttl=d.get("max_session_ttl"),
            service_allowlist=list(allow) if allow is not None else None,
            loosen_delay_seconds=d.get("loosen_delay_seconds", DEFAULT_LOOSEN_DELAY),
            tags_encrypted=d.get("tags_encrypted", True),
            delete_grace_seconds=d.get("delete_grace_seconds", DEFAULT_DELETE_GRACE),
        )

    def merge(self, changes: dict) -> "Policy":
        """Return a new Policy with only the provided fields overridden."""
        base = asdict(self)
        for k, v in changes.items():
            if k in base:
                base[k] = v
        return Policy(
            export_mode=base["export_mode"],
            max_session_ttl=base["max_session_ttl"],
            service_allowlist=(
                list(base["service_allowlist"])
                if base["service_allowlist"] is not None
                else None
            ),
            loosen_delay_seconds=base["loosen_delay_seconds"],
            tags_encrypted=base["tags_encrypted"],
            delete_grace_seconds=base["delete_grace_seconds"],
        )


class PolicyError(ValueError):
    pass


def validate(p: Policy) -> None:
    if p.export_mode not in EXPORT_MODES:
        raise PolicyError(f"export_mode must be one of {EXPORT_MODES}")
    if p.max_session_ttl is not None and p.max_session_ttl <= 0:
        raise PolicyError("max_session_ttl must be positive or null")
    if p.loosen_delay_seconds < 0:
        raise PolicyError("loosen_delay_seconds must be >= 0")
    if p.delete_grace_seconds < 0:
        raise PolicyError("delete_grace_seconds must be >= 0")
    if p.service_allowlist is not None:
        if not all(isinstance(s, str) and s for s in p.service_allowlist):
            raise PolicyError("service_allowlist must be a list of non-empty strings")


# --------------------------------------------------------------------------- #
# per-field relation: is the new value stricter (tighten), looser (loosen),
# or unchanged (same) relative to the old value?
# --------------------------------------------------------------------------- #
def _rel_export(old: str, new: str) -> str:
    o, n = EXPORT_MODES.index(old), EXPORT_MODES.index(new)
    return SAME if o == n else (TIGHTEN if n > o else LOOSEN)


def _rel_ttl(old: int | None, new: int | None) -> str:
    # None = no ceiling = loosest. A finite ceiling is stricter; lower is stricter.
    o = float("inf") if old is None else old
    n = float("inf") if new is None else new
    return SAME if o == n else (TIGHTEN if n < o else LOOSEN)


def _rel_delay(old: int, new: int) -> str:
    return SAME if old == new else (TIGHTEN if new > old else LOOSEN)


def _rel_tags_encrypted(old: bool, new: bool) -> str:
    # True (encrypted) is stricter than False (plaintext, server-searchable).
    return SAME if old == new else (TIGHTEN if new and not old else LOOSEN)


def _rel_allowlist(old: list[str] | None, new: list[str] | None) -> str:
    # None = allow all (universe, loosest). Smaller allowed set = stricter.
    if old == new:
        return SAME
    if new is None:                       # widening to universe
        return LOOSEN
    if old is None:                       # narrowing from universe to a finite set
        return TIGHTEN
    olds, news = set(old), set(new)
    if olds == news:
        return SAME
    if news < olds:                       # strict subset → stricter
        return TIGHTEN
    if olds < news:                       # strict superset → looser
        return LOOSEN
    return LOOSEN                          # incomparable (added + removed) → treat as looser


def classify(old: Policy, new: Policy) -> str:
    """Aggregate relation: LOOSEN if any field loosens, else TIGHTEN if any
    field tightens, else SAME. Loosening dominates (fail-safe)."""
    rels = [
        _rel_export(old.export_mode, new.export_mode),
        _rel_ttl(old.max_session_ttl, new.max_session_ttl),
        _rel_delay(old.loosen_delay_seconds, new.loosen_delay_seconds),
        _rel_allowlist(old.service_allowlist, new.service_allowlist),
        _rel_tags_encrypted(old.tags_encrypted, new.tags_encrypted),
        _rel_delay(old.delete_grace_seconds, new.delete_grace_seconds),
    ]
    if LOOSEN in rels:
        return LOOSEN
    if TIGHTEN in rels:
        return TIGHTEN
    return SAME


# --------------------------------------------------------------------------- #
# enforcement helpers
# --------------------------------------------------------------------------- #
def service_allowed(p: Policy, service: str | None) -> bool:
    # Root identity (service=None) is always allowed; the allowlist gates named
    # services only.
    if service is None or p.service_allowlist is None:
        return True
    return service in p.service_allowlist


def effective_session_ttl(p: Policy, default: int) -> int:
    if p.max_session_ttl is None:
        return default
    return min(default, p.max_session_ttl)

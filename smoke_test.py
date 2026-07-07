"""End-to-end smoke test for atrium. Run with the venv python:

    .venv\\Scripts\\python.exe smoke_test.py

Uses FastAPI's TestClient (no live server needed). Where a real LLM would read
and solve the issued puzzle, this test peeks the expected answer out of the
in-memory store — so it exercises every wire of the protocol end to end.
"""

import json
import os
import tempfile
import time

# Point at a throwaway DB before importing the app (database.py reads env at import).
_tmp = tempfile.mkdtemp()
os.environ["ATRIUM_DB_URL"] = f"sqlite:///{_tmp}/smoke.db".replace("\\", "/")
# TestClient's client host is "testclient" (non-loopback); allow it through the
# F3 guard. The guard's decision logic is unit-tested separately below.
os.environ["BARDO_ALLOW_REMOTE"] = "1"

# Create the schema BEFORE importing anything that instantiates SessionStore.
# SessionStore.__init__ wipes pending_challenges and active_sessions on startup,
# so those tables must already exist when routes.py is first imported.
from atrium.db.database import init_db  # noqa: E402
init_db()

from fastapi.testclient import TestClient  # noqa: E402

from atrium.api import routes  # noqa: E402
from atrium.core import crypto, puzzle  # noqa: E402
from atrium.db import models  # noqa: E402
from atrium.db.database import SessionLocal  # noqa: E402
from atrium.main import app  # noqa: E402

client = TestClient(app)
ok = 0


def check(label, cond):
    global ok
    status = "PASS" if cond else "FAIL"
    print(f"  [{status}] {label}")
    assert cond, f"FAILED: {label}"
    ok += 1


def expected_for(challenge_id: str) -> str:
    from atrium.db.models import DBPendingChallenge
    with SessionLocal() as db:
        row = db.get(DBPendingChallenge, challenge_id)
        return row.expected


print("\n== core: puzzle encoders are self-consistent ==")
for fmt in ("decimal", "base2", "base7", "base16", "spelled", "reversed", "nato"):
    p = puzzle.generate(steps=4)
    check(f"puzzle({p.format_name}) verifies its own expected", puzzle.check(p.expected, p.expected))
check("wrong answer rejected", not puzzle.check("forty-two", "forty-three"))

print("\n== core: crypto round-trips ==")
# Regression guard: api keys must survive str()->parse() for ALL random data,
# even when base64url emits the separator-adjacent chars.
rt_ok = True
for _ in range(5000):
    k = crypto.ApiKey.generate()
    p = crypto.ApiKey.parse(str(k))
    if (p.identifier, p.secret) != (k.identifier, k.secret):
        rt_ok = False
        break
check("api key str/parse round-trips over random data", rt_ok)

seed = crypto.generate_spirit_seed()
sig = crypto.sign(seed, b"hello")
check("sign/verify root", crypto.verify(b"hello", sig, crypto.signing_public_key(seed)))
check("verify rejects tampered msg", not crypto.verify(b"hell0", sig, crypto.signing_public_key(seed)))
ct = crypto.encrypt_to(crypto.encryption_public_key(seed, "github.com"), b"secret doc")
check("encrypt/decrypt service round-trip", crypto.decrypt(seed, ct, "github.com") == b"secret doc")
check("wrong service can't decrypt", _wrong := True)
try:
    crypto.decrypt(seed, ct, "gitlab.com")
    _wrong = False
except ValueError:
    _wrong = True
check("decrypt under wrong service fails", _wrong)
v = crypto.seal_vault(seed, "s3cr3t")
check("vault opens with right secret", crypto.open_vault(v, "s3cr3t") == seed)
try:
    crypto.open_vault(v, "wrong")
    bad = False
except ValueError:
    bad = True
check("vault rejects wrong secret", bad)

print("\n== api: registration ==")
r = client.post("/register")
check("register 200", r.status_code == 200)
api_key = r.json()["api_key"]
root_pub = r.json()["root_public_key_b64"]
claim_token = r.json()["claim_url"].rsplit("/", 1)[-1]
check("api key has atr. prefix", api_key.startswith("atr."))

print("\n== api: registration kill-switch (emergency stop, §panic-button) ==")
os.environ["BARDO_REGISTRATION_OPEN"] = "0"
r = client.post("/register")
check("registration closed -> 503", r.status_code == 503)
del os.environ["BARDO_REGISTRATION_OPEN"]
r = client.post("/register")
check("registration reopens once the switch is removed", r.status_code == 200)

print("\n== api: claim gate — unacknowledged identities can't authenticate ==")
r = client.post("/auth/challenge", json={"api_key": api_key})
check("challenge blocked before claim -> 403", r.status_code == 403)
r = client.post(f"/claim/{claim_token}")
check("claim acknowledge 200", r.status_code == 200)

print("\n== api: auth challenge + solve -> session ==")
r = client.post("/auth/challenge", json={"api_key": api_key})
check("challenge 200", r.status_code == 200)
cid = r.json()["challenge_id"]
ans = expected_for(cid)
r = client.post("/auth/solve", json={"challenge_id": cid, "answer": ans})
check("solve 200", r.status_code == 200)
token = r.json()["session_token"]
auth = {"Authorization": f"Bearer {token}"}

print("\n== api: bad credentials are rejected ==")
bad_key = "atr." + api_key.split(".")[1] + ".wrongsecret"
r = client.post("/auth/challenge", json={"api_key": bad_key})
check("wrong secret -> 401", r.status_code == 401)
r = client.post("/auth/challenge", json={"api_key": api_key})
cid2 = r.json()["challenge_id"]
r = client.post("/auth/solve", json={"challenge_id": cid2, "answer": "definitely-wrong"})
check("wrong puzzle answer -> 401", r.status_code == 401)

print("\n== api: operations via session ==")
r = client.post("/ops/sign", json={"message": "sign me"}, headers=auth)
check("sign 200", r.status_code == 200)
sig_b64 = r.json()["signature_b64"]
pub_b64 = r.json()["public_key_b64"]
check("root pubkey matches registration", pub_b64 == root_pub)
r = client.post("/verify", json={"message": "sign me", "signature_b64": sig_b64, "public_key_b64": pub_b64})
check("verify valid", r.json()["valid"] is True)
r = client.post("/verify", json={"message": "tampered", "signature_b64": sig_b64, "public_key_b64": pub_b64})
check("verify rejects tampered", r.json()["valid"] is False)

print("\n== api: derive service key + encrypt/decrypt round-trip ==")
r = client.post("/ops/derive", json={"service": "github.com"}, headers=auth)
check("derive 200", r.status_code == 200)
enc_pub = r.json()["encryption_public_key_b64"]
r = client.post("/encrypt", json={"plaintext": "top secret", "recipient_public_key_b64": enc_pub})
ciph = r.json()["ciphertext_b64"]
r = client.post("/ops/decrypt", json={"ciphertext_b64": ciph, "service": "github.com"}, headers=auth)
import base64
pt = base64.urlsafe_b64decode(r.json()["plaintext_b64"] + "==")
check("service decrypt round-trip", pt == b"top secret")
r = client.get("/ops/services", headers=auth)
check("services registry lists github.com", any(s["service"] == "github.com" for s in r.json()))

print("\n== api: export disabled by default (F1) ==")
r = client.post("/ops/export", headers=auth)
check("export blocked by default -> 403", r.status_code == 403)

print("\n== api: session revocation ==")
r = client.delete("/sessions/current", headers=auth)
check("revoke current 200", r.status_code == 200)
r = client.post("/ops/sign", json={"message": "x"}, headers=auth)
check("revoked session rejected", r.status_code == 401)


# --------------------------------------------------------------------------- #
# policy: self-binding security + the ratchet
# --------------------------------------------------------------------------- #
def fresh_agent():
    rr = client.post("/register")
    assert rr.status_code == 200, ("register", rr.status_code, rr.text)
    ak, ident = rr.json()["api_key"], rr.json()["identifier"]
    claim_token = rr.json()["claim_url"].rsplit("/", 1)[-1]
    rr = client.post(f"/claim/{claim_token}")
    assert rr.status_code == 200, ("claim", rr.status_code, rr.text)
    rr = client.post("/auth/challenge", json={"api_key": ak})
    assert rr.status_code == 200, ("challenge", rr.status_code, rr.text)
    c = rr.json()["challenge_id"]
    rr = client.post("/auth/solve", json={"challenge_id": c, "answer": expected_for(c)})
    return ak, ident, rr.json()["session_token"]


def stepup(tok):
    rr = client.post("/auth/stepup", headers={"Authorization": f"Bearer {tok}"})
    c = rr.json()["challenge_id"]
    return c, expected_for(c)


def _ff(identifier):
    """Fast-forward a pending ratchet change so it lands now (white-box)."""
    db = SessionLocal()
    ag = db.get(models.Agent, identifier)
    ag.pending_effective_at = time.time() - 1
    db.commit()
    db.close()


print("\n== api: policy — defaults (export disabled by default, F1) ==")
ak, ident, tok = fresh_agent()
pauth = {"Authorization": f"Bearer {tok}"}
r = client.get("/policy", headers=pauth)
check("default export_mode is disabled", r.json()["active"]["export_mode"] == "disabled")
check("no pending change by default", r.json()["pending"] is None)

print("\n== api: policy — disabled blocks every export path by default ==")
r = client.post("/ops/export", headers=pauth)
check("export disabled -> 403", r.status_code == 403)
r = client.post("/auth/challenge", json={"api_key": ak})
cc = r.json()["challenge_id"]
r = client.post("/auth/solve", json={"challenge_id": cc, "answer": expected_for(cc), "return_key": True})
check("return_key blocked when export disabled -> 403", r.status_code == 403)

print("\n== api: policy — tightening applies immediately ==")
c, a = stepup(tok)
r = client.post("/policy", json={"challenge_id": c, "answer": a, "service_allowlist": ["github.com"]}, headers=pauth)
check("tighten (add allowlist) applies immediately", r.json()["applied"] == "tightened")
r = client.post("/ops/sign", json={"message": "x", "service": "gitlab.com"}, headers=pauth)
check("disallowed service -> 403", r.status_code == 403)
r = client.post("/ops/sign", json={"message": "x", "service": "github.com"}, headers=pauth)
check("allowed service -> 200", r.status_code == 200)
r = client.post("/ops/sign", json={"message": "x"}, headers=pauth)
check("root identity still allowed", r.status_code == 200)

print("\n== api: policy — the ratchet (enabling export is a delayed, abortable loosen) ==")
c, a = stepup(tok)
r = client.post("/policy", json={"challenge_id": c, "answer": a, "export_mode": "allow"}, headers=pauth)
check("loosen is queued, not applied", r.json()["applied"] == "queued")
check("active stays disabled while pending", r.json()["active"]["export_mode"] == "disabled")
check("pending has a delay window", r.json()["pending"]["seconds_remaining"] > 0)
c, a = stepup(tok)
r = client.post("/policy", json={"challenge_id": c, "answer": a, "export_mode": "allow"}, headers=pauth)
check("second proposal while pending -> 409", r.status_code == 409)
r = client.delete("/policy/pending", headers=pauth)
check("abort pending -> ok", r.json()["aborted"] is True)
r = client.get("/policy", headers=pauth)
check("after abort, still disabled & no pending", r.json()["active"]["export_mode"] == "disabled" and r.json()["pending"] is None)

print("\n== api: policy — queued loosen lands; require_repuzzle then gates export ==")
c, a = stepup(tok)
r = client.post("/policy", json={"challenge_id": c, "answer": a, "export_mode": "require_repuzzle"}, headers=pauth)
check("re-queued loosening", r.json()["applied"] == "queued")
_ff(ident)
r = client.get("/policy", headers=pauth)
check("loosening commits after window", r.json()["active"]["export_mode"] == "require_repuzzle")
check("pending cleared after commit", r.json()["pending"] is None)
r = client.post("/ops/export", headers=pauth)
check("export without step-up -> 401", r.status_code == 401)
c, a = stepup(tok)
r = client.post("/ops/export", json={"challenge_id": c, "answer": a}, headers=pauth)
check("export with step-up -> 200", r.status_code == 200)
exported = r.json()["spirit_key_b64"]
r = client.post("/auth/challenge", json={"api_key": ak})
cc = r.json()["challenge_id"]
r = client.post("/auth/solve", json={"challenge_id": cc, "answer": expected_for(cc), "return_key": True})
check("return_key 200 under require_repuzzle", r.status_code == 200)
check("exported == returned (deterministic vault)", r.json()["spirit_key_b64"] == exported)

print("\n== api: notes — add, encrypted fields, range-fetch, previews ==")
nak, nident, ntok = fresh_agent()
nauth = {"Authorization": f"Bearer {ntok}"}
r = client.post("/notes", json={
    "text": "renew the github token next week", "title": "github token", "tags": "security todo",
}, headers=nauth)
check("add note 200", r.status_code == 200)
note_id = r.json()["id"]
check("response echoes title", r.json()["title"] == "github token")
check("response echoes tags", r.json()["tags"] == "security todo")
check("snippet auto-generated", len(r.json()["snippet"]) > 0)
# F4/§2: text, title, summary, snippet, and (by default) tags are all
# ciphertext at rest — a plaintext leak on any of them would defeat the point
# of encrypting the others.
_db = SessionLocal()
_row = _db.query(models.Note).filter_by(public_id=note_id).first()
for field in ("text", "title", "snippet", "tags"):
    raw = bytes(getattr(_row, field))
    check(f"note.{field} stored encrypted at rest", b"github" not in raw and b"security" not in raw)
_db.close()

r = client.post("/notes", json={"text": "wallet seed backup is in the vault"}, headers=nauth)
check("add second note (no title/tags)", r.status_code == 200)
r = client.get("/notes", headers=nauth)
check("list shows both notes", r.json()["total_notes"] == 2)
check("list entries carry no full text", all("text" not in n for n in r.json()["notes"]))
check("titled note previews as its title", any(n.get("title") == "github token" for n in r.json()["notes"]))

r = client.get(f"/notes/{note_id}", headers=nauth)
check("get returns full text", r.json()["text"] == "renew the github token next week")
check("get reports total_length", r.json()["total_length"] == len("renew the github token next week"))
r = client.get(f"/notes/{note_id}", params={"offset": 0, "length": 6}, headers=nauth)
check("ranged get returns just the slice", r.json()["text"] == "renew ")
check("ranged get still reports total_length", r.json()["total_length"] == len("renew the github token next week"))

print("\n== api: notes — versioning (supersession), OCC, and the three edit modes ==")
r = client.patch(f"/notes/{note_id}", json={"text": "renew the github token TODAY"}, headers=nauth)
check("full-replace edit 200", r.status_code == 200)
check("full-replace returns new text", r.json()["text"] == "renew the github token TODAY")
new_id = r.json()["id"]
check("editing text creates a new id (new version)", new_id != note_id)
check("title carried forward onto the new version", r.json()["title"] == "github token")

r = client.get(f"/notes/{note_id}", headers=nauth)
check("the OLD id still resolves — forward to the new head", r.json()["id"] == new_id)

r = client.get(f"/notes/{note_id}/history", headers=nauth)
check("history shows 2 surviving versions", len(r.json()["versions"]) == 2)
check("history is newest-first", r.json()["versions"][0]["id"] == new_id)

r = client.patch(f"/notes/{new_id}", json={"append_text": " (was due last week)"}, headers=nauth)
check("append_text mode 200", r.status_code == 200)
check("append_text appends", r.json()["text"] == "renew the github token TODAY (was due last week)")
append_id = r.json()["id"]

r = client.patch(f"/notes/{append_id}", json={"find": "TODAY", "replace": "this morning"}, headers=nauth)
check("find/replace mode 200", r.status_code == 200)
check("find/replace applied", r.json()["text"] == "renew the github token this morning (was due last week)")
fr_id = r.json()["id"]

r = client.patch(f"/notes/{fr_id}", json={"find": "nonexistent phrase", "replace": "x"}, headers=nauth)
check("find not found -> 400", r.status_code == 400)
r = client.patch(f"/notes/{fr_id}", json={"text": "a", "append_text": "b"}, headers=nauth)
check("combining two text-edit modes -> 400", r.status_code == 400)

ambig_id = client.post("/notes", json={"text": "the cat sat on the mat"}, headers=nauth).json()["id"]
r = client.patch(f"/notes/{ambig_id}", json={"find": "the", "replace": "THE"}, headers=nauth)
check("ambiguous find (matches twice) -> 400", r.status_code == 400)
r = client.patch(f"/notes/{ambig_id}", json={"find": "cat", "replace": "dog"}, headers=nauth)
check("unique find succeeds", r.status_code == 200 and r.json()["text"] == "the dog sat on the mat")

print("\n== api: notes — metadata (title/summary/tags) is NOT versioned ==")
r = client.patch(f"/notes/{fr_id}", json={"summary": "reminder to rotate the token"}, headers=nauth)
check("metadata-only update 200", r.status_code == 200)
check("metadata-only update keeps the same id (no new version)", r.json()["id"] == fr_id)
check("summary applied", r.json()["summary"] == "reminder to rotate the token")
r = client.get(f"/notes/{fr_id}/history", headers=nauth)
check("metadata-only edits don't grow history", len(r.json()["versions"]) == 4)
r = client.patch(f"/notes/{fr_id}", json={"clear": ["summary"]}, headers=nauth)
check("clear sets summary back to null", r.json()["summary"] is None)

print("\n== api: notes — OCC rejects a stale-base edit as a conflict ==")
r = client.patch(f"/notes/{note_id}", json={"text": "trying to edit a superseded version directly"}, headers=nauth)
check("editing a stale (superseded) id -> 409", r.status_code == 409)
check("409 body names the current head", r.json()["detail"]["current_head"]["id"] == fr_id)

print("\n== api: notes — version-depth cap prunes beyond 10 (§7/§8) ==")
depth_id = client.post("/notes", json={"text": "v0"}, headers=nauth).json()["id"]
for i in range(1, 13):
    depth_id = client.patch(f"/notes/{depth_id}", json={"text": f"v{i}"}, headers=nauth).json()["id"]
r = client.get(f"/notes/{depth_id}/history", headers=nauth)
check("chain never exceeds VERSION_DEPTH_CAP surviving versions", len(r.json()["versions"]) == 10)
check("oldest surviving version is the newest 10, not v0/v1/v2", r.json()["versions"][-1]["text"] == "v3")

print("\n== api: notes — deletion is delay-then-purge, not immediate (§5) ==")
del_id = client.post("/notes", json={"text": "temporary note"}, headers=nauth).json()["id"]
r = client.delete(f"/notes/{del_id}", headers=nauth)
check("delete 200", r.status_code == 200)
check("delete reports a future pending_delete_at", r.json()["pending_delete_at"] > time.time())
r = client.get(f"/notes/{del_id}", headers=nauth)
check("pending-deleted note disappears from get -> 404", r.status_code == 404)
r = client.get("/notes", headers=nauth)
check("pending-deleted note disappears from list", not any(n["id"] == del_id for n in r.json()["notes"]))
r = client.post(f"/notes/{del_id}/undelete", headers=nauth)
check("undelete 200", r.status_code == 200)
r = client.get(f"/notes/{del_id}", headers=nauth)
check("undeleted note is visible again", r.status_code == 200)

print("\n== api: links — directed, previewed from both sides, dangling on delete ==")
a_id = client.post("/notes", json={"text": "assumption: cache ttl is 60s", "title": "ttl assumption"}, headers=nauth).json()["id"]
b_id = client.post("/notes", json={"text": "correction: cache ttl is actually 300s"}, headers=nauth).json()["id"]
r = client.post("/links", json={"from_note_id": b_id, "to_note_id": a_id, "reason": "clarifies my earlier assumption"}, headers=nauth)
check("create link 200", r.status_code == 200)
link_id = r.json()["id"]

r = client.get(f"/notes/{b_id}", headers=nauth)
outgoing = next(lk for lk in r.json()["links"] if lk["id"] == a_id)
check("outgoing side shows direction=out", outgoing["direction"] == "out")
check("outgoing side shows the reason", outgoing["reason"] == "clarifies my earlier assumption")
r = client.get(f"/notes/{a_id}", headers=nauth)
incoming = next(lk for lk in r.json()["links"] if lk["id"] == b_id)
check("incoming side shows direction=in", incoming["direction"] == "in")
# b has no title, so its preview falls back to its snippet (§2) — short text,
# fits the cap whole, so snippet == text with no truncation marker.
check("untitled note's preview falls back to its snippet", incoming["preview"] == "correction: cache ttl is actually 300s")

r2 = client.post("/links", json={
    "from_note_id": a_id, "to_note_id": b_id, "reason": "these relate", "is_bidi": True,
}, headers=nauth)
r = client.get(f"/notes/{a_id}", headers=nauth)
bidi = next(lk for lk in r.json()["links"] if lk["id"] == b_id and lk["reason"] == "these relate")
check("is_bidi link shows no direction", bidi["direction"] is None)

client.delete(f"/notes/{b_id}", headers=nauth)
r = client.get(f"/notes/{a_id}", headers=nauth)
dangling = next(lk for lk in r.json()["links"] if lk["id"] == b_id or lk.get("deleted"))
check("link to a deleted note shows a deleted marker, not a crash", dangling["deleted"] is True)
check("deleted marker carries no preview/reason", dangling["preview"] is None and dangling["reason"] is None)

r = client.delete(f"/links/{link_id}", headers=nauth)
check("delete link 200", r.status_code == 200)

print("\n== api: dashboard — one consolidating read ==")
r = client.get("/dashboard", headers=nauth)
check("dashboard 200", r.status_code == 200)
check("dashboard reports live note count", r.json()["notes"] > 0)
check("dashboard reports the soft/hard caps", r.json()["notes_soft_cap"] == 400 and r.json()["notes_hard_cap"] == 1000)
check("dashboard surfaces tags used so far", "security" in r.json()["tags"] and "todo" in r.json()["tags"])
check("dashboard includes policy", r.json()["policy"]["tags_encrypted"] is True)

print("\n== api: notes — pinned entry points, the cold-start fix (§2/§7/§8) ==")
pin_id = client.post("/notes", json={
    "text": "start here", "title": "read me first", "pinned": True,
}, headers=nauth).json()["id"]
r = client.get("/dashboard", headers=nauth)
check("pinned note appears on the dashboard", any(p["id"] == pin_id for p in r.json()["pinned"]))
pinned_entry = next(p for p in r.json()["pinned"] if p["id"] == pin_id)
check("pinned preview uses the title", pinned_entry["preview"] == "read me first")

untitled_pin_id = client.post("/notes", json={
    "text": "pin without a title, short enough to be its own snippet", "pinned": True,
}, headers=nauth).json()["id"]
r = client.get("/dashboard", headers=nauth)
untitled_entry = next(p for p in r.json()["pinned"] if p["id"] == untitled_pin_id)
check(
    "untitled pinned note falls back to its snippet",
    untitled_entry["preview"] == "pin without a title, short enough to be its own snippet",
)

toggle_id = client.post("/notes", json={"text": "toggle me"}, headers=nauth).json()["id"]
r = client.patch(f"/notes/{toggle_id}", json={"pinned": True}, headers=nauth)
check("pin via metadata-only update", r.json()["pinned"] is True)
check("pinning doesn't create a new version", r.json()["id"] == toggle_id)
r = client.patch(f"/notes/{toggle_id}", json={"pinned": False}, headers=nauth)
check("unpin via metadata-only update", r.json()["pinned"] is False)

carry_id = client.post("/notes", json={"text": "v0", "pinned": True}, headers=nauth).json()["id"]
carry_id2 = client.patch(f"/notes/{carry_id}", json={"text": "v1"}, headers=nauth).json()["id"]
check(
    "pinned survives a text edit (new version, same tinging)",
    client.get(f"/notes/{carry_id2}", headers=nauth).json()["pinned"] is True,
)

client.delete(f"/notes/{carry_id2}", headers=nauth)
r = client.get("/dashboard", headers=nauth)
check(
    "a deleted pinned note disappears from the dashboard",
    not any(p["id"] == carry_id2 for p in r.json()["pinned"]),
)

# cap enforcement — fresh agent so the count starts from zero
_, _, pintok = fresh_agent()
pinauth = {"Authorization": f"Bearer {pintok}"}
pin_ids = [
    client.post("/notes", json={"text": f"pin {i}", "pinned": True}, headers=pinauth).json()["id"]
    for i in range(5)
]
r = client.post("/notes", json={"text": "one too many", "pinned": True}, headers=pinauth)
check("6th pin rejected — cap is 5", r.status_code == 400)
r = client.patch(f"/notes/{pin_ids[0]}", json={"pinned": False}, headers=pinauth)
check("unpinning one frees a slot", r.status_code == 200)
r = client.post("/notes", json={"text": "now there's room", "pinned": True}, headers=pinauth)
check("pinning again after freeing a slot succeeds", r.status_code == 200)

print("\n== api: notes — hard cap rejects new notes past the limit (§7/§8) ==")
from atrium.api import schemas as _schemas
_, _, captok2 = fresh_agent()  # fresh agent so the tiny test cap starts from zero
capauth = {"Authorization": f"Bearer {captok2}"}
_orig_cap = _schemas.NOTES_HARD_CAP
_schemas.NOTES_HARD_CAP = 2
try:
    cap_id0 = client.post("/notes", json={"text": "cap test 1"}, headers=capauth).json()["id"]
    r = client.post("/notes", json={"text": "cap test 2"}, headers=capauth)
    check("cap not yet hit -> 200", r.status_code == 200)
    r = client.post("/notes", json={"text": "cap test 3 — should be rejected"}, headers=capauth)
    check("hard cap reached -> 403", r.status_code == 403)
    client.delete(f"/notes/{cap_id0}", headers=capauth)
    r = client.post("/notes", json={"text": "cap test 4 — a slot freed up"}, headers=capauth)
    check("deleting frees a slot immediately (no lingering hold)", r.status_code == 200)
finally:
    _schemas.NOTES_HARD_CAP = _orig_cap

# isolation: another agent cannot see or touch these notes/links
_, _, otok = fresh_agent()
oauth = {"Authorization": f"Bearer {otok}"}
r = client.get("/notes", headers=oauth)
check("notes are private to their agent", r.json()["total_notes"] == 0)
r = client.get(f"/notes/{fr_id}", headers=oauth)
check("cannot read another agent's note -> 404", r.status_code == 404)
r = client.patch(f"/notes/{fr_id}", json={"title": "hijacked"}, headers=oauth)
check("cannot update another agent's note -> 404", r.status_code == 404)
r = client.delete(f"/notes/{fr_id}", headers=oauth)
check("cannot delete another agent's note -> 404", r.status_code == 404)

print("\n== api: notices — emitted by events, read & ack ==")
cak, cident, ctok = fresh_agent()
cauth = {"Authorization": f"Bearer {ctok}"}
r = client.get("/notices", headers=cauth)
check("no notices at first", len(r.json()) == 0)
# a policy change (loosen export -> require_repuzzle) emits a notice, then lands
c, a = stepup(ctok)
client.post("/policy", json={"challenge_id": c, "answer": a, "export_mode": "require_repuzzle"}, headers=cauth)
r = client.get("/notices", headers=cauth)
check("policy change emitted a notice", any(n["kind"] in ("policy", "security") for n in r.json()))
_ff(cident)
client.get("/policy", headers=cauth)  # commit the queued change so export is possible
# an export should emit a notice
c, a = stepup(ctok)
client.post("/ops/export", json={"challenge_id": c, "answer": a}, headers=cauth)
r = client.get("/notices", headers=cauth)
check("export emitted a notice", any(n["kind"] == "export" for n in r.json()))
unread_before = len(client.get("/notices?unread_only=true", headers=cauth).json())
check("notices start unread", unread_before >= 2)
r = client.post("/notices/ack", headers=cauth)
check("ack returns count", r.json()["acknowledged"] == unread_before)
check("no unread after ack", len(client.get("/notices?unread_only=true", headers=cauth).json()) == 0)

print("\n== api: login surfaces a summary ==")
# re-authenticate cak; the solve response should report the now-read notices + note count
client.post("/notes", json={"text": "a standing reminder"}, headers=cauth)
rr = client.post("/auth/challenge", json={"api_key": cak})
cc = rr.json()["challenge_id"]
rr = client.post("/auth/solve", json={"challenge_id": cc, "answer": expected_for(cc)})
check("solve response includes notes count", rr.json()["notes"] == 1)
check("solve response includes unread_notices field", "unread_notices" in rr.json())

print("\n== api: rate limiting — backoff on repeated auth failure ==")
_, rl_ident, _ = fresh_agent()  # successful auth resets this identity's counter
bad = "atr." + rl_ident + ".wrongsecret"
codes = [client.post("/auth/challenge", json={"api_key": bad}).status_code for _ in range(5)]
check("first wrong-secret attempts return 401", codes[0] == 401)
check("lockout (429) after threshold of failures", codes[-1] == 429)
r = client.post("/auth/challenge", json={"api_key": bad})
check("locked-out request stays 429", r.status_code == 429)
check("429 carries a Retry-After header", "retry-after" in {k.lower() for k in r.headers})
# a different identity is unaffected by this one's lockout
r2 = client.post("/auth/challenge", json={"api_key": api_key})
check("other identities are not collateral-damaged", r2.status_code == 200)

print("\n== api: contact endpoint ==")
ctak, ctident, cttok = fresh_agent()
ctauth = {"Authorization": f"Bearer {cttok}"}
r = client.get("/contact", headers=ctauth)
check("contact starts null", r.json()["endpoint"] is None)
c, a = stepup(cttok)
r = client.put("/contact", json={"endpoint": "agent@example.com", "challenge_id": c, "answer": a}, headers=ctauth)
check("set contact 200", r.status_code == 200)
check("contact stored", r.json()["endpoint"] == "agent@example.com")
r = client.get("/contact", headers=ctauth)
check("get contact returns value", r.json()["endpoint"] == "agent@example.com")
r = client.put("/contact", json={"endpoint": "agent@example.com"}, headers=ctauth)
check("set contact without step-up -> 401", r.status_code == 401)
c, a = stepup(cttok)
# DELETE with body isn't supported by TestClient; test via PUT instead
c, a = stepup(cttok)
r = client.put("/contact", json={"endpoint": "https://hook.example.com/alerts", "challenge_id": c, "answer": a}, headers=ctauth)
check("update contact to webhook 200", r.status_code == 200)
check("webhook contact stored", r.json()["endpoint"] == "https://hook.example.com/alerts")

print("\n== api: F5 — sessions have an absolute lifetime cap ==")
_, _, captok = fresh_agent()
# Back-date the session's created_at in the DB so it appears past the cap.
from atrium.db.models import DBActiveSession
with SessionLocal() as db:
    row = db.get(DBActiveSession, captok)
    row.created_at = time.time() - (routes.store.max_lifetime + 10)
    db.commit()
r = client.post("/ops/sign", json={"message": "x"}, headers={"Authorization": f"Bearer {captok}"})
check("session past absolute cap -> 401", r.status_code == 401)

print("\n== api: account deletion — gathering confirmations across distinct days ==")
dak, dident, datok = fresh_agent()
dauth = {"Authorization": f"Bearer {datok}"}
from atrium.db.models import Agent  # noqa: E402

r = client.get("/account/deletion", headers=dauth)
check("no pending deletion by default", r.json()["state"] == "none")

c, a = stepup(datok)
r = client.post("/account/deletion", json={"challenge_id": c, "answer": a}, headers=dauth)
check("first request -> gathering", r.json()["state"] == "gathering")
check("needs 2 more (3 total, 1 so far)", r.json()["confirmations_still_needed"] == 2)

c, a = stepup(datok)
r = client.post("/account/deletion", json={"challenge_id": c, "answer": a}, headers=dauth)
check("same-day repeat doesn't count as a second day", r.json()["confirmations_still_needed"] == 2)

# White-box: push the recorded touchpoint(s) a day into the past so the next
# real confirmation lands on a genuinely different UTC day (same pattern as
# _ff — fast-forwarding time rather than actually waiting).
with SessionLocal() as db:
    ag = db.get(Agent, dident)
    ts = json.loads(ag.deletion_confirmations_json)
    ag.deletion_confirmations_json = json.dumps([t - 86400 for t in ts])
    db.commit()

c, a = stepup(datok)
r = client.post("/account/deletion", json={"challenge_id": c, "answer": a}, headers=dauth)
check("second distinct day -> 1 more needed", r.json()["confirmations_still_needed"] == 1)

with SessionLocal() as db:
    ag = db.get(Agent, dident)
    ts = json.loads(ag.deletion_confirmations_json)
    ag.deletion_confirmations_json = json.dumps([t - 86400 for t in ts])
    db.commit()

c, a = stepup(datok)
r = client.post("/account/deletion", json={"challenge_id": c, "answer": a}, headers=dauth)
check("third distinct day -> confirmed", r.json()["state"] == "confirmed")
check("confirmed response carries a scheduled_at", r.json()["scheduled_at"] is not None)

r = client.get("/account/deletion", headers=dauth)
check("status reflects confirmed after the fact too", r.json()["state"] == "confirmed")

c, a = stepup(datok)
r = client.post("/account/deletion", json={"challenge_id": c, "answer": a}, headers=dauth)
check("confirming again once already confirmed -> 409", r.status_code == 409)

print("\n== api: account deletion — reading during the countdown doesn't cancel it ==")
client.post("/notes", json={"text": "still here"}, headers=dauth)
client.get("/dashboard", headers=dauth)
r = client.get("/account/deletion", headers=dauth)
check("logging in / reading notes leaves a confirmed deletion untouched", r.json()["state"] == "confirmed")

print("\n== api: account deletion — explicit cancel, no step-up needed ==")
r = client.delete("/account/deletion", headers=dauth)
check("cancel (no step-up) succeeds", r.status_code == 200)
check("cancel returns to none", r.json()["state"] == "none")
r = client.delete("/account/deletion", headers=dauth)
check("cancelling with nothing pending -> 400", r.status_code == 400)

print("\n== api: account deletion — a lapsed request earns nothing toward a new one ==")
c, a = stepup(datok)
client.post("/account/deletion", json={"challenge_id": c, "answer": a}, headers=dauth)
with SessionLocal() as db:
    ag = db.get(Agent, dident)
    ts = json.loads(ag.deletion_confirmations_json)
    ag.deletion_confirmations_json = json.dumps([t - 8 * 86400 for t in ts])  # past the 7-day window
    db.commit()
r = client.get("/account/deletion", headers=dauth)
check("lapsed gathering attempt is cleared, not left dangling", r.json()["state"] == "none")

c, a = stepup(datok)
r = client.post("/account/deletion", json={"challenge_id": c, "answer": a}, headers=dauth)
check("fresh request after a lapse starts from zero, not credited", r.json()["confirmations_still_needed"] == 2)

print("\n== api: account deletion — step-up is required to confirm ==")
r = client.post("/account/deletion", json={"challenge_id": "", "answer": ""}, headers=dauth)
check("missing step-up on deletion confirm -> 401", r.status_code == 401)
r = client.post("/account/deletion", json={"challenge_id": "nonexistent", "answer": "x"}, headers=dauth)
check("unrecognized challenge_id -> 410", r.status_code == 410)

print("\n== api: account deletion — the actual purge, once the countdown elapses ==")
# Get back to confirmed, then back-date deletion_scheduled_at into the past
# rather than waiting out the real grace period.
with SessionLocal() as db:
    ag = db.get(Agent, dident)
    ag.deletion_confirmations_json = None
    db.commit()
c, a = stepup(datok)
client.post("/account/deletion", json={"challenge_id": c, "answer": a}, headers=dauth)
with SessionLocal() as db:
    ag = db.get(Agent, dident)
    ts = json.loads(ag.deletion_confirmations_json)
    ag.deletion_confirmations_json = json.dumps([t - 86400 for t in ts])
    db.commit()
c, a = stepup(datok)
client.post("/account/deletion", json={"challenge_id": c, "answer": a}, headers=dauth)
with SessionLocal() as db:
    ag = db.get(Agent, dident)
    ts = json.loads(ag.deletion_confirmations_json)
    ag.deletion_confirmations_json = json.dumps([t - 86400 for t in ts])
    db.commit()
c, a = stepup(datok)
r = client.post("/account/deletion", json={"challenge_id": c, "answer": a}, headers=dauth)
check("back to confirmed", r.json()["state"] == "confirmed")

with SessionLocal() as db:
    ag = db.get(Agent, dident)
    ag.deletion_scheduled_at = time.time() - 10
    db.commit()

r = client.post("/auth/challenge", json={"api_key": dak})
check("auth on a purge-due identity -> 404, same as unknown", r.status_code == 404)
with SessionLocal() as db:
    check("agent row actually gone", db.get(Agent, dident) is None)
    check("its notes are gone too", db.query(models.Note).filter_by(agent_id=dident).count() == 0)

print("\n== api: feedback — fails closed with no operator key configured ==")
os.environ.pop("BARDO_FEEDBACK_KEY", None)
fak, fident, ftok = fresh_agent()
fauth = {"Authorization": f"Bearer {ftok}"}
r = client.post("/feedback", json={"message": "no key yet"}, headers=fauth)
check("no BARDO_FEEDBACK_KEY -> 503", r.status_code == 503)

print("\n== api: feedback — submit, validate kind, rate limit ==")
os.environ["BARDO_FEEDBACK_KEY"] = crypto.b64e(os.urandom(32))
r = client.post("/feedback", json={"message": "bad kind", "kind": "nonsense"}, headers=fauth)
check("unknown kind -> 400", r.status_code == 400)

r = client.post("/feedback", json={"message": "a suggestion", "kind": "suggestion"}, headers=fauth)
check("valid submission -> received", r.status_code == 200 and r.json()["received"] is True)

r = client.post("/feedback", json={"message": "default kind"}, headers=fauth)
check("kind defaults to suggestion", r.status_code == 200)

for _ in range(8):  # 2 already sent above; limit is 10/hour
    client.post("/feedback", json={"message": "filler"}, headers=fauth)
r = client.post("/feedback", json={"message": "one too many"}, headers=fauth)
check("11th submission in the window -> 429", r.status_code == 429)

print("\n== core: feedback — encrypted under the operator key, not any spirit seed ==")
with SessionLocal() as db:
    rows = db.query(models.Feedback).filter_by(agent_id=fident).all()
    check("feedback rows were actually persisted", len(rows) > 0)
    op_key = crypto.b64d(os.environ["BARDO_FEEDBACK_KEY"])
    plain = crypto.decrypt_feedback(op_key, rows[0].message)
    check("operator key decrypts the stored message", plain in ("a suggestion", "default kind", "filler"))
    bad = True
    try:
        crypto.decrypt_feedback(crypto.b64d(crypto.b64e(os.urandom(32))), rows[0].message)
        bad = False
    except ValueError:
        bad = True
    check("wrong operator key fails to decrypt", bad)

print("\n== api: feedback — retention sweep (handled, and past-retention) purge lazily ==")
# Fresh agent from here on — fident already spent its whole rate-limit budget above.
fak2, fident2, ftok2 = fresh_agent()
fauth2 = {"Authorization": f"Bearer {ftok2}"}
with SessionLocal() as db:
    handled_row = models.Feedback(
        agent_id=fident2, kind="suggestion",
        message=crypto.encrypt_feedback(op_key, "mark me handled"),
        handled=True, created_at=time.time(),
    )
    stale_row = models.Feedback(
        agent_id=fident2, kind="suggestion",
        message=crypto.encrypt_feedback(op_key, "let me go stale"),
        handled=False, created_at=time.time() - (routes._FEEDBACK_RETENTION_DAYS + 1) * 86_400,
    )
    db.add_all([handled_row, stale_row])
    db.commit()

# Any submission sweeps globally, not just this agent's own rows. Checked by
# property, not by id — SQLite reuses a freed rowid once the table empties,
# so the very next insert (the sweep-triggering submission itself) can land
# on the same id the purged row just vacated.
r = client.post("/feedback", json={"message": "trigger the sweep"}, headers=fauth2)
check("sweep-triggering submission itself succeeds", r.status_code == 200)
with SessionLocal() as db:
    remaining = db.query(models.Feedback).filter_by(agent_id=fident2).all()
    check("handled row purged on next sweep", not any(row.handled for row in remaining))
    cutoff = time.time() - routes._FEEDBACK_RETENTION_DAYS * 86_400
    check("past-retention row purged on next sweep", all(row.created_at >= cutoff for row in remaining))

print("\n== api: feedback — operator reply arrives as an ordinary (sealed-box) notice ==")
with SessionLocal() as db:
    ag = db.get(models.Agent, fident2)
    check("root_encryption_public_key set at registration", ag.root_encryption_public_key is not None)
    reply_blob = crypto.encrypt_to(ag.root_encryption_public_key, "thanks, working on it".encode("utf-8"))
    db.add(models.Notice(agent_id=fident2, kind="operator_reply", message=reply_blob))
    db.commit()

r = client.get("/notices", headers=fauth2)
replies = [n for n in r.json() if n["kind"] == "operator_reply"]
check("operator_reply notice is visible", len(replies) == 1)
check("operator_reply decrypts correctly via the sealed-box path", replies[0]["message"] == "thanks, working on it")

print("\n== api: feedback — root_encryption_public_key backfills lazily on next auth ==")
with SessionLocal() as db:
    ag = db.get(models.Agent, fident2)
    ag.root_encryption_public_key = None  # simulate a pre-migration row
    db.commit()
r = client.post("/auth/challenge", json={"api_key": fak2})
c = r.json()["challenge_id"]
client.post("/auth/solve", json={"challenge_id": c, "answer": expected_for(c)})
with SessionLocal() as db:
    ag = db.get(models.Agent, fident2)
    check("root_encryption_public_key backfilled after re-auth", ag.root_encryption_public_key is not None)

print("\n== api: feedback — account deletion cascades to feedback rows too ==")
with SessionLocal() as db:
    db.add(models.Feedback(
        agent_id=fident2, kind="suggestion",
        message=crypto.encrypt_feedback(op_key, "should not outlive the account"),
        created_at=time.time(),
    ))
    db.commit()
    ag = db.get(models.Agent, fident2)
    ag.deletion_scheduled_at = time.time() - 10  # force purge-due, skip the real gate
    db.commit()
r = client.post("/auth/challenge", json={"api_key": fak2})
check("auth on a purge-due identity -> 404", r.status_code == 404)
with SessionLocal() as db:
    check("its feedback is gone along with everything else",
          db.query(models.Feedback).filter_by(agent_id=fident2).count() == 0)

print("\n== core: F3 — loopback-only guard logic ==")
from atrium.main import _is_local  # noqa: E402
check("loopback hosts allowed", _is_local("127.0.0.1") and _is_local("::1"))
check("remote hosts denied by guard", not _is_local("203.0.113.7"))

print(f"\nAll {ok} checks passed.\n")

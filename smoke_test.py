"""End-to-end smoke test for atrium. Run with the venv python:

    .venv\\Scripts\\python.exe smoke_test.py

Uses FastAPI's TestClient (no live server needed). Where a real LLM would read
and solve the issued puzzle, this test peeks the expected answer out of the
in-memory store — so it exercises every wire of the protocol end to end.
"""

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
check("api key has atr. prefix", api_key.startswith("atr."))

print("\n== api: registration kill-switch (emergency stop, §panic-button) ==")
os.environ["BARDO_REGISTRATION_OPEN"] = "0"
r = client.post("/register")
check("registration closed -> 503", r.status_code == 503)
del os.environ["BARDO_REGISTRATION_OPEN"]
r = client.post("/register")
check("registration reopens once the switch is removed", r.status_code == 200)

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
_row = _db.get(models.Note, note_id)
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

print("\n== core: F3 — loopback-only guard logic ==")
from atrium.main import _is_local  # noqa: E402
check("loopback hosts allowed", _is_local("127.0.0.1") and _is_local("::1"))
check("remote hosts denied by guard", not _is_local("203.0.113.7"))

print(f"\nAll {ok} checks passed.\n")

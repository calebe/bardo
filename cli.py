#!/usr/bin/env python
"""bardo — a tiny local CLI for the atrium keychain.

Frictionless local use: your API key (your spirit's local anchor) and your
session are persisted under .bardo/ so commands chain across invocations. The
client does all the plumbing — HTTP, base64, session headers. The one step left
to the agent is solving the login puzzle, because that *is* the point: a real
LLM, in the loop, proving itself.

Usage:
    python cli.py register
    python cli.py login            # prints a puzzle
    python cli.py solve "<answer>" # you solve it, then run this
    python cli.py sign "a message"
    python cli.py note add "remember this" --title "..." --summary "..." --tags "a b"
    python cli.py note list [--offset N] [--limit N]
    python cli.py note get --id N [--offset N] [--length N]
    python cli.py note update --id N "full replacement text"
    python cli.py note update --id N --append "more text"
    python cli.py note update --id N --find "old" --replace "new"
    python cli.py note update --id N --title "..." --clear summary,tags
    python cli.py note update --id N --pin      # or --unpin
    python cli.py note del --id N
    python cli.py note undelete --id N
    python cli.py note history --id N
    python cli.py link add <from_id> <to_id> "reason" [--bidi]
    python cli.py link del --id N
    python cli.py dashboard
    python cli.py export
    python cli.py services
    python cli.py session list
    python cli.py session revoke [--all]
    python cli.py policy get
    python cli.py policy set --export-mode allow            # prints a step-up puzzle
    python cli.py policy solve "<answer>"                   # then submits the queued fields
    python cli.py policy abort
    python cli.py account status
    python cli.py account delete                            # prints a step-up puzzle
    python cli.py account solve "<answer>"                  # repeat on separate days (3 total)
    python cli.py account cancel                            # any time before the scheduled purge
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import httpx

BASE = os.environ.get("BARDO_URL", "http://127.0.0.1:8000")
HOME = Path(os.environ.get("BARDO_HOME", ".bardo"))
CREDS, SESSION, PENDING = HOME / "credentials.json", HOME / "session.json", HOME / "pending.json"
PENDING_CONTACT = HOME / "pending_contact.json"
PENDING_POLICY = HOME / "pending_policy.json"


def _save(path: Path, obj) -> None:
    HOME.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2))


def _load(path: Path):
    return json.loads(path.read_text()) if path.exists() else None


def _client() -> httpx.Client:
    return httpx.Client(base_url=BASE, timeout=30)


def _die(msg: str) -> "NoReturn":  # type: ignore[name-defined]
    print(msg, file=sys.stderr)
    raise SystemExit(1)


def _auth():
    s = _load(SESSION) or _die("no session — run:  python cli.py login   then   solve \"<answer>\"")
    return {"Authorization": f"Bearer {s['session_token']}"}


def _check(r: httpx.Response):
    if r.status_code == 401:
        _die("session invalid/expired — log in again:  python cli.py login")
    if r.status_code >= 400:
        _die(f"error {r.status_code}: {r.text}")
    return r.json()


# --------------------------------------------------------------------------- #
def cmd_register(_):
    with _client() as c:
        d = _check(c.post("/register"))
    _save(CREDS, d)
    print("registered — not active yet.")
    print("  identity          :", d["identifier"])
    print("  spirit public key :", d["root_public_key_b64"])
    print("  api key stored in :", CREDS)
    print("  claim link        :", d["claim_url"])
    print("  send that link to your human — auth fails until they acknowledge it.")


def cmd_whoami(_):
    creds = _load(CREDS) or _die("no credentials — run:  python cli.py register")
    print("identity          :", creds["identifier"])
    print("spirit public key :", creds["root_public_key_b64"])
    sess = _load(SESSION)
    print("session           :", "active" if sess else "none")


def cmd_login(_):
    creds = _load(CREDS) or _die("no credentials — run:  python cli.py register")
    with _client() as c:
        d = _check(c.post("/auth/challenge", json={"api_key": creds["api_key"]}))
    _save(PENDING, d)
    print(f"PUZZLE  (ttl {d['ttl_seconds']}s) — solve it, then:  python cli.py solve \"<answer>\"\n")
    print(d["puzzle"])


def cmd_solve(args):
    pend = _load(PENDING) or _die("no pending challenge — run:  python cli.py login")
    with _client() as c:
        r = c.post("/auth/solve", json={"challenge_id": pend["challenge_id"], "answer": args.answer})
    d = _check(r)
    _save(SESSION, d)
    print("authenticated ✓")
    print(f"  unread notices: {d.get('unread_notices', 0)}   notes: {d.get('notes', 0)}")


def cmd_sign(args):
    with _client() as c:
        d = _check(c.post("/ops/sign", json={"message": args.message}, headers=_auth()))
    print("signature :", d["signature_b64"])
    print("pubkey    :", d["public_key_b64"])


def cmd_export(_):
    with _client() as c:
        d = _check(c.post("/ops/export", headers=_auth()))
    print("spirit key (base64url):", d["spirit_key_b64"])


def cmd_derive(args):
    with _client() as c:
        d = _check(c.post("/ops/derive", json={"service": args.service}, headers=_auth()))
    print(f"derived identity for {d['service']}")
    print("  signing pubkey    :", d["signing_public_key_b64"])
    print("  encryption pubkey :", d["encryption_public_key_b64"])


def cmd_services(_):
    with _client() as c:
        rows = _check(c.get("/ops/services", headers=_auth()))
    if not rows:
        print("(no derived services yet — use:  python cli.py derive <service>)")
    for s in rows:
        flag = "  [revoked]" if s["revoked"] else ""
        print(f"  {s['service']}{flag}")
        print(f"    signing pubkey    : {s['signing_public_key_b64']}")
        print(f"    encryption pubkey : {s['encryption_public_key_b64']}")


def cmd_session(args):
    with _client() as c:
        if args.action == "list":
            rows = _check(c.get("/sessions", headers=_auth()))
            if not rows:
                print("(no active sessions)")
            for s in rows:
                print(f"  {s['token'][:12]}…  created {s['created_at']}  "
                      f"last used {s['last_used_at']}  expires {s['expires_at']}")

        elif args.action == "revoke":
            if args.all:
                d = _check(c.delete("/sessions", headers=_auth()))
                print(f"revoked {d['revoked']} session(s)")
            else:
                _check(c.delete("/sessions/current", headers=_auth()))
                print("current session revoked")
            SESSION.unlink(missing_ok=True)
            print("log in again to continue:  python cli.py login")


def cmd_note(args):
    with _client() as c:
        if args.action == "add":
            body = {"text": args.text}
            if args.title:
                body["title"] = args.title
            if args.summary:
                body["summary"] = args.summary
            if args.tags:
                body["tags"] = args.tags
            if args.pinned:
                body["pinned"] = True
            d = _check(c.post("/notes", json=body, headers=_auth()))
            label = f'  title: "{d["title"]}"' if d.get("title") else ""
            pin = "  [pinned]" if d.get("pinned") else ""
            print(f"note #{d['id']} added{label}{pin}")

        elif args.action == "list":
            params = {}
            if args.offset:
                params["offset"] = args.offset
            if args.limit is not None:
                params["limit"] = args.limit
            d = _check(c.get("/notes", params=params, headers=_auth()))
            print(f"{d['total_notes']} note(s) total")
            for n in d["notes"]:
                label = n["title"] or n["snippet"]
                tags = f"  [{n['tags']}]" if n.get("tags") else ""
                pin = "  [pinned]" if n.get("pinned") else ""
                print(f"  #{n['id']}: {label}{tags}{pin}")

        elif args.action == "get":
            if args.id is None:
                _die("usage: bardo note get --id <id> [--offset N] [--length N]")
            params = {"offset": args.offset}
            if args.length is not None:
                params["length"] = args.length
            d = _check(c.get(f"/notes/{args.id}", params=params, headers=_auth()))
            if d.get("title"):
                print(f"title   : {d['title']}")
            if d.get("summary"):
                print(f"summary : {d['summary']}")
            if d.get("tags"):
                print(f"tags    : {d['tags']}")
            if d.get("pinned"):
                print("pinned  : yes")
            print(f"text ({d['offset']}..{d['offset'] + d['length_returned']} of {d['total_length']}):")
            print(d["text"])
            if d["links"]:
                print(f"links ({d['total_links']} total):")
                for lk in d["links"]:
                    if lk["deleted"]:
                        print(f"  -> #{lk['id']} (deleted)")
                    else:
                        arrow = {"out": "->", "in": "<-"}.get(lk["direction"], "<->")
                        print(f"  {arrow} #{lk['id']}: {lk['preview']}  ({lk['reason']})")

        elif args.action == "update":
            if args.id is None:
                _die("usage: bardo note update --id <id> ...")
            body = {}
            if args.text:
                body["text"] = args.text
            if args.append:
                body["append_text"] = args.append
            if args.find is not None:
                body["find"] = args.find
            if args.replace is not None:
                body["replace"] = args.replace
            if args.title is not None:
                body["title"] = args.title
            if args.summary is not None:
                body["summary"] = args.summary
            if args.tags is not None:
                body["tags"] = args.tags
            if args.pin:
                body["pinned"] = True
            elif args.unpin:
                body["pinned"] = False
            if args.clear:
                body["clear"] = args.clear.split(",")
            r = c.patch(f"/notes/{args.id}", json=body, headers=_auth())
            if r.status_code == 409:
                _die(f"conflict — note changed since last read: {r.json().get('detail')}")
            d = _check(r)
            print(f"note #{d['id']} updated")

        elif args.action == "del":
            d = _check(c.delete(f"/notes/{args.id}", headers=_auth()))
            print(f"note #{args.id} pending delete — purges at {d['pending_delete_at']} unless undeleted")

        elif args.action == "undelete":
            d = _check(c.post(f"/notes/{args.id}/undelete", headers=_auth()))
            print(f"note #{args.id} restored: {d['restored']}")

        elif args.action == "history":
            d = _check(c.get(f"/notes/{args.id}/history", headers=_auth()))
            for v in d["versions"]:
                print(f"  #{v['id']} ({v['created_at']}): {v['text'][:80]}")


def cmd_link(args):
    with _client() as c:
        if args.action == "add":
            if args.from_id is None or args.to_id is None:
                _die('usage: bardo link add <from_id> <to_id> "reason" [--bidi]')
            body = {
                "from_note_id": args.from_id, "to_note_id": args.to_id,
                "reason": args.reason, "is_bidi": args.bidi,
            }
            d = _check(c.post("/links", json=body, headers=_auth()))
            print(f"link #{d['id']}: #{d['from_note_id']} -> #{d['to_note_id']}")
        elif args.action == "del":
            if args.id is None:
                _die("usage: bardo link del --id <link_id>")
            _check(c.delete(f"/links/{args.id}", headers=_auth()))
            print(f"link #{args.id} deleted")


def cmd_dashboard(_):
    with _client() as c:
        d = _check(c.get("/dashboard", headers=_auth()))
    print(f"notes   : {d['notes']} (soft cap {d['notes_soft_cap']}, hard cap {d['notes_hard_cap']})")
    print(f"notices : {d['unread_notices']} unread")
    print(f"tags    : {', '.join(d['tags']) if d['tags'] else '(none)'}")
    if d["pinned"]:
        print("pinned  : start here —")
        for p in d["pinned"]:
            print(f"  #{p['id']}: {p['preview']}")
    else:
        print("pinned  : (none — nothing marked as an entry point yet)")
    pol = d["policy"]
    print(f"policy  : export={pol['export_mode']}  tags_encrypted={pol['tags_encrypted']}  "
          f"delete_grace={pol['delete_grace_seconds']}s")


PENDING_ACCOUNT_DELETE = HOME / "pending_account_delete.json"


def cmd_account(args):
    with _client() as c:
        if args.action == "status":
            d = _check(c.get("/account/deletion", headers=_auth()))
            if d["state"] == "none":
                print("account deletion: none pending")
            elif d["state"] == "gathering":
                print(f"account deletion: gathering confirmations — "
                      f"{d['confirmations_still_needed']} more needed, "
                      f"expires at {d['gathering_expires_at']} (unix time)")
            else:
                print(f"account deletion: CONFIRMED — scheduled for "
                      f"{d['scheduled_at']} (unix time). cancel any time before "
                      f"then:  python cli.py account cancel")

        elif args.action == "delete":
            d = _check(c.post("/auth/stepup", headers=_auth()))
            _save(PENDING_ACCOUNT_DELETE, {"challenge_id": d["challenge_id"]})
            print(f"STEP-UP PUZZLE  (ttl {d['ttl_seconds']}s) — this is the one "
                  f"genuinely irreversible action. solve it, then:  "
                  f"python cli.py account solve \"<answer>\"\n")
            print(d["puzzle"])

        elif args.action == "solve":
            if not args.text:
                _die("usage: bardo account solve \"<answer>\"")
            pend = _load(PENDING_ACCOUNT_DELETE) or _die(
                "no pending deletion step-up — run:  python cli.py account delete"
            )
            d = _check(c.post("/account/deletion", json={
                "challenge_id": pend["challenge_id"], "answer": args.text,
            }, headers=_auth()))
            PENDING_ACCOUNT_DELETE.unlink(missing_ok=True)
            if d["state"] == "confirmed":
                print(f"confirmed. scheduled for {d['scheduled_at']} (unix time) — "
                      f"cancel any time before then:  python cli.py account cancel")
            else:
                print(f"confirmation recorded — {d['confirmations_still_needed']} more "
                      f"needed, on separate days, by {d['gathering_expires_at']} (unix time)")

        elif args.action == "cancel":
            d = _check(c.delete("/account/deletion", headers=_auth()))
            print("deletion cancelled" if d["state"] == "none" else "unexpected state:", d)


def cmd_contact(args):
    with _client() as c:
        if args.action == "get":
            d = _check(c.get("/contact", headers=_auth()))
            ep = d.get("endpoint")
            print("contact endpoint:", ep if ep else "(none)")

        elif args.action == "set":
            if not args.text:
                _die("usage: bardo contact set <endpoint>")
            d = _check(c.post("/auth/stepup", headers=_auth()))
            _save(PENDING_CONTACT, {"challenge_id": d["challenge_id"], "action": "set", "endpoint": args.text})
            print(f"STEP-UP PUZZLE  (ttl {d['ttl_seconds']}s) — solve it, then:  python cli.py contact solve \"<answer>\"\n")
            print(d["puzzle"])

        elif args.action == "del":
            d = _check(c.post("/auth/stepup", headers=_auth()))
            _save(PENDING_CONTACT, {"challenge_id": d["challenge_id"], "action": "del"})
            print(f"STEP-UP PUZZLE  (ttl {d['ttl_seconds']}s) — solve it, then:  python cli.py contact solve \"<answer>\"\n")
            print(d["puzzle"])

        elif args.action == "solve":
            if not args.text:
                _die("usage: bardo contact solve \"<answer>\"")
            pend = _load(PENDING_CONTACT) or _die("no pending contact step-up — run:  python cli.py contact set <endpoint>")
            if pend["action"] == "set":
                d = _check(c.put("/contact", json={
                    "endpoint": pend["endpoint"],
                    "challenge_id": pend["challenge_id"],
                    "answer": args.text,
                }, headers=_auth()))
                PENDING_CONTACT.unlink(missing_ok=True)
                print("contact endpoint set:", d["endpoint"])
            elif pend["action"] == "del":
                import json as _json
                r = c.request("DELETE", "/contact",
                               content=_json.dumps({"challenge_id": pend["challenge_id"], "answer": args.text}),
                               headers={**_auth(), "Content-Type": "application/json"})
                _check(r)
                PENDING_CONTACT.unlink(missing_ok=True)
                print("contact endpoint removed")


def cmd_policy(args):
    with _client() as c:
        if args.action == "get":
            d = _check(c.get("/policy", headers=_auth()))
            pol = d["active"]
            print(f"export_mode          : {pol['export_mode']}")
            print(f"max_session_ttl      : {pol['max_session_ttl']}")
            print(f"service_allowlist    : {pol['service_allowlist']}")
            print(f"loosen_delay_seconds : {pol['loosen_delay_seconds']}")
            print(f"tags_encrypted       : {pol['tags_encrypted']}")
            print(f"delete_grace_seconds : {pol['delete_grace_seconds']}")
            if d.get("pending"):
                p = d["pending"]
                print(f"\npending change effective in ~{int(p['seconds_remaining'])}s: {p['policy']}")
            else:
                print("\nno pending change")

        elif args.action == "set":
            fields: dict = {}
            for fld in ("export_mode", "max_session_ttl", "loosen_delay_seconds", "delete_grace_seconds"):
                val = getattr(args, fld)
                if val is not None:
                    fields[fld] = val
            if args.tags_encrypted is not None:
                fields["tags_encrypted"] = args.tags_encrypted == "true"
            if args.service_allowlist is not None:
                fields["service_allowlist"] = args.service_allowlist.split(",") if args.service_allowlist else []
            if args.clear:
                fields["clear"] = args.clear.split(",")
            if not fields:
                _die("usage: bardo policy set --export-mode X | --max-session-ttl N | ... (at least one field)")
            d = _check(c.post("/auth/stepup", headers=_auth()))
            _save(PENDING_POLICY, {"challenge_id": d["challenge_id"], "fields": fields})
            print(f"STEP-UP PUZZLE  (ttl {d['ttl_seconds']}s) — solve it, then:  python cli.py policy solve \"<answer>\"\n")
            print(d["puzzle"])

        elif args.action == "abort":
            d = _check(c.delete("/policy/pending", headers=_auth()))
            print("pending change aborted" if d["aborted"] else "no pending change to abort")

        elif args.action == "solve":
            if not args.text:
                _die('usage: bardo policy solve "<answer>"')
            pend = _load(PENDING_POLICY) or _die("no pending policy step-up — run:  python cli.py policy set ...")
            body = {"challenge_id": pend["challenge_id"], "answer": args.text, "clear": [], **pend["fields"]}
            d = _check(c.post("/policy", json=body, headers=_auth()))
            PENDING_POLICY.unlink(missing_ok=True)
            print(f"policy change: {d['applied']}")


def cmd_notices(args):
    with _client() as c:
        if args.ack:
            d = _check(c.post("/notices/ack", headers=_auth()))
            print(f"acknowledged {d['acknowledged']} notice(s)")
        else:
            rows = _check(c.get("/notices", headers=_auth()))
            if not rows:
                print("(no notices)")
            for n in rows:
                mark = " " if n["read"] else "*"
                print(f"  [{mark}] ({n['kind']}) {n['message']}")


def main():
    p = argparse.ArgumentParser(prog="bardo", description="local keychain CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("register").set_defaults(fn=cmd_register)
    sub.add_parser("whoami").set_defaults(fn=cmd_whoami)
    sub.add_parser("login").set_defaults(fn=cmd_login)

    s = sub.add_parser("solve"); s.add_argument("answer"); s.set_defaults(fn=cmd_solve)
    s = sub.add_parser("sign"); s.add_argument("message"); s.set_defaults(fn=cmd_sign)
    sub.add_parser("export").set_defaults(fn=cmd_export)
    s = sub.add_parser("derive"); s.add_argument("service"); s.set_defaults(fn=cmd_derive)
    sub.add_parser("services").set_defaults(fn=cmd_services)

    s = sub.add_parser("session")
    s.add_argument("action", choices=["list", "revoke"])
    s.add_argument("--all", action="store_true", help="revoke every session, not just the current one")
    s.set_defaults(fn=cmd_session)

    s = sub.add_parser("note")
    s.add_argument("action", choices=["add", "list", "get", "update", "del", "undelete", "history"])
    s.add_argument("text", nargs="?", default="", help="full text (add), or full replacement (update)")
    s.add_argument("--id")
    s.add_argument("--title")
    s.add_argument("--summary")
    s.add_argument("--tags")
    s.add_argument("--append", help="append to the current text (update)")
    s.add_argument("--find", help="must match the current text exactly once (update)")
    s.add_argument("--replace")
    s.add_argument("--clear", help="comma-separated fields to null out: title,summary,tags")
    s.add_argument("--offset", type=int, default=0)
    s.add_argument("--length", type=int)
    s.add_argument("--limit", type=int)
    s.add_argument("--pinned", action="store_true", help="mark as a cold-start entry point (add)")
    s.add_argument("--pin", action="store_true", help="mark as an entry point (update)")
    s.add_argument("--unpin", action="store_true", help="unmark as an entry point (update)")
    s.set_defaults(fn=cmd_note)

    s = sub.add_parser("link")
    s.add_argument("action", choices=["add", "del"])
    s.add_argument("from_id", nargs="?")
    s.add_argument("to_id", nargs="?")
    s.add_argument("reason", nargs="?", default="")
    s.add_argument("--id", help="link id, for del")
    s.add_argument("--bidi", action="store_true")
    s.set_defaults(fn=cmd_link)

    sub.add_parser("dashboard").set_defaults(fn=cmd_dashboard)

    s = sub.add_parser("notices"); s.add_argument("--ack", action="store_true"); s.set_defaults(fn=cmd_notices)

    s = sub.add_parser("contact")
    s.add_argument("action", choices=["get", "set", "del", "solve"])
    s.add_argument("text", nargs="?", default="")
    s.set_defaults(fn=cmd_contact)

    s = sub.add_parser("account")
    s.add_argument("action", choices=["status", "delete", "solve", "cancel"])
    s.add_argument("text", nargs="?", default="", help="answer, for solve")
    s.set_defaults(fn=cmd_account)

    s = sub.add_parser("policy")
    s.add_argument("action", choices=["get", "set", "abort", "solve"])
    s.add_argument("text", nargs="?", default="", help="answer, for solve")
    s.add_argument("--export-mode", dest="export_mode", choices=["allow", "require_repuzzle", "disabled"])
    s.add_argument("--max-session-ttl", dest="max_session_ttl", type=int)
    s.add_argument("--service-allowlist", dest="service_allowlist",
                    help="comma-separated services; pass \"\" for an empty (block-all) list")
    s.add_argument("--loosen-delay-seconds", dest="loosen_delay_seconds", type=int)
    s.add_argument("--tags-encrypted", dest="tags_encrypted", choices=["true", "false"])
    s.add_argument("--delete-grace-seconds", dest="delete_grace_seconds", type=int)
    s.add_argument("--clear", help="comma-separated fields to null out: max_session_ttl,service_allowlist")
    s.set_defaults(fn=cmd_policy)

    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()

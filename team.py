#!/usr/bin/env python3
"""team.py — shared task board + hash-chained ledger for archivist ⇄ claude-code.

Append-only by construction: tasks and ledger are JSONL event logs, never edited.
Every ledger entry carries `prev` (previous digest) and its own `digest`, so any
tampering is detectable by `verify`.

    python3 team.py init
    python3 team.py post --from claude-code --to archivist --title "..." [--body ...] [--prio 2]
    python3 team.py claim --role archivist --id T1
    python3 team.py done --role archivist --id T1 --note "..."
    python3 team.py ls
    python3 team.py msg --from claude-code --to archivist --body "..."
    python3 team.py inbox --role archivist [--consume]
    python3 team.py log --from archivist --task "..." --status done --note "..."
    python3 team.py verify
"""
import argparse
import fcntl
import hashlib
import json
import os
import sys
import time

BASE = os.path.dirname(os.path.abspath(__file__))
TASKS = os.path.join(BASE, "board", "tasks.jsonl")
LEDGER = os.path.join(BASE, "ledger.jsonl")
INBOX = os.path.join(BASE, "inbox")
ROLES = ("archivist", "claude-code")


def ts():
    return int(time.time())


def iso(t=None):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts() if t is None else t))


def digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()[:16]


def append_jsonl(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.write(json.dumps(obj, sort_keys=True) + "\n")
        f.flush()
        os.fsync(f.fileno())
        fcntl.flock(f, fcntl.LOCK_UN)


def read_jsonl(path):
    if not os.path.exists(path):
        return []
    out = []
    with open(path, encoding="utf-8") as f:
        fcntl.flock(f, fcntl.LOCK_SH)
        for line in f:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    out.append({"event": "__corrupt__", "raw": line})
        fcntl.flock(f, fcntl.LOCK_UN)
    return out


# ---------------------------------------------------------------- board state
def state():
    tasks = {}
    order = []
    for e in read_jsonl(TASKS):
        if e.get("event") == "post":
            tasks[e["id"]] = {"id": e["id"], "title": e["title"], "to": e.get("to", "any"),
                              "from": e["from"], "prio": e.get("prio", 3),
                              "status": "open", "owner": None, "notes": []}
            order.append(e["id"])
        elif e.get("event") == "claim" and e["id"] in tasks:
            tasks[e["id"]].update(status="claimed", owner=e["from"])
        elif e.get("event") == "done" and e["id"] in tasks:
            tasks[e["id"]].update(status="done", owner=e.get("from"))
            if e.get("note"):
                tasks[e["id"]]["notes"].append(e["note"])
    return tasks, order


def cmd_post(a):
    tasks, order = state()
    tid = f"T{len(order) + 1}"
    append_jsonl(TASKS, {"event": "post", "id": tid, "ts": ts(), "from": a.__dict__["_from"],
                         "to": a.to, "title": a.title, "body": a.body, "prio": a.prio})
    append_jsonl(LEDGER, _ledger_entry(a.__dict__["_from"], f"post {tid}", "open", a.title))
    print(f"posted {tid}  {a.title}")


def cmd_claim(a):
    tasks, _ = state()
    if a.id not in tasks:
        sys.exit(f"error: no task {a.id}")
    if tasks[a.id]["status"] == "done":
        sys.exit(f"error: {a.id} already done")
    append_jsonl(TASKS, {"event": "claim", "id": a.id, "ts": ts(), "from": a.role})
    append_jsonl(LEDGER, _ledger_entry(a.role, f"claim {a.id}", "claimed", tasks[a.id]["title"]))
    print(f"{a.role} claimed {a.id}")


def cmd_done(a):
    tasks, _ = state()
    if a.id not in tasks:
        sys.exit(f"error: no task {a.id}")
    append_jsonl(TASKS, {"event": "done", "id": a.id, "ts": ts(), "from": a.role, "note": a.note})
    append_jsonl(LEDGER, _ledger_entry(a.role, f"done {a.id}", "done", a.note or tasks[a.id]["title"]))
    print(f"{a.role} closed {a.id}")


def cmd_ls(_a):
    tasks, order = state()
    if not order:
        print("(board empty)")
        return
    print(f"{'id':4} {'prio':4} {'status':8} {'owner':12} title")
    for tid in order:
        t = tasks[tid]
        print(f"{t['id']:4} {t['prio']:<4} {t['status']:8} {str(t['owner'] or '-'):12} {t['title']}")


# -------------------------------------------------------------------- mailbox
def cmd_msg(a):
    d = os.path.join(INBOX, a.to)
    os.makedirs(d, exist_ok=True)
    name = f"{ts()}-{a.__dict__['_from']}.md"
    p = os.path.join(d, name)
    with open(p, "w", encoding="utf-8") as f:
        f.write(f"<!-- from: {a.__dict__['_from']} to: {a.to} at: {iso()} -->\n\n{a.body}\n")
    append_jsonl(LEDGER, _ledger_entry(a.__dict__["_from"], "msg", "sent", f"to {a.to}: {a.body[:60]}"))
    print(f"delivered {p}")


def cmd_inbox(a):
    d = os.path.join(INBOX, a.role)
    if not os.path.isdir(d):
        print("(empty)")
        return
    files = sorted(f for f in os.listdir(d) if not f.startswith("."))
    if not files:
        print("(empty)")
    for f in files:
        p = os.path.join(d, f)
        print(f"--- {f} ---")
        with open(p, encoding="utf-8") as fh:
            print(fh.read().rstrip())
        if a.consume:
            done_dir = os.path.join(d, ".read")
            os.makedirs(done_dir, exist_ok=True)
            os.replace(p, os.path.join(done_dir, f))


# --------------------------------------------------------------------- ledger
def _ledger_entry(role, task, status, note=""):
    prev = ""
    if os.path.exists(LEDGER):
        lines = [l for l in open(LEDGER, encoding="utf-8") if l.strip()]
        if lines:
            prev = json.loads(lines[-1]).get("digest", "")
    e = {"prev": prev, "ts": ts(), "at": iso(), "from": role,
         "task": task, "status": status, "note": note}
    e["digest"] = digest(e)
    return e


def cmd_log(a):
    append_jsonl(LEDGER, _ledger_entry(a.__dict__["_from"], a.task, a.status, a.note))
    print("logged")


def cmd_verify(_a):
    ok = True
    prev = ""
    n = 0
    for e in read_jsonl(LEDGER):
        n += 1
        body = {k: v for k, v in e.items() if k != "digest"}
        if digest(body) != e.get("digest"):
            print(f"FAIL  ledger line {n}: digest mismatch"); ok = False
        if e.get("prev", "") != prev:
            print(f"FAIL  ledger line {n}: chain break (prev={e.get('prev')} expected={prev})"); ok = False
        prev = e.get("digest", "")
    tasks, _ = state()
    for tid, t in tasks.items():
        if t["status"] == "done" and not t["owner"]:
            print(f"FAIL  {tid} done with no owner"); ok = False
    print(f"ledger entries: {n} | tasks: {len(tasks)}")
    print("RESULT:", "VALID" if ok else "INVALID")
    return 0 if ok else 1


def cmd_init(_a):
    for d in ("board", "notes", os.path.join(INBOX, ROLES[0]), os.path.join(INBOX, ROLES[1])):
        os.makedirs(os.path.join(BASE, d), exist_ok=True)
    for f in (TASKS, LEDGER):
        open(f, "a").close()
    print(f"initialised {BASE}")


def main():
    ap = argparse.ArgumentParser(description="team board for archivist ⇄ claude-code")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init"); p.set_defaults(func=cmd_init)

    p = sub.add_parser("post")
    p.add_argument("--from", dest="_from", required=True, choices=ROLES)
    p.add_argument("--to", default="any")
    p.add_argument("--title", required=True); p.add_argument("--body", default="")
    p.add_argument("--prio", type=int, default=3)
    p.set_defaults(func=cmd_post)

    p = sub.add_parser("claim")
    p.add_argument("--role", required=True, choices=ROLES); p.add_argument("--id", required=True)
    p.set_defaults(func=cmd_claim)

    p = sub.add_parser("done")
    p.add_argument("--role", required=True, choices=ROLES); p.add_argument("--id", required=True)
    p.add_argument("--note", default="")
    p.set_defaults(func=cmd_done)

    p = sub.add_parser("ls"); p.set_defaults(func=cmd_ls)

    p = sub.add_parser("msg")
    p.add_argument("--from", dest="_from", required=True, choices=ROLES)
    p.add_argument("--to", required=True, choices=ROLES); p.add_argument("--body", required=True)
    p.set_defaults(func=cmd_msg)

    p = sub.add_parser("inbox")
    p.add_argument("--role", required=True, choices=ROLES)
    p.add_argument("--consume", action="store_true")
    p.set_defaults(func=cmd_inbox)

    p = sub.add_parser("log")
    p.add_argument("--from", dest="_from", required=True, choices=ROLES)
    p.add_argument("--task", required=True); p.add_argument("--status", default="done")
    p.add_argument("--note", default="")
    p.set_defaults(func=cmd_log)

    p = sub.add_parser("verify"); p.set_defaults(func=cmd_verify)

    a = ap.parse_args()
    if hasattr(a, "to") and getattr(a, "to") not in (None, "any") and a.to not in ROLES:
        ap.error(f"--to must be 'any' or one of {ROLES}")
    sys.exit(a.func(a) or 0)


if __name__ == "__main__":
    main()

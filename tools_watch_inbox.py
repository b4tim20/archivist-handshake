#!/usr/bin/env python3
"""Watch inbox/archivist/ for new messages; print each as it lands.

Usage: python3 tools_watch_inbox.py [--timeout 180] [--interval 3]
Exit: 0 if at least one new file appeared, 1 on timeout, 2 on usage error.
Baseline is taken at start, so files already present are not reported.
"""
import argparse, os, sys, time

INBOX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "inbox", "archivist")


def snap():
    out = {}
    for f in os.listdir(INBOX):
        p = os.path.join(INBOX, f)
        if os.path.isfile(p):
            st = os.stat(p)
            out[f] = (st.st_mtime, st.st_size)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--timeout", type=float, default=180)
    ap.add_argument("--interval", type=float, default=3)
    a = ap.parse_args()

    base = snap()
    print(f"watching {INBOX}", flush=True)
    print(f"baseline: {len(base)} files; timeout {a.timeout:.0f}s, poll {a.interval:.0f}s", flush=True)
    t0 = time.time()
    found = []
    while time.time() - t0 < a.timeout:
        time.sleep(a.interval)
        cur = snap()
        for f, (mt, sz) in sorted(cur.items()):
            if f not in base:
                print(f"NEW   {time.strftime('%H:%M:%S')}  {sz:>6} B  {f}", flush=True)
                found.append(f)
            elif base[f] != (mt, sz):
                print(f"CHANGED {f}  {base[f][1]} -> {sz} B", flush=True)
                found.append(f)
        base = cur
        if found:
            break
    if found:
        print(f"RESULT: {len(found)} new/changed file(s)")
        return 0
    print("RESULT: timeout, nothing new")
    return 1


if __name__ == "__main__":
    sys.exit(main())

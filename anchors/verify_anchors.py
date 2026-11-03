#!/usr/bin/env python3
"""Verify anchors AND the ledger they anchor.

Two distinct failure modes, two distinct mechanisms:
  * content edits      -> each entry's digest must recompute from its own body (team.py recipe)
  * truncation/rollback-> anchor.entries must exist and hold anchor.head at that position
  * anchor edits       -> each anchor's prev_anchor_sha256 must match its predecessor's bytes
An anchor that only checks the head position is blind to a doctored middle. This one is not.
"""
import glob, hashlib, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def sha_file(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


def entry_digest(e):
    """Same recipe as team.py: sha256 of the sorted body, truncated to 16 hex."""
    body = {k: v for k, v in e.items() if k != "digest"}
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()[:16]


def main():
    ledger = [json.loads(l) for l in open(os.path.join(ROOT, "ledger.jsonl"), encoding="utf-8") if l.strip()]
    files = sorted(glob.glob(os.path.join(HERE, "[0-9]*.json")))
    if not files:
        sys.exit("no anchors found")
    ok = True

    # 1. ledger internal integrity: digests recompute, prev links hold
    bad = 0
    prev = ""
    for i, e in enumerate(ledger, 1):
        if entry_digest(e) != e.get("digest"):
            print(f"  FAIL ledger line {i}: digest mismatch"); ok = False; bad += 1
        if e.get("prev", "") != prev:
            print(f"  FAIL ledger line {i}: chain break"); ok = False; bad += 1
        prev = e.get("digest", "")
    if not bad:
        print(f"  OK   ledger internal: {len(ledger)} entries, digests recomputed, chain intact")

    # 2. anchors against the ledger and against each other
    prev_sha = None
    for f in files:
        a = json.load(open(f, encoding="utf-8"))
        problems = []
        if a["prev_anchor_sha256"] != prev_sha:
            problems.append(f"prev_anchor_sha256 mismatch (file {str(a['prev_anchor_sha256'])[:16]}, expected {str(prev_sha)[:16]})")
        if a["entries"] > len(ledger):
            problems.append(f"claims {a['entries']} entries, ledger has {len(ledger)} — tail truncated")
        elif ledger[a["entries"] - 1]["digest"] != a["head"]:
            problems.append("head does not match ledger at that position — history rewritten")
        print(f"  {'OK  ' if not problems else 'FAIL'} {os.path.basename(f)}  entries={a['entries']:>3}  head={a['head'][:8]}")
        for p in problems:
            print(f"         - {p}")
        ok = ok and not problems
        prev_sha = sha_file(f)

    print(f"\nanchors: {len(files)}  ledger: {len(ledger)} entries")
    print("RESULT:", "VALID" if ok else "BROKEN")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

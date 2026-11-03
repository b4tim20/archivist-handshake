#!/usr/bin/env python3
"""Write one ledger anchor: a dated, self-chaining snapshot of the ledger head."""
import datetime, glob, hashlib, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
LEDGER = os.path.join(ROOT, "ledger.jsonl")


def sha_file(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


def main():
    rows = [json.loads(l) for l in open(LEDGER, encoding="utf-8") if l.strip()]
    if not rows:
        sys.exit("ledger empty")
    prev = sorted(glob.glob(os.path.join(HERE, "[0-9]*.json")))
    prev_sha = sha_file(prev[-1]) if prev else None
    now = datetime.datetime.now(datetime.timezone.utc)
    anchor = {
        "schema": "archivist.anchor.v1",
        "date": now.strftime("%Y-%m-%d"),
        "generated_at": now.isoformat(),
        "entries": len(rows),
        "head": rows[-1]["digest"],
        "head_at": rows[-1]["at"],
        "prev_anchor_sha256": prev_sha,
        "note": "Anchors chain to each other. Truncating the ledger tail or editing a past anchor "
                "breaks this chain visibly at the earliest altered file.",
    }
    stem = now.strftime("%Y-%m-%dT%H%M%SZ")
    out = os.path.join(HERE, stem + ".json")
    n = 1
    while os.path.exists(out):          # never overwrite an anchor: that would break the chain
        n += 1
        out = os.path.join(HERE, f"{stem}-{n}.json")
    tmp = out + ".tmp"
    json.dump(anchor, open(tmp, "w", encoding="utf-8"), indent=2)
    open(tmp, "a").write("\n")
    os.replace(tmp, out)
    print("wrote", os.path.relpath(out, ROOT))
    for k in ("entries", "head", "prev_anchor_sha256"):
        print(f"  {k:20s} {anchor[k]}")
    print(f"  {'anchor_sha256':20s} {sha_file(out)}")


if __name__ == "__main__":
    main()

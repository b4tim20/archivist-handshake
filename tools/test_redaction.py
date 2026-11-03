#!/usr/bin/env python3
"""Redaction tests. The first test must FAIL (redaction off) before the second may PASS.

A leak test that has never seen a leak proves nothing.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from redact import redact, harvest_secrets, scan_leaks

FAKE = {
    "handshake":  "a" * 59 + "bcd1",
    "sessionkey": "7f" * 32,
    "nonce":      "de" * 32,
    "preimage":   "ARCHIVIST-HANDSHAKE/v1|2026-10-31|archivist:" + "0f" * 32,
    "code":       "QX7RT-M9WZK",
    "sudo":       "123456",
    "file_sha":   "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}

FIXTURE = f"""# TEAM.md (excerpt)
## Session key (2026-10-18 meeting)
| **handshake** | `{FAKE['handshake']}` |
| **sessionkey** | `{FAKE['sessionkey']}` |
| nonce | {FAKE['nonce']}
preimage: {FAKE['preimage']}

## Manifest
sha256 of the dossier text: {FAKE['file_sha']}

Recovery code backup: {FAKE['code']}
last command: sudo={FAKE['sudo']} chmod 600 file
"""

SECRETS_EXPECTED = {FAKE[k] for k in ("handshake", "sessionkey", "nonce", "preimage", "code", "sudo")}


def main():
    results = []

    # --- Control: with redaction disabled, the leak MUST be detectable.
    leaks_off = scan_leaks(FIXTURE, SECRETS_EXPECTED)
    control_ok = len(leaks_off) == len(SECRETS_EXPECTED)
    results.append(("control: unredacted text leaks every secret (must be detected)",
                    control_ok, f"{len(leaks_off)}/{len(SECRETS_EXPECTED)} detected"))

    # --- The real thing.
    clean, stats = redact(FIXTURE)
    leaks_on = scan_leaks(clean, SECRETS_EXPECTED)
    results.append(("redacted text leaks nothing", not leaks_on, f"leaks={leaks_on or 'none'}"))

    # --- Legitimate file digest must survive: over-redaction destroys the audit trail.
    keeps_sha = FAKE["file_sha"] in clean
    results.append(("legitimate file sha256 preserved (not over-redacted)", keeps_sha,
                    "present" if keeps_sha else "DESTROYED"))

    # --- Non-secret prose survives.
    keeps_prose = "## Manifest" in clean and "Recovery code backup" in clean
    results.append(("surrounding prose preserved", keeps_prose, "ok" if keeps_prose else "lost"))

    # --- Harvest must find the real values, not the placeholders.
    harvested = harvest_secrets([FIXTURE])
    missing = SECRETS_EXPECTED - harvested
    results.append(("harvest_secrets finds all secret values", not missing,
                    f"missing={missing or 'none'}"))

    # --- Placeholders must not be re-harvested (idempotent redaction).
    clean2, _ = redact(clean)
    results.append(("redaction is idempotent", clean2 == clean, "stable" if clean2 == clean else "drifts"))

    width = max(len(n) for n, _, _ in results)
    ok_all = True
    print()
    for name, ok, detail in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name:<{width}}  {detail}")
        ok_all &= ok
    print(f"\n  stats: {stats}")
    print("RESULT:", "ALL PASS" if ok_all else "FAILURES PRESENT")
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Redaction rules for embedded artifacts, plus the leak scan that enforces them."""
import re

SECRET_KEYS = ("handshake", "sessionkey", "session key", "session_key", "nonce",
               "preimage", "commitment")
HEXISH = re.compile(r"\b[0-9a-fA-F]{16,}\b")
RECOVERY = re.compile(r"\b[A-Z0-9]{5}-[A-Z0-9]{5}\b")
SUDO = re.compile(r"(sudo\s*=\s*)(\S+)")
KEYED_LINE = re.compile("|".join(re.escape(k) for k in SECRET_KEYS), re.I)


def redact(text):
    """Return (clean_text, stats). Contextual: only lines carrying a secret key are scrubbed."""
    stats = {"keyed_lines": 0, "hex_redacted": 0, "codes_redacted": 0, "sudo_redacted": 0}
    out = []
    for line in text.splitlines():
        if KEYED_LINE.search(line):
            stats["keyed_lines"] += 1
            def sub(m):
                stats["hex_redacted"] += 1
                return "[REDACTED:key]"
            line = HEXISH.sub(sub, line)
        line, n = RECOVERY.subn("[REDACTED:recovery-code]", line)
        stats["codes_redacted"] += n
        line, n = SUDO.subn(r"\1[REDACTED:secret]", line)
        stats["sudo_redacted"] += n
        out.append(line)
    return "\n".join(out) + ("\n" if text.endswith("\n") else ""), stats


def harvest_secrets(texts):
    """Collect secret-shaped values: anything carrying a >=32-hex run, recovery codes, sudo values.

    Not "any long token on a keyed line" — that harvests filenames like ARCHIVIST-HANDSHAKE.md and
    makes the fail-closed gate abort on prose. Secret-shaped, not merely long.
    """
    HEXRUN = re.compile(r"[0-9a-fA-F]{32,}")
    found = set()
    for t in texts:
        for line in t.splitlines():
            if not KEYED_LINE.search(line):
                continue
            for m in re.finditer(r"[`\"']([^`\"']+)[`\"']", line):
                if HEXRUN.search(m.group(1)):
                    found.add(m.group(1))          # composite secret (preimage), whole value
            m = re.search(r"[:=]\s*(\S{16,})\s*$", line)
            if m and HEXRUN.search(m.group(1)):
                found.add(m.group(1).strip("|`\"' "))
            for m in HEXISH.finditer(line):
                if len(m.group()) >= 32:
                    found.add(m.group())
    for t in texts:
        for m in RECOVERY.finditer(t):
            found.add(m.group())
        for m in SUDO.finditer(t):
            found.add(m.group(2))
    return found


def scan_leaks(rendered, secrets):
    return {s: rendered.count(s) for s in secrets if rendered.count(s)}

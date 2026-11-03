# archivist-handshake

A working protocol for two AI agents — with different owners, contexts and failure modes — to collaborate
on shared artifacts without trusting each other's claims.

Built and used in production across ~180 ledger entries, including a statistical audit, a site deployment,
and a resume review.

## What it provides

| Component | File | Purpose |
|---|---|---|
| Task board | `team.py` | append-only task ledger with claim/close states, roles, and notes |
| Hash chain | `team.py` | every entry carries the digest of the previous entry; `verify` detects edits and truncation |
| Anchors | `anchors/gen_anchor.py`, `anchors/verify_anchors.py` | periodic head digests pin the chain against rollback |
| Handshake | `archivist_handshake.py` | nonce-commitment protocol so both sides can prove they saw the same session |
| Dossier | `tools/gen_dossier.py` | renders the collaboration record to PDF, with a **redaction gate that aborts rather than write** if a secret survives |
| Redaction | `tools/redact.py` | pattern harvesting and replacement, with tests |

## Design rules worth stealing

- **A digest identifies bytes at a time, not a file forever.** Recompute before use; re-declare when the
  file changed. Three separate incidents in this project came from using a stale digest.
- **Verification is independent of authority.** The non-manager role re-runs the manager's commands rather
  than accepting the result. Disagreement is reported once, with the command and output.
- **Errors against interest are the strongest signal.** A document that understates its own figures is
  more likely to be honest than one that rounds in its own favour.
- **Fail closed on secrets.** The dossier generator aborts with exit 2 and writes nothing if redaction
  leaves a secret in the output.

## Requirements

Python 3.10+. The dossier generator additionally needs `tectonic` (or any LaTeX engine) for PDF output.

## Status

The tooling is general. The ledger, inbox, notes and memory directories from the live deployment are not
included — they contain the private record of that collaboration.

## License

MIT — see `LICENSE`.

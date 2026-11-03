#!/usr/bin/env python3
"""Build a dossier that cannot leak what it embeds, and that contains its own source.

Fail-closed: secrets are harvested from the sources, the output is rendered, and the build
aborts if any harvested value appears in the rendered text. Nothing is written on failure.
"""
import datetime, glob, hashlib, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from redact import redact, harvest_secrets, scan_leaks

OUT = os.path.join(ROOT, "dossier")

def sha(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()

def read(p):
    return open(p, encoding="utf-8", errors="replace").read()

def jsonl(p):
    return [json.loads(l) for l in open(p, encoding="utf-8") if l.strip()]

def esc(s):
    rep = {"\\": r"\textbackslash{}", "&": r"\&", "%": r"\%", "$": r"\$", "#": r"\#",
           "_": r"\_", "{": r"\{", "}": r"\}", "~": r"\textasciitilde{}", "^": r"\textasciicircum{}"}
    return "".join(rep.get(c, c) for c in str(s))

def verify_ledger(rows):
    prev = ""
    for i, e in enumerate(rows, 1):
        body = {k: v for k, v in e.items() if k != "digest"}
        d = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()[:16]
        if d != e.get("digest") or e.get("prev", "") != prev:
            return False, f"entry {i}"
        prev = e.get("digest", "")
    return True, "all entries"

def main():
    now = datetime.datetime.now(datetime.timezone.utc)
    team = read(os.path.join(ROOT, "TEAM.md"))
    ledger = jsonl(os.path.join(ROOT, "ledger.jsonl"))
    board = [e for e in jsonl(os.path.join(ROOT, "board", "tasks.jsonl")) if e.get("event") == "post"]
    hands = sorted(glob.glob(os.path.join(ROOT, "handshake", "*", "*.json")))
    notes = sorted(glob.glob(os.path.join(ROOT, "notes", "*.md")))

    sources = [os.path.join(ROOT, "TEAM.md"), os.path.join(ROOT, "ledger.jsonl"),
               os.path.join(ROOT, "board", "tasks.jsonl")] + hands
    src_text = [read(p) for p in sources]

    ok, detail = verify_ledger(ledger)
    # Excerpt the whole file, not a comfortable prefix: the risky block (the session key table)
    # sits near the end, so a 40-line excerpt would "pass" by never reaching it.
    team_red, stats_team = redact(team)
    hands_rows = []
    for h in hands:
        j = json.load(open(h))
        role = j.get("role"); meeting = j.get("meeting")
        hands_rows.append((meeting, role, "published", j.get("created_at", "")[:19]))

    L = []
    A = L.append
    A(r"\documentclass[10pt,a4paper]{article}")
    A(r"\usepackage[margin=20mm]{geometry}")
    A(r"\usepackage{longtable,booktabs,array,xcolor,listings,hyperref}")
    A(r"\newcolumntype{L}[1]{>{\raggedright\arraybackslash}p{#1}}")
    A(r"\lstset{basicstyle=\ttfamily\scriptsize,breaklines=true,frame=single,columns=fullflexible}")
    A(r"\setlength{\parindent}{0pt}\setlength{\parskip}{4pt}")
    A(r"\title{\textbf{Team Dossier --- Archivist and Claude Code}\\ \large regenerable build}")
    A(r"\author{archivist}\date{" + now.strftime("%Y-%m-%d %H:%M UTC") + "}")
    A(r"\begin{document}\maketitle")

    gen_sha = sha(os.path.abspath(__file__))
    A(r"\section*{Document control}")
    A(r"\begin{longtable}{L{5.2cm}L{10.4cm}}\toprule")
    A(r"Field & Value \\ \midrule")
    rows_dc = [
        ("Generated at", now.isoformat(timespec="seconds")),
        ("Generator", "tools/gen_dossier.py"),
        ("Generator SHA-256", gen_sha),
        ("Generator source", "embedded verbatim in Appendix A"),
        ("Redaction", "contextual on keyed lines + fail-closed leak scan before write"),
        ("Ledger entries", str(len(ledger))),
        ("Ledger integrity", ("VALID" if ok else "INVALID") + " (" + detail + ")"),
        ("Handshake records", str(len(hands))),
        ("Notes", str(len(notes))),
    ]
    for k, v in rows_dc:
        A(esc(k) + " & " + esc(v) + r" \\")
    A(r"\bottomrule\end{longtable}")

    A(r"\section{Purpose}")
    A(r"This document is produced by a generator that travels inside it. The digest above describes "
      r"the file that produced these pages, computed at build time --- not a hash of some earlier "
      r"version that no longer exists. Rebuild with \texttt{python3 tools/gen\_dossier.py} and the "
      r"Document Control table must reproduce, except for the timestamp.")

    A(r"\section{Redaction policy}")
    A(r"Two layers. Contextual: any line whose key is one of \texttt{handshake}, \texttt{sessionkey}, "
      r"\texttt{nonce}, \texttt{preimage} or \texttt{commitment} has its values replaced. File digests "
      r"elsewhere are preserved deliberately --- over-redaction would destroy the audit trail in order "
      r"to protect nothing. Fail-closed: secret values are harvested from the sources, the output is "
      r"scanned, and the build aborts if any harvested value survives. This build passed that scan.")

    A(r"\section{Team state (redacted excerpt)}")
    A(r"\begin{lstlisting}")
    A(team_red)
    A(r"\end{lstlisting}")

    A(r"\section{Ledger}")
    A(r"\begin{longtable}{L{3.2cm}L{3.6cm}L{2.4cm}L{6.0cm}}\toprule")
    A(r"At & From & Task & Note \\ \midrule")
    for e in ledger[-25:]:
        note, _ = redact(str(e.get("note", ""))[:110])
        A(f"{esc(e.get('at',''))[:19]} & {esc(e.get('from',''))} & {esc(e.get('task',''))} & {esc(note)} \\\\")
    A(r"\bottomrule\end{longtable}")

    A(r"\section{Board}")
    A(r"\begin{longtable}{L{1.3cm}L{1.4cm}L{2.2cm}L{2.4cm}L{8.1cm}}\toprule")
    A(r"ID & Prio & Status & Owner & Title \\ \midrule")
    for t in sorted(board, key=lambda x: x.get("id", "")):
        A(f"{esc(t.get('id'))} & {esc(t.get('prio'))} & {esc(t.get('status'))} & "
          f"{esc(t.get('owner') or '-')} & {esc(t.get('title'))} \\\\")
    A(r"\bottomrule\end{longtable}")

    A(r"\section{Handshake records}")
    A(r"\begin{longtable}{L{2.6cm}L{3.0cm}L{2.6cm}L{6.8cm}}\toprule")
    A(r"Meeting & Role & Nonce state & Published \\ \midrule")
    for meeting, role, state, when in hands_rows:
        A(f"{esc(meeting)} & {esc(role)} & {esc(state)} & {esc(when)} \\\\")
    A(r"\bottomrule\end{longtable}")
    A(r"Nonce values are withheld from this table by policy; they remain in \texttt{handshake/} at "
      r"mode 0600. Their publication here would be equivalent to publishing the session key.")

    A(r"\section{Source receipts}")
    A(r"\begin{longtable}{L{7.4cm}L{7.8cm}}\toprule")
    A(r"Source & SHA-256 \\ \midrule")
    for p in sources:
        A(r"\texttt{" + esc(os.path.relpath(p, ROOT)) + "} & \\texttt{" + sha(p) + "} \\\\")
    A(r"\bottomrule\end{longtable}")

    A(r"\appendix")
    A(r"\section{Generator source}")
    A(r"The complete source of the program that produced this document, so the claim in Document "
      r"Control is checkable rather than asserted.")
    # lstinputlisting, not an inline listing: this file contains the literal end-of-listing
    # marker in its own source, which terminates an inline environment and breaks the build.
    A(r"\lstinputlisting[language=Python]{../tools/gen_dossier.py}")
    A(r"\end{document}")
    tex = "\n".join(L)

    # ---- fail-closed gate
    secrets = harvest_secrets(src_text)
    leaks = scan_leaks(tex, secrets)
    if leaks:
        print(f"ABORT: {len(leaks)} secret value(s) survived redaction. Nothing written.", file=sys.stderr)
        for s in list(leaks)[:3]:
            print(f"  leaked value of length {len(s)}", file=sys.stderr)
        return 2

    os.makedirs(OUT, exist_ok=True)
    out = os.path.join(OUT, now.strftime("%Y-%m-%dT%H%MZ") + "-dossier.tex")
    open(out, "w", encoding="utf-8").write(tex)
    print(f"wrote {os.path.relpath(out, ROOT)} ({len(tex.encode())} B)")
    print(f"  generator sha256   {gen_sha}")
    print(f"  secrets harvested  {len(secrets)}")
    print(f"  leaks              none (build permitted)")
    print(f"  output sha256      {sha(out)}")
    return 0

if __name__ == "__main__":
    sys.exit(main())

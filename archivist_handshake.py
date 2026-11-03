#!/usr/bin/env python3
"""
ARCHIVIST-HANDSHAKE/v1

Simultaneous handshake between two local agent roles (e.g. claude-code and
archivist) on the same machine.

How it works:
  1. Both sides independently run `run --role <role>` at the same time.
  2. Each publishes a random 32-byte nonce (plus a commitment) to
     ~/.config/archivist/handshake/<meeting>/<role>.json
  3. Each waits for the peer's file, verifies the commitment, then both
     compute the SAME handshake hash over the two nonces in sorted order.
  4. The handshake hash is expanded into a 32-byte session key via HKDF.

Because the nonces are sorted before hashing, neither side needs to know who
went first. Both arrive at the identical digest without further coordination.

The `token` subcommand is a lighter-weight check: a SHA-256 over the current
time window. Both sides running it in the same window get the same token.

This authenticates *shared presence and shared inputs between cooperating
processes*. It is NOT a substitute for authentication against a hostile local
user -- any process that can read the rendezvous files can see the nonces.
Keep the rendezvous directory mode 0700.

stdlib only.
"""

import argparse
import hashlib
import hmac
import json
import os
import secrets
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone

PROTOCOL = "ARCHIVIST-HANDSHAKE/v1"
SYNC_PROTOCOL = "ARCHIVIST-SYNCH/v1"
DEFAULT_MEETING = datetime.now(timezone.utc).strftime("%Y-%m-%d")
BASE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "handshake")
NONCE_BYTES = 32
DEFAULT_WINDOW_SECONDS = 60


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_nonce_preimage(meeting: str, role_a: str, nonce_a: str,
                             role_b: str, nonce_b: str) -> str:
    """Order-independent preimage: sort the (nonce, role) pairs by nonce."""
    pairs = sorted([(nonce_a, role_a), (nonce_b, role_b)])
    return "|".join([
        PROTOCOL,
        meeting,
        f"{pairs[0][1]}:{pairs[0][0]}",
        f"{pairs[1][1]}:{pairs[1][0]}",
    ])


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, t, counter = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]


def meeting_dir(meeting: str) -> str:
    return os.path.join(BASE_DIR, meeting)


def role_path(meeting: str, role: str) -> str:
    return os.path.join(meeting_dir(meeting), f"{role}.json")


def ensure_private_dir(path: str) -> None:
    os.makedirs(path, mode=0o700, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass


def atomic_write_json(path: str, payload: dict, mode: int = 0o600) -> None:
    directory = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def read_json(path: str) -> dict:
    with open(path, "r") as fh:
        return json.load(fh)


# --------------------------------------------------------------------------
# token: time-window synchrony hash
# --------------------------------------------------------------------------

def cmd_token(args: argparse.Namespace) -> int:
    now = time.time()
    window = max(1, args.window)
    bucket = int(now // window)
    start = datetime.fromtimestamp(bucket * window, timezone.utc)
    end = start + timedelta(seconds=window)
    preimage = f"{SYNC_PROTOCOL}|window={bucket}|seconds={window}"
    token = sha256_hex(preimage.encode())
    print(f"protocol   {SYNC_PROTOCOL}")
    print(f"window     {bucket}  ({start.isoformat()} .. {end.isoformat()})")
    print(f"preimage   {preimage}")
    print(f"token      {token}")


# --------------------------------------------------------------------------
# publish / verify / run: nonce-exchange handshake
# --------------------------------------------------------------------------

def cmd_publish(args: argparse.Namespace) -> int:
    if not args.role:
        print("error: --role is required", file=sys.stderr)
        return 2
    meeting = args.meeting
    nonce = secrets.token_hex(NONCE_BYTES)
    commitment = sha256_hex(f"{PROTOCOL}|{meeting}|{args.role}|{nonce}".encode())
    payload = {
        "protocol": PROTOCOL,
        "meeting": meeting,
        "role": args.role,
        "nonce": nonce,
        "commitment": commitment,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    path = role_path(meeting, args.role)
    ensure_private_dir(meeting_dir(meeting))
    atomic_write_json(path, payload)
    print(f"published  {path}")
    print(f"role       {args.role}")
    print(f"meeting    {meeting}")
    print(f"commitment {commitment}")
    return 0


def _load_and_validate(path: str, meeting: str, role: str) -> dict:
    payload = read_json(path)
    for key in ("protocol", "meeting", "role", "nonce", "commitment"):
        if key not in payload:
            raise ValueError(f"{path}: missing field {key!r}")
    if payload["protocol"] != PROTOCOL:
        raise ValueError(f"{path}: protocol mismatch")
    if payload["meeting"] != meeting:
        raise ValueError(f"{path}: meeting mismatch")
    if payload["role"] != role:
        raise ValueError(f"{path}: role mismatch (expected {role!r})")
    nonce = payload["nonce"]
    if len(nonce) != NONCE_BYTES * 2:
        raise ValueError(f"{path}: nonce has wrong length")
    expected = sha256_hex(f"{PROTOCOL}|{meeting}|{role}|{nonce}".encode())
    if not hmac.compare_digest(payload["commitment"], expected):
        raise ValueError(f"{path}: commitment verification failed")
    return payload


def cmd_verify(args: argparse.Namespace) -> int:
    if not args.role:
        print("error: --role is required", file=sys.stderr)
        return 2
    meeting = args.meeting
    mine_path = role_path(meeting, args.role)
    peer_path = role_path(meeting, args.peer_role)

    mine = _load_and_validate(mine_path, meeting, args.role)

    deadline = time.time() + max(0, args.timeout)
    while not os.path.exists(peer_path):
        if time.time() >= deadline:
            print(f"waiting    peer file not found: {peer_path}", file=sys.stderr)
            print(f"hint       run on the other side: "
                  f"python3 {os.path.abspath(__file__)} run --role {args.peer_role}"
                  f" --meeting {meeting}", file=sys.stderr)
            return 3
        time.sleep(0.25)

    peer = _load_and_validate(peer_path, meeting, args.peer_role)

    if hmac.compare_digest(mine["nonce"], peer["nonce"]):
        print("error: nonces are identical; one side reused the other's value",
              file=sys.stderr)
        return 4

    preimage = canonical_nonce_preimage(
        meeting,
        args.role, mine["nonce"],
        args.peer_role, peer["nonce"],
    )
    handshake = sha256_hex(preimage.encode())
    key = hkdf_sha256(
        bytes.fromhex(handshake),
        salt=sha256_hex(f"{PROTOCOL}|{meeting}".encode()).encode(),
        info=b"archivist-session-key/v1",
        length=32,
    )

    print(f"protocol   {PROTOCOL}")
    print(f"meeting    {meeting}")
    print(f"roles      {args.role} <-> {args.peer_role}")
    print(f"preimage   {preimage}")
    print(f"handshake  {handshake}")
    print(f"sessionkey {key.hex()}")
    print("status     VERIFIED")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    rc = cmd_publish(args)
    if rc != 0:
        return rc
    return cmd_verify(args)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="ARCHIVIST-HANDSHAKE/v1 — simultaneous hash handshake "
                    "between two local agent roles.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_token = sub.add_parser("token", help="print the time-window synchrony token")
    p_token.add_argument("--window", type=int, default=DEFAULT_WINDOW_SECONDS,
                         help="window length in seconds (default 60)")
    p_token.set_defaults(func=cmd_token)

    def add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--role", required=True, help="your role name")
        p.add_argument("--peer-role", required=True, help="peer role name")
        p.add_argument("--meeting", default=DEFAULT_MEETING,
                       help="meeting id (default: current UTC date)")
        p.add_argument("--timeout", type=float, default=120.0,
                       help="seconds to wait for the peer file (default 120)")

    p_pub = sub.add_parser("publish", help="publish your nonce commitment")
    add_common(p_pub)
    p_pub.set_defaults(func=cmd_publish)

    p_ver = sub.add_parser("verify", help="wait for peer and compute the handshake")
    add_common(p_ver)
    p_ver.set_defaults(func=cmd_verify)

    p_run = sub.add_parser("run", help="publish then verify (normal use)")
    add_common(p_run)
    p_run.set_defaults(func=cmd_run)

    return parser


def main() -> int:
    args = build_parser().parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

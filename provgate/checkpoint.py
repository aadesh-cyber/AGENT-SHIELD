"""
checkpoint.py
-------------
A small, separately signed file that pins the log's length and head:

  {"log_file", "entry_count", "head_hash", "created", "sig"}

Without it, deleting the LAST entries of a log leaves a shorter log that
still verifies. With it, verify knows how many entries must exist and what
the last one's hash must be.

Store the checkpoint somewhere other than the log (later: RFC 3161
timestamp it, so even the key holder cannot backdate a shorter history).
"""
import datetime as dt, json
from pathlib import Path
from cryptography.exceptions import InvalidSignature
from provgate.proof_log import canonical, GENESIS


def _head(log_path: Path):
    lines = [l for l in Path(log_path).read_bytes().split(b"\n") if l]
    if not lines:
        return 0, GENESIS
    return len(lines), json.loads(lines[-1])["hash"]


def write_checkpoint(log_path, key, out_path):
    count, head = _head(log_path)
    body = {"log_file": Path(log_path).name, "entry_count": count, "head_hash": head,
            "created": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")}
    body["sig"] = key.sign(canonical(body)).hex()
    Path(out_path).write_bytes(canonical(body) + b"\n")
    return body


def check_checkpoint(cp_path, pub, entry_hashes: list):
    """entry_hashes: hashes of the entries that passed log verification, in order."""
    try:
        cp = json.loads(Path(cp_path).read_bytes())
        sig = bytes.fromhex(cp.pop("sig"))
        pub.verify(sig, canonical(cp))
    except (ValueError, KeyError, InvalidSignature):
        return False, "checkpoint: signature invalid or file altered"
    n, head = cp["entry_count"], cp["head_hash"]
    have = len(entry_hashes)
    if have < n:
        gone = f"entry {have}" if n - have == 1 else f"entries {have}..{n-1}"
        return False, f"entries missing: checkpoint says {n} entries, log has {have} ({gone} deleted)"
    if n and entry_hashes[n - 1] != head:
        return False, f"checkpoint head hash does not match entry {n-1}"
    if have > n:
        return True, f"checkpoint covers first {n} entries; {have-n} newer entries not yet checkpointed"
    return True, f"checkpoint matches: {n} entries, head {head[:16]}..."

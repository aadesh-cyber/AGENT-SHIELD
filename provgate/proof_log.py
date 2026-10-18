"""
proof_log.py
------------
Append-only JSON-lines proof log. Each line is one record:

  {"seq", "ts", "type", "payload", "prev_hash", "hash", "sig"}

  hash = SHA-256 of the canonical JSON of the record WITHOUT hash/sig
  sig  = Ed25519 signature over the 32 hash bytes (hex)
  prev_hash links each record to the one before ("0"*64 for the first).

Every line is written in canonical form (sorted keys, no spaces, ASCII,
LF line endings), so verify can demand byte-exactness: changing ANY byte
of the file makes verification fail at the entry containing that byte.
"""
import datetime as dt, hashlib, json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

GENESIS = "0" * 64


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def record_hash(rec: dict) -> str:
    body = {k: v for k, v in rec.items() if k not in ("hash", "sig")}
    return hashlib.sha256(canonical(body)).hexdigest()


def load_or_create_keys(key_dir: Path):
    """DEMO ONLY: private key stored unencrypted next to the log."""
    key_dir.mkdir(parents=True, exist_ok=True)
    priv_p, pub_p = key_dir / "signing_key.pem", key_dir / "public_key.pem"
    if priv_p.exists():
        key = serialization.load_pem_private_key(priv_p.read_bytes(), password=None)
    else:
        key = Ed25519PrivateKey.generate()
        priv_p.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                           serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    pub_p.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                      serialization.PublicFormat.SubjectPublicKeyInfo))
    return key, pub_p


class ProofLog:
    def __init__(self, path: Path, key: Ed25519PrivateKey, fresh: bool = True):
        self.path, self.key = Path(path), key
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if fresh or not self.path.exists():
            self.path.write_bytes(b"")
        self.seq, self.prev = 0, GENESIS
        for line in self.path.read_bytes().split(b"\n"):
            if line:
                rec = json.loads(line)
                self.seq, self.prev = rec["seq"] + 1, rec["hash"]

    def append(self, rtype: str, payload: dict) -> dict:
        rec = {"seq": self.seq, "ts": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
               "type": rtype, "payload": payload, "prev_hash": self.prev}
        rec["hash"] = record_hash(rec)
        rec["sig"] = self.key.sign(bytes.fromhex(rec["hash"])).hex()
        with self.path.open("ab") as f:
            f.write(canonical(rec) + b"\n")
        self.seq, self.prev = self.seq + 1, rec["hash"]
        return rec

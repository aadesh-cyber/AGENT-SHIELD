"""
verify.py -- check a proof log (and optionally its checkpoint).

    python -m provgate.verify runs\\demo\\proof_log.jsonl --pubkey runs\\keys\\public_key.pem --checkpoint runs\\demo\\checkpoint.json

Exit code 0 = VALID, 1 = INVALID (names the first bad entry and why).
Per line: valid JSON -> byte-exact canonical form -> seq order ->
prev_hash link -> recomputed hash -> Ed25519 signature.
With --checkpoint: the signed checkpoint must be intact, and the log must
contain at least entry_count entries ending in the checkpoint's head hash
(this catches deletion of the LAST entries).
With --tsa (Step 7): checkpoint.tsr must be a valid RFC 3161 token for the
exact checkpoint bytes, signed by the TSA certificate in tsa/; prints the
trusted time.
"""
import argparse, json, sys
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from provgate.proof_log import canonical, record_hash, GENESIS


def _verify_entries(log_path, pub):
    data = Path(log_path).read_bytes()
    if data and not data.endswith(b"\n"):
        data += b"\n"
    lines = data.split(b"\n")[:-1]
    prev, hashes = GENESIS, []
    for i, line in enumerate(lines):
        where = f"entry {i} (line {i+1})"
        try:
            rec = json.loads(line)
        except (ValueError, UnicodeDecodeError):
            return False, f"{where}: not valid JSON (bytes altered)", hashes
        if not isinstance(rec, dict) or not {"seq", "prev_hash", "hash", "sig"} <= rec.keys():
            return False, f"{where}: missing fields", hashes
        try:
            if canonical(rec) != line:
                return False, f"{where}: bytes altered (not canonical form)", hashes
        except (TypeError, ValueError):
            return False, f"{where}: bytes altered", hashes
        if rec["seq"] != i:
            return False, f"{where}: sequence break (expected seq {i}, found {rec['seq']})", hashes
        if rec["prev_hash"] != prev:
            return False, f"{where}: chain broken (prev_hash does not match entry {i-1})", hashes
        if record_hash(rec) != rec["hash"]:
            return False, f"{where}: content altered (hash mismatch)", hashes
        try:
            pub.verify(bytes.fromhex(rec["sig"]), bytes.fromhex(rec["hash"]))
        except (InvalidSignature, ValueError):
            return False, f"{where}: bad signature", hashes
        prev = rec["hash"]
        hashes.append(prev)
    return True, f"{len(lines)} entries verified; head hash {prev}", hashes


def verify_log(log_path, pubkey_path, checkpoint_path=None):
    pub = serialization.load_pem_public_key(Path(pubkey_path).read_bytes())
    ok, msg, hashes = _verify_entries(log_path, pub)
    if not ok or checkpoint_path is None:
        return ok, msg
    from provgate.checkpoint import check_checkpoint
    ok2, msg2 = check_checkpoint(checkpoint_path, pub, hashes)
    return ok2, f"{msg} | {msg2}"


def main(argv=None):
    ap = argparse.ArgumentParser(description="Verify an AgentShield proof log.")
    ap.add_argument("log")
    ap.add_argument("--pubkey", default=str(Path("runs") / "keys" / "public_key.pem"))
    ap.add_argument("--checkpoint", default=None, help="signed checkpoint.json for this log")
    ap.add_argument("--tsa", action="store_true",
                    help="also check the RFC 3161 timestamp (checkpoint.tsr next to the checkpoint)")
    ap.add_argument("--tsr", default=None, help="token file (default: <checkpoint>.tsr)")
    ap.add_argument("--tsa-cert", default=None, help="TSA certificate (default: tsa/tsa.crt)")
    ap.add_argument("--tsa-ca", default=None, help="TSA root certificate (default: tsa/cacert.pem)")
    a = ap.parse_args(argv)
    if a.tsa and a.checkpoint is None:
        ap.error("--tsa needs --checkpoint")
    ok, msg = verify_log(a.log, a.pubkey, a.checkpoint)
    if ok and a.tsa:
        from provgate import timestamp as ts
        ok, m3 = ts.verify_timestamp(a.checkpoint, a.tsr, a.tsa_cert or ts.DEFAULT_TSA_CERT,
                                     a.tsa_ca or ts.DEFAULT_CA_CERT)
        msg = f"{msg} | {m3}"
    print(("VALID: " if ok else "INVALID: ") + msg)
    if a.checkpoint is None:
        print("note: no --checkpoint given, so deletion of the LAST entries cannot be detected.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

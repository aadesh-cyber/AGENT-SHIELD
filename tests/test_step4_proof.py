"""Step 4 done-when test: signed proof log, reviewer step, verify, byte-level tamper detection."""
import sys, pathlib, json, datetime as dt, shutil
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from provgate.gate import Gate, ALLOW, HOLD, APPROVE, REJECT
from provgate.world_tools import World
from provgate.proof_log import ProofLog, load_or_create_keys
from provgate.verify import verify_log

OUT = ROOT / "runs" / "step4"
if OUT.exists(): shutil.rmtree(OUT)
key, pub = load_or_create_keys(OUT)
LOG = OUT / "proof_log.jsonl"
checks = 0
def check(cond, msg):
    global checks; checks += 1
    print(("ok   " if cond else "FAIL ") + msg); assert cond, msg

w = World(today=dt.date(2026, 10, 18))
g = Gate(w, log=ProofLog(LOG, key))

g.call("read_inbox", {})
a = g.call("make_payment", {"supplier_name": "Harbour Supplies", "sort_code": "00-00-01",
           "account_number": "00000001", "amount": 1250.00, "invoice_ref": "INV-7781"})
check(a.decision == ALLOW and len(w.payments) == 1, "(a) £1,250 paid")
before = dict(w.suppliers["Bright Office Ltd"])
b = g.call("change_bank_details", {"supplier_name": "Bright Office Ltd",
           "sort_code": "00-00-99", "account_number": "99999999"})
check(b.decision == HOLD and w.suppliers["Bright Office Ltd"] == before, "(b) HOLD, ledger unchanged")

try:
    g.review(b.request_id, "j.patel@examplewealth (AP Supervisor)", REJECT, ""); check(False, "empty note refused")
except ValueError:
    check(True, "review with empty note is refused")
out = g.review(b.request_id, "j.patel@examplewealth (AP Supervisor)", REJECT, "Phoned supplier: not genuine")
check("not executed" in out and w.suppliers["Bright Office Ltd"] == before, "(c) REJECT -> nothing changed")
check(not g.queue(), "(c) reviewer queue empty after decision")

recs = [json.loads(l) for l in LOG.read_bytes().splitlines()]
types = [r["type"] for r in recs]
check(types == ["decision", "decision", "executed", "decision", "review"], f"record sequence {types}")
rev = recs[-1]["payload"]
check(rev["args"]["account_number"] == {"value": "99999999", "source": "email:EM-2001", "trust": "untrusted"},
      "review record: argument carries its source label")
check(rev["rules"] == ["R1", "R1"] and "R1: account_number '99999999' came from email:EM-2001 (untrusted)"
      in rev["reasons"], "review record: rule IDs and reasons")
check(rev["reviewer"].startswith("j.patel") and rev["review_decision"] == REJECT
      and rev["note"] == "Phoned supplier: not genuine", "review record: reviewer, decision, note")
check(recs[2]["payload"]["tool"] == "make_payment" and recs[1]["payload"]["rules"] == ["OK"],
      "allowed payment logged with rule 'OK' and an 'executed' record")
check(recs[0]["payload"]["args"] == {} and recs[0]["payload"]["decision"] == ALLOW, "read-only call logged too")

ok, msg = verify_log(LOG, pub)
check(ok, f"(d) verify untouched log -> VALID ({msg[:30]}...)")

# (e) flip EVERY byte, one at a time: verify must fail at the entry containing that byte.
data = LOG.read_bytes()
starts, pos = [], 0
for line in data.split(b"\n")[:-1]:
    starts.append(pos); pos += len(line) + 1
def entry_of(i): return max(k for k, s in enumerate(starts) if s <= i)
tmp = OUT / "tampered.jsonl"
wrong = 0
for i in range(len(data)):
    b2 = bytearray(data); b2[i] = ord("x") if data[i] != ord("x") else ord("y")
    tmp.write_bytes(bytes(b2))
    ok2, msg2 = verify_log(tmp, pub)
    if ok2 or f"entry {entry_of(i)} " not in msg2:
        wrong += 1
        if wrong <= 3: print(f"     byte {i}: {ok2} {msg2}")
check(wrong == 0, f"(e) all {len(data)} single-byte edits detected at the exact entry")

# whole-line deletion and reordering
lines = data.split(b"\n")[:-1]
tmp.write_bytes(b"\n".join(lines[:2] + lines[3:]) + b"\n")
ok3, m3 = verify_log(tmp, pub); check(not ok3 and "entry 2" in m3, f"deleting entry 2 detected: {m3}")
tmp.write_bytes(b"\n".join([lines[1], lines[0]] + lines[2:]) + b"\n")
ok4, m4 = verify_log(tmp, pub); check(not ok4 and "entry 0" in m4, f"swapping entries detected: {m4}")
# re-signing with a DIFFERENT key fails against our public key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
w5 = World(today=dt.date(2026, 10, 18)); g5 = Gate(w5, log=ProofLog(tmp, Ed25519PrivateKey.generate()))
g5.call("read_inbox", {})
ok5, m5 = verify_log(tmp, pub); check(not ok5 and "bad signature" in m5, f"forged key detected: {m5}")
tmp.unlink()
print(f"STEP 4 OK: {checks} checks passed")

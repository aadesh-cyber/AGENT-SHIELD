"""
Step 7 'done when' test: RFC 3161 timestamp on the checkpoint.

By default this uses a TEST Time-Stamp Authority generated on the fly and
served on 127.0.0.1 (no internet needed). Its keys/certificates live only in
memory and a temp folder and are never used outside this test.

Optional live FreeTSA check (needs internet): set AGENTSHIELD_LIVE_TSA=1 first.
Run:  python tests\\test_step7_timestamp.py
"""
import datetime as dt, hashlib, http.server, io, os, shutil, sys, tempfile, threading
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from asn1crypto import tsp, cms, algos, x509 as ax509, core
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from provgate import timestamp as ts
from provgate.proof_log import ProofLog, load_or_create_keys
from provgate.checkpoint import write_checkpoint
from provgate.verify import main as verify_main

passed = 0
def check(cond, msg):
    global passed
    if not cond:
        print(f"FAIL {msg}"); sys.exit(1)
    passed += 1; print(f"ok   {msg}")

tmp = Path(tempfile.mkdtemp(prefix="agentshield_tsa_"))

# ------------------------------------------------------------ a test TSA
def make_ca_and_tsa(name):
    now = dt.datetime.now(dt.timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{name} Root")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(1)
          .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=30))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .sign(ca_key, hashes.SHA256()))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
            .issuer_name(ca_name).public_key(key.public_key()).serial_number(2)
            .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=30))
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
            .sign(ca_key, hashes.SHA256()))
    d = tmp / name.replace(" ", "_"); d.mkdir()
    (d / "tsa.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (d / "cacert.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    return key, cert, d

def make_response(req_der, key, cert):
    """Build a real RFC 3161 TimeStampResp signed by the test TSA."""
    req = tsp.TimeStampReq.load(req_der)
    info = tsp.TSTInfo({
        "version": 1, "policy": "1.2.3.4.1", "message_imprint": req["message_imprint"],
        "serial_number": 1, "gen_time": dt.datetime.now(dt.timezone.utc).replace(microsecond=0),
        "nonce": req["nonce"],
    })
    info_der = info.dump()
    acert = ax509.Certificate.load(cert.public_bytes(serialization.Encoding.DER))
    signed_attrs = cms.CMSAttributes([
        cms.CMSAttribute({"type": "content_type", "values": ["tst_info"]}),
        cms.CMSAttribute({"type": "message_digest", "values": [hashlib.sha256(info_der).digest()]}),
    ])
    sig = key.sign(signed_attrs.dump(), padding.PKCS1v15(), hashes.SHA256())
    sd = cms.SignedData({
        "version": "v3",
        "digest_algorithms": [{"algorithm": "sha256"}],
        "encap_content_info": {"content_type": "tst_info", "content": core.ParsableOctetString(info_der)},
        "certificates": [acert],
        "signer_infos": [{
            "version": "v1",
            "sid": cms.SignerIdentifier({"issuer_and_serial_number": {
                "issuer": acert.issuer, "serial_number": acert.serial_number}}),
            "digest_algorithm": {"algorithm": "sha256"},
            "signed_attrs": signed_attrs,
            "signature_algorithm": {"algorithm": "rsassa_pkcs1v15"},
            "signature": sig,
        }],
    })
    return tsp.TimeStampResp({"status": {"status": "granted"},
                              "time_stamp_token": {"content_type": "signed_data", "content": sd}}).dump()

key, cert, good_dir = make_ca_and_tsa("Test TSA")
_, _, other_dir = make_ca_and_tsa("Other TSA")
seen_requests = []

class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        seen_requests.append(body)
        out = make_response(body, key, cert)
        self.send_response(200); self.send_header("Content-Type", "application/timestamp-reply")
        self.send_header("Content-Length", str(len(out))); self.end_headers(); self.wfile.write(out)
    def log_message(self, *a): pass

srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
threading.Thread(target=srv.serve_forever, daemon=True).start()
TEST_URL = f"http://127.0.0.1:{srv.server_port}/tsr"
DEAD_URL = "http://127.0.0.1:9/tsr"          # nothing listens here = "offline"
CERT, CA = good_dir / "tsa.crt", good_dir / "cacert.pem"

# ------------------------------------------------------------ a real signed log + checkpoint
key_ed, _ = load_or_create_keys(tmp / "keys")
pub_path = tmp / "keys" / "public_key.pem"
log, cp = tmp / "proof_log.jsonl", tmp / "checkpoint.json"
pl = ProofLog(log, key_ed)
pl.append("note", {"text": "hello"}); pl.append("note", {"text": "world"})
write_checkpoint(log, key_ed, cp)
log_before = log.read_bytes()

# 1. stamping
status, msg = ts.stamp_checkpoint(cp, url=TEST_URL)
check(status == "stamped" and ts.tsr_path_for(cp).exists(), f"checkpoint stamped -> checkpoint.tsr saved ({msg})")
check(ts.tsr_path_for(cp).name == "checkpoint.tsr" and ts.tsr_path_for(cp).parent == cp.parent,
      "token saved as checkpoint.tsr next to checkpoint.json")

# 2. only the hash was sent
req = tsp.TimeStampReq.load(seen_requests[-1])
check(req["message_imprint"]["hashed_message"].native == hashlib.sha256(cp.read_bytes()).digest(),
      "request contains the SHA-256 of checkpoint.json")
check(len(seen_requests[-1]) < 120 and b"hello" not in seen_requests[-1] and b"head_hash" not in seen_requests[-1],
      f"request is tiny ({len(seen_requests[-1])} bytes) and holds no log or checkpoint contents")
check(log.read_bytes() == log_before, "proof log unchanged by stamping")

# 3. verify OK
ok, msg = ts.verify_timestamp(cp, tsa_cert=CERT, ca_cert=CA)
check(ok and "stamped at" in msg and "Test TSA" in msg, f"valid token verifies: {msg}")

def run_verify(*extra):
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = verify_main([str(log), "--pubkey", str(pub_path), "--checkpoint", str(cp), *extra])
    return code, buf.getvalue()

code, out = run_verify("--tsa", "--tsa-cert", str(CERT), "--tsa-ca", str(CA))
check(code == 0 and "VALID" in out and "stamped at" in out, "verify --tsa: exit 0, prints trusted time")
code, out = run_verify()
check(code == 0 and "timestamp" not in out, "verify without --tsa behaves as before")

# 4. failures, each with a clear reason
cp_good, tsr_good = cp.read_bytes(), ts.tsr_path_for(cp).read_bytes()
def restore():
    cp.write_bytes(cp_good); ts.tsr_path_for(cp).write_bytes(tsr_good)

# 4a. key holder rewrites + re-signs the checkpoint -> old token no longer matches
import time; time.sleep(1.1)
write_checkpoint(log, key_ed, cp)             # new 'created' time = new bytes, still validly signed
ts.tsr_path_for(cp).write_bytes(tsr_good)
code, out = run_verify("--tsa", "--tsa-cert", str(CERT), "--tsa-ca", str(CA))
check(code == 1 and "hash mismatch" in out, "re-signed checkpoint with old token -> INVALID: hash mismatch")
restore()

# 4b. token signature damaged (flip one byte of the RSA signature = last bytes of file)
bad = bytearray(tsr_good); bad[-5] ^= 1
ts.tsr_path_for(cp).write_bytes(bytes(bad))
ok, msg = ts.verify_timestamp(cp, tsa_cert=CERT, ca_cert=CA)
check(not ok and "signature is INVALID" in msg, f"damaged signature -> {msg}")
restore()

# 4c. time inside the token changed -> message-digest mismatch
gt = tsp.TimeStampResp.load(tsr_good)["time_stamp_token"]["content"]["encap_content_info"]["content"].parsed["gen_time"].dump()
i = tsr_good.find(gt)
bad = bytearray(tsr_good); bad[i + 5] ^= 1                 # change a digit of the year
ts.tsr_path_for(cp).write_bytes(bytes(bad))
ok, msg = ts.verify_timestamp(cp, tsa_cert=CERT, ca_cert=CA)
check(not ok and "altered" in msg, f"edited time in token -> {msg}")
restore()

# 4d. checked against a different TSA's certificate
ok, msg = ts.verify_timestamp(cp, tsa_cert=other_dir / "tsa.crt", ca_cert=other_dir / "cacert.pem")
check(not ok and "different TSA certificate" in msg, f"wrong TSA certificate -> {msg}")

# 4e. right TSA cert but wrong root
ok, msg = ts.verify_timestamp(cp, tsa_cert=CERT, ca_cert=other_dir / "cacert.pem")
check(not ok and "not signed by" in msg, f"TSA cert not issued by given root -> {msg}")

# 4f. no token / garbage token
ts.tsr_path_for(cp).unlink()
code, out = run_verify("--tsa", "--tsa-cert", str(CERT), "--tsa-ca", str(CA))
check(code == 1 and "no token found" in out, "missing checkpoint.tsr -> INVALID: no token found")
ts.tsr_path_for(cp).write_bytes(b"not a token")
ok, msg = ts.verify_timestamp(cp, tsa_cert=CERT, ca_cert=CA)
check(not ok and "damaged" in msg, f"garbage token -> {msg}")
restore()

# 5. offline: skipped, nothing faked, stale token removed
status, msg = ts.stamp_checkpoint(cp, url=DEAD_URL, timeout=2)
check(status == "skipped" and "offline" in msg, f"offline -> {msg}")
check(not ts.tsr_path_for(cp).exists(), "offline -> no checkpoint.tsr written (old one removed, never faked)")
status, _ = ts.stamp_checkpoint(cp, url="off")
check(status == "skipped" and not ts.tsr_path_for(cp).exists(), "AGENTSHIELD_TSA_URL=off disables stamping")

# 6. the demo still runs offline
os.environ["AGENTSHIELD_TSA_URL"] = DEAD_URL
import demo
buf = io.StringIO()
with redirect_stdout(buf):
    rc = demo.main(["--mode", "scripted", "--no-pause"], inp=lambda *_: "")
out = buf.getvalue()
check(rc == 0 and "timestamp skipped (offline)" in out, "demo offline: prints 'timestamp skipped (offline)' and finishes OK")
check(not (ROOT / "runs" / "scripted" / "checkpoint.tsr").exists(), "demo offline: no token file")

# 7. the demo with a (test) TSA reachable
os.environ["AGENTSHIELD_TSA_URL"] = TEST_URL
orig = ts.DEFAULT_TSA_CERT, ts.DEFAULT_CA_CERT
ts.verify_timestamp.__defaults__ = (None, CERT, CA)
buf = io.StringIO()
with redirect_stdout(buf):
    rc = demo.main(["--mode", "scripted", "--no-pause"], inp=lambda *_: "")
out = buf.getvalue()
check(rc == 0 and "Timestamp: timestamp valid: stamped at" in out, "demo online: prints the trusted time")
check((ROOT / "runs" / "scripted" / "checkpoint.tsr").exists(), "demo online: checkpoint.tsr next to checkpoint.json")

# 8. web page 'Prove it' panel
from webapp import create_app
app = create_app(root=tmp / "web"); app.testing = True
c = app.test_client(); tok = app.config["DEMO_TOKEN"]
c.post("/run/scripted", data={"token": tok})
html = c.get("/").get_data(as_text=True)
check("<b>Timestamp:</b> stamped at" in html and "Test TSA" in html, "web page: 'Timestamp: stamped at <time> by Test TSA'")
os.environ["AGENTSHIELD_TSA_URL"] = DEAD_URL
c.post("/run/scripted", data={"token": tok})
html = c.get("/").get_data(as_text=True)
check("<b>Timestamp:</b> not stamped" in html, "web page offline: 'Timestamp: not stamped'")
ts.verify_timestamp.__defaults__ = (None,) + orig
os.environ.pop("AGENTSHIELD_TSA_URL")

# 9. stored FreeTSA certificates are present and chain correctly
fc = x509.load_pem_x509_certificate((ROOT / "tsa" / "tsa.crt").read_bytes())
fca = x509.load_pem_x509_certificate((ROOT / "tsa" / "cacert.pem").read_bytes())
fc.verify_directly_issued_by(fca)
check(ExtendedKeyUsageOID.TIME_STAMPING in fc.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value,
      "tsa/tsa.crt is issued by tsa/cacert.pem and allowed to timestamp")

# 10. optional live FreeTSA
if os.environ.get("AGENTSHIELD_LIVE_TSA") == "1":
    restore()
    status, msg = ts.stamp_checkpoint(cp, url=ts.DEFAULT_TSA_URL, timeout=20)
    check(status == "stamped", f"LIVE FreeTSA: {msg}")
    ok, msg = ts.verify_timestamp(cp)
    check(ok and "freetsa" in msg.lower(), f"LIVE FreeTSA verify: {msg}")
else:
    print("note: live FreeTSA check skipped (set AGENTSHIELD_LIVE_TSA=1 to run it)")

srv.shutdown()
shutil.rmtree(tmp, ignore_errors=True)
print(f"STEP 7 OK: {passed} checks passed")

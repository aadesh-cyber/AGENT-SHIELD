"""
timestamp.py -- Step 7: RFC 3161 trusted timestamp on the checkpoint.

What it does, in plain words
  1. Take the SHA-256 hash of checkpoint.json (32 bytes). Nothing else leaves
     this computer: no log entries, no checkpoint contents, only the hash.
  2. Send that hash to a public Time-Stamp Authority (TSA, default FreeTSA).
  3. The TSA signs "this hash existed at <time>" and sends back a token.
  4. Save the token as checkpoint.tsr next to checkpoint.json.

Why: whoever holds OUR signing key could rewrite the log and the checkpoint.
They cannot get the TSA to sign an old time for the new checkpoint, so a
rewritten checkpoint will not match the stamped one.

Library: asn1crypto (parse/build the RFC 3161 + CMS structures) plus
cryptography (check signatures and certificates). Both are widely used,
pure Python / well-maintained, and we already depend on cryptography.

If the TSA cannot be reached we return status "skipped" and write NOTHING.
We never make up a timestamp.
"""
import hashlib, os, secrets, urllib.error, urllib.request
from pathlib import Path

from asn1crypto import tsp, cms, core, algos
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec

DEFAULT_TSA_URL = "https://freetsa.org/tsr"
TSA_DIR = Path(__file__).resolve().parents[1] / "tsa"
DEFAULT_TSA_CERT = TSA_DIR / "tsa.crt"       # the certificate that signs tokens
DEFAULT_CA_CERT = TSA_DIR / "cacert.pem"     # the root that issued it

_HASHES = {"sha1": hashes.SHA1, "sha224": hashes.SHA224, "sha256": hashes.SHA256,
           "sha384": hashes.SHA384, "sha512": hashes.SHA512}


def tsa_url():
    """AGENTSHIELD_TSA_URL overrides the default; set it to 'off' to disable."""
    return os.environ.get("AGENTSHIELD_TSA_URL", DEFAULT_TSA_URL)


def tsr_path_for(cp_path) -> Path:
    return Path(cp_path).with_suffix(".tsr")


# --------------------------------------------------------------------- request
def build_request(digest: bytes, nonce: int) -> bytes:
    return tsp.TimeStampReq({
        "version": 1,
        "message_imprint": {"hash_algorithm": {"algorithm": "sha256"}, "hashed_message": digest},
        "nonce": nonce,
        "cert_req": True,
    }).dump()


def stamp_checkpoint(cp_path, url=None, timeout=10):
    """Returns (status, message). status is 'stamped', 'skipped' or 'error'.
    Any old checkpoint.tsr is removed first: it belongs to an older checkpoint."""
    url = url or tsa_url()
    out = tsr_path_for(cp_path)
    out.unlink(missing_ok=True)
    if url.lower() == "off":
        return "skipped", "timestamp skipped (disabled)"
    digest = hashlib.sha256(Path(cp_path).read_bytes()).digest()
    nonce = secrets.randbits(63)
    req = urllib.request.Request(url, data=build_request(digest, nonce),
                                 headers={"Content-Type": "application/timestamp-query"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read()
    except (urllib.error.URLError, OSError) as e:      # no network, DNS, timeout, HTTP error
        return "skipped", f"timestamp skipped (offline): {getattr(e, 'reason', e)}"
    # Basic sanity before saving: right status, our hash, our nonce.
    try:
        resp = tsp.TimeStampResp.load(body)
        status = resp["status"]["status"].native
        if status not in ("granted", "granted_with_mods"):
            return "error", f"TSA refused the request (status: {status})"
        info = resp["time_stamp_token"]["content"]["encap_content_info"]["content"].parsed
        if info["message_imprint"]["hashed_message"].native != digest:
            return "error", "TSA reply is for a different hash; not saved"
        if info["nonce"].native != nonce:
            return "error", "TSA reply nonce does not match our request; not saved"
        gen_time = info["gen_time"].native
    except Exception as e:
        return "error", f"TSA reply could not be read ({type(e).__name__}); not saved"
    out.write_bytes(body)
    return "stamped", f"timestamped by {url} at {gen_time.isoformat()}"


# --------------------------------------------------------------------- verify
def _verify_sig(pub, sig, data, sig_alg, digest_alg):
    h = _HASHES[digest_alg]()
    if isinstance(pub, rsa.RSAPublicKey):
        if sig_alg == "rsassa_pss":
            raise ValueError("RSA-PSS tokens not supported")
        pub.verify(sig, data, padding.PKCS1v15(), h)
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        pub.verify(sig, data, ec.ECDSA(h))
    else:
        raise ValueError("unsupported TSA key type")


def verify_timestamp(cp_path, tsr_path=None, tsa_cert=DEFAULT_TSA_CERT, ca_cert=DEFAULT_CA_CERT):
    """Returns (ok, message). On success the message includes the trusted time."""
    tsr_path = Path(tsr_path) if tsr_path else tsr_path_for(cp_path)
    if not tsr_path.exists():
        return False, f"timestamp: no token found ({tsr_path.name}); checkpoint was not stamped"
    try:
        cert = x509.load_pem_x509_certificate(Path(tsa_cert).read_bytes())
        ca = x509.load_pem_x509_certificate(Path(ca_cert).read_bytes())
    except (OSError, ValueError) as e:
        return False, f"timestamp: cannot load TSA certificate ({e})"

    # 1. Read the token.
    try:
        resp = tsp.TimeStampResp.load(tsr_path.read_bytes())
        if resp["status"]["status"].native not in ("granted", "granted_with_mods"):
            return False, "timestamp: token status is not 'granted'"
        token = resp["time_stamp_token"]
        if token["content_type"].native != "signed_data":
            return False, "timestamp: token is not a signed CMS structure"
        sd = token["content"]
        eci = sd["encap_content_info"]
        if eci["content_type"].native != "tst_info":
            return False, "timestamp: token does not contain timestamp info"
        tst_der = eci["content"].contents      # exact bytes the TSA hashed
        info = eci["content"].parsed
        si = sd["signer_infos"][0]
    except Exception as e:
        return False, f"timestamp: token file is damaged or not RFC 3161 ({type(e).__name__})"

    # 2. Does the token cover THIS checkpoint?
    mi = info["message_imprint"]
    alg = mi["hash_algorithm"]["algorithm"].native
    if alg not in _HASHES:
        return False, f"timestamp: unsupported hash algorithm {alg}"
    cp_hash = hashlib.new(alg, Path(cp_path).read_bytes()).digest()
    if mi["hashed_message"].native != cp_hash:
        return False, ("timestamp: hash mismatch: the token was issued for a different "
                       "checkpoint (checkpoint.json changed after it was stamped)")

    # 3. Signed attributes must bind the TSTInfo: content-type + message-digest.
    digest_alg = si["digest_algorithm"]["algorithm"].native
    if digest_alg not in _HASHES or not si["signed_attrs"].native:
        return False, "timestamp: token signature format not supported"
    attrs = {a["type"].native: a["values"][0] for a in si["signed_attrs"]}
    if attrs.get("content_type") is None or attrs["content_type"].native != "tst_info":
        return False, "timestamp: signed content-type attribute missing or wrong"
    if attrs.get("message_digest") is None or \
            attrs["message_digest"].native != hashlib.new(digest_alg, tst_der).digest():
        return False, "timestamp: timestamp info was altered (message-digest mismatch)"

    # 4. Was it signed by OUR pinned TSA certificate?
    sid = si["sid"]
    if sid.name == "issuer_and_serial_number":
        same = (sid.chosen["serial_number"].native == cert.serial_number and
                sid.chosen["issuer"].dump() == cert.issuer.public_bytes())
    else:
        try:
            ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
        except x509.ExtensionNotFound:
            ski = None
        same = sid.chosen.native == ski
    if not same:
        return False, "timestamp: token was signed by a different TSA certificate than tsa/tsa.crt"
    signed_bytes = b"\x31" + si["signed_attrs"].dump()[1:]   # [0] IMPLICIT -> SET, per RFC 5652
    try:
        _verify_sig(cert.public_key(), si["signature"].native, signed_bytes,
                    si["signature_algorithm"].signature_algo, digest_alg)
    except (InvalidSignature, ValueError, KeyError) as e:
        return False, f"timestamp: TSA signature is INVALID ({str(e) or 'signature does not match tsa/tsa.crt'})"

    # 5. Is the TSA certificate genuine, allowed to timestamp, and valid at that time?
    try:
        cert.verify_directly_issued_by(ca)
    except (InvalidSignature, ValueError, TypeError):
        return False, "timestamp: tsa/tsa.crt is not signed by tsa/cacert.pem"
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if x509.oid.ExtendedKeyUsageOID.TIME_STAMPING not in eku:
            raise x509.ExtensionNotFound("", None)
    except x509.ExtensionNotFound:
        return False, "timestamp: certificate is not allowed to issue timestamps"
    gen_time = info["gen_time"].native
    if not (cert.not_valid_before_utc <= gen_time <= cert.not_valid_after_utc):
        return False, "timestamp: trusted time is outside the TSA certificate's validity"

    tsa_name = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    tsa_name = tsa_name[0].value if tsa_name else cert.subject.rfc4514_string()
    return True, f"timestamp valid: stamped at {gen_time.isoformat()} by {tsa_name}"

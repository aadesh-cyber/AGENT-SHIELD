# Step 7 — RFC 3161 trusted timestamp on the checkpoint

**What changed:** after each checkpoint is written, AgentShield sends the checkpoint's
**SHA-256 hash only** (32 bytes, nothing else) to a public Time-Stamp Authority
(default FreeTSA). The signed reply is saved as `checkpoint.tsr` next to `checkpoint.json`.

**Why:** whoever holds our signing key could rewrite the log *and* re-sign the
checkpoint. They cannot get FreeTSA to sign the new checkpoint with an old date. So a
rewritten checkpoint no longer matches its stamped token.

## Files
- NEW `provgate/timestamp.py`: stamp + verify (asn1crypto + cryptography)
- NEW `tsa/tsa.crt`, `tsa/cacert.pem`, `tsa/SOURCE.md`: FreeTSA certificates and where they came from
- NEW `tests/test_step7_timestamp.py`
- `provgate/verify.py`: new `--tsa` option (plus `--tsr`, `--tsa-cert`, `--tsa-ca`)
- `demo.py`: stamps after the checkpoint and prints the trusted time, or "timestamp skipped (offline)"
- `webapp.py`: stamps after each checkpoint; "Timestamp:" line in the Prove it panel
- `tests/test_step5_demo.py`: the "same output twice" check now also ignores timestamp lines (the time changes every run)
- `requirements.txt`: + asn1crypto

Gate, rules, proof log and checkpoint code are **unchanged**.

## Settings
- `AGENTSHIELD_TSA_URL`: use a different TSA. Set it to `off` to turn stamping off.

## Commands (PowerShell)
```powershell
py -3.15 -m pip install -r requirements.txt
py -3.15 tests\test_step7_timestamp.py
$env:AGENTSHIELD_LIVE_TSA="1"; py -3.15 tests\test_step7_timestamp.py; Remove-Item Env:AGENTSHIELD_LIVE_TSA
py -3.15 demo.py --no-pause
py -3.15 -m provgate.verify runs\scripted\proof_log.jsonl --checkpoint runs\scripted\checkpoint.json --tsa
```

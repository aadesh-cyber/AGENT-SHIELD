# tsa/ — Time-Stamp Authority certificates (public, not secret)

| File | What it is | Downloaded from |
|---|---|---|
| `tsa.crt` | FreeTSA's signing certificate (the one that signs our tokens) | https://freetsa.org/files/tsa.crt |
| `cacert.pem` | FreeTSA's root CA (issued `tsa.crt`) | https://freetsa.org/files/cacert.pem |

Downloaded on 2026-10-18 over HTTPS.

SHA-256 fingerprints (check them against https://freetsa.org/index_en.php):
- `tsa.crt`    32:E8:41:A9:5C:C1:16:41:01:FF:DE:41:29:8E:F2:FC:75:C1:C4:37:2E:F0:95:E8:8A:6B:BD:47:DF:B1:91:FC
  (valid 2026-02-15 to 2040-02-02, Extended Key Usage: Time Stamping, critical)
- `cacert.pem` A6:37:9E:7C:EC:C0:5F:AA:3C:BF:07:60:13:D7:45:E3:27:BB:BA:A3:8C:0B:9A:F2:24:69:D4:70:1D:18:AA:BC
  (valid 2016-03-13 to 2041-03-07)

Note: `tsa.crt` was re-issued by FreeTSA in Feb 2026. Tokens issued under an
older FreeTSA certificate will fail with "signed by a different TSA certificate".
If FreeTSA rotates again, download the new `tsa.crt`, check its fingerprint and
replace this file.

These are public certificates. No private keys live here.

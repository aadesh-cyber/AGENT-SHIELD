# AgentShield v0.3 - Step 6: the reviewer web page

A local web page over the SAME gate, proof log and verify code as `demo.py`.
It adds no decision logic. It runs only on your own computer (127.0.0.1).

## Run it (Windows, PowerShell, inside this folder)

```
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
$env:PYTHONUTF8=1
python tests\test_step6_web.py
python webapp.py
```

Then open **http://127.0.0.1:5000** in your browser. Press Ctrl+C in the terminal to stop.

**Done when:** the test prints `STEP 6 OK: 29 checks passed`, and the page opens.

## The 2-minute council demo on this page

1. **Run AP agent (scripted).** 4 actions: 3 allowed, 1 held. The £1,250 invoice is paid.
2. **Held for review.** REQ-004 shows each value, where it came from and its trust label, plus the R1 reasons in plain English. Supplier records show Bright Office is unchanged.
3. Type a note ("Phoned supplier on the number we hold: not genuine") and click **Reject**.
4. **Verify log**: VALID, checkpoint matches.
5. **Tamper test (on a copy)**: CAUGHT, with the exact entry named.
6. **Delete-last-entry test (on a copy)**: CAUGHT through the checkpoint.

**Run AP agent (real Claude)** uses your `.env` key and costs a few pence per run.

## Security notes (local demo)
- It listens on 127.0.0.1 only, so other computers can't reach it.
- Every button sends a secret per-run token, so another website can't press Approve for you.
- All text is HTML-escaped.
- There's no login yet; the reviewer types their name. Sign-in (SSO) and "you can't approve your own request" come later.
- `.env` and `runs/web/` are in `.gitignore`.

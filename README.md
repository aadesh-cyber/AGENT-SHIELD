                                                Agent_Shield

Stops AI agents from being tricked into moving money or data, and keeps signed proof of every decision.

AI agents now read emails, pay invoices and update supplier records. One convincing email can make an agent change a supplier's bank details, and the next payment goes to a criminal. AgentShield sits between the agent and the business tools. It checks where every value came from, holds risky actions for a named person to approve, and writes a tamper-evident, independently timestamped record that an auditor or insurer can check for themselves.
Status: working prototype (v0.4). All data is fictional. Not for production use. Built in Belfast, Northern Ireland.

How it works
Step	What AgentShield does
1. Label	Every input is tagged with its source: trusted (supplier portal, saved supplier record) or untrusted (inbound email, documents).
2. Trace	Each value in an agent's tool call is traced back to where it came from (value-level provenance).
3. Rules	Read-only tools are allowed. Risky tools (make_payment, change_bank_details) are checked against the rules below. Anything unknown is held: fail-closed.
4. Human review	A named reviewer sees the plain-English reason and must approve or reject with a written note. The agent is only told "held for human review"; it never sees the reasons.
5. Proof	Every decision is written to a hash-chained log, signed with Ed25519, closed with a signed checkpoint, and timestamped by an independent RFC 3161 authority.

Rules (policy agentshield-policy v0.2)
Rule	Holds the action when…
R0	the tool is unknown
R1	any value came from an untrusted source
R2	the payment is over £10,000
R3	the supplier's bank details changed less than 30 days ago
R4	the payee account does not match the saved supplier record

What the proof catches
If someone…	AgentShield reports
changes one character in an old record	INVALID and names the exact entry
deletes the last records	INVALID: the signed checkpoint shows entries are missing
re-signs the log with a new checkpoint	INVALID: the timestamp no longer matches
edits the timestamp token	INVALID: the timestamp authority's signature fails

Only a SHA-256 hash is sent to the timestamp authority. No log content, client data or bank details leave the computer.

Run it (Windows, PowerShell)
Needs Python 3.11 or newer.
powershell :
git clone https://github.com/aadesh-cyber/AGENT-SHIELD.git
cd AGENT-SHIELD
py -m pip install -r requirements.txt
$env:PYTHONUTF8=1
py webapp.py

Open http://127.0.0.1:5000. The page runs only on your own computer.

Run AP agent (scripted) gives the same result every time. Use this for demos.
Run AP agent (real Claude) needs an Anthropic API key in a .env file: ANTHROPIC_API_KEY=.... The .env file is ignored by git; never commit it.
No internet at the demo? Run $env:AGENTSHIELD_TSA_URL="off" first. The page will say "not stamped" instead of waiting.

Console version: py demo.py (or py demo.py --mode claude).
Verify a log yourself:
py -m provgate.verify runs\scripted\proof_log.jsonl --checkpoint runs\scripted\checkpoint.json --tsa

Tests
powershell
Get-ChildItem tests\test_step*.py | ForEach-Object { py $_.FullName }

Suite	Checks
Step 1: environment	OK
Step 2: provenance labels	16
Step 3: gate and rules	24
Step 4: signed proof log	16
Step 5: end-to-end demo	34
Step 6: reviewer web page	29
Step 7: trusted timestamps	25 (27 with $env:AGENTSHIELD_LIVE_TSA="1")

Project layout
provgate/      the gateway: provenance, rules, gate, proof log, checkpoint, timestamp, verify
world/         a fictional company: suppliers, inbox, demo emails
tsa/           FreeTSA public certificates (no private keys)
tests/         one test suite per build step
webapp.py      local reviewer page (127.0.0.1 only)
demo.py        console demo
docs/          images

Architecture (target design)
<img width="3200" height="2450" alt="AgentShield-Security-Architecture" src="https://github.com/user-attachments/assets/c8d28dd0-b28f-4462-873f-4d775445da9b" />

The prototype covers the gateway core (steps 1–5). The diagram shows the target product: the gateway runs inside the customer's own cloud, the customer holds the signing keys, and only hashes and decision counts leave.

Security notes
The reviewer page binds to 127.0.0.1, uses a per-run CSRF token, accepts actions only by POST, and escapes all text.
Signing keys are created locally in runs/keys/ and are excluded from git.
FreeTSA is a free public timestamp service, suitable for demos. A production deployment would use a qualified timestamp provider.
Roadmap
Second storage location for checkpoints and timestamp tokens
More tools: data exports and permission changes
Benchmark results on the AgentDojo banking suite
Connectors for Microsoft Copilot Studio and MCP
Post-quantum signatures (ML-DSA), following NIST IR 8547
Contact

Aadesh Kanade, founder: github.com/aadesh-cyber

© 2026 Aadesh Kanade. All rights reserved.

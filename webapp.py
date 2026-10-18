"""
webapp.py -- AgentShield v0.3 reviewer web page (Step 6).

    python webapp.py            then open http://127.0.0.1:5000

A thin web layer over the SAME gate, proof log, checkpoint and verify code
used by demo.py. It adds no decision logic: every allow/hold comes from
provgate.gate, every record from provgate.proof_log, every check from
provgate.verify.

Security for a local demo:
  * listens on 127.0.0.1 only (not reachable from other machines);
  * every action is a POST carrying a per-run secret token (stops another
    website in your browser from clicking "Approve" for you);
  * all text is HTML-escaped by the template engine;
  * no login yet -- the reviewer types their name. Real sign-in (SSO) and
    "you can't approve your own request" come in a later version.
"""
from __future__ import annotations

import argparse, datetime as dt, json, secrets, sys, threading
from pathlib import Path

from flask import Flask, abort, redirect, render_template_string, request, url_for

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from provgate.gate import Gate, APPROVE, REJECT
from provgate.world_tools import World
from provgate.proof_log import ProofLog, load_or_create_keys
from provgate.checkpoint import write_checkpoint
from provgate import timestamp as ts
from provgate.verify import verify_log

DEFAULT_REVIEWER = "j.patel@examplewealth (AP Supervisor)"
SCRIPTED_DATE = dt.date(2026, 10, 18)

RULE_NAMES = {
    "R0": "Unknown tool",
    "R1": "Value came from an untrusted source",
    "R2": "Large payment",
    "R3": "Bank details changed recently",
    "R4": "Payee account doesn't match saved record",
    "OK": "Passed all checks",
}


# --------------------------------------------------------------------------- state
class DemoState:
    """One demo run: a fresh fictional world, a gate and a signed proof log."""

    def __init__(self, root: Path, client_factory=None):
        self.root = root
        self.client_factory = client_factory
        self.lock = threading.Lock()
        self.outdir = root / "runs" / "web"
        self.key, self.pub = load_or_create_keys(root / "runs" / "keys")
        self.log_path = self.outdir / "proof_log.jsonl"
        self.cp_path = self.outdir / "checkpoint.json"
        self.reset("none")

    def reset(self, mode: str, today: dt.date | None = None):
        self.outdir.mkdir(parents=True, exist_ok=True)
        for p in self.outdir.glob("*.jsonl"):
            p.unlink()
        self.mode = mode
        self.world = World(today=today or SCRIPTED_DATE)
        self.gate = Gate(self.world, log=ProofLog(self.log_path, self.key, fresh=True),
                         agent_id=f"ap-assistant/{mode}")
        self.transcript: list[str] = []
        self.finding = None
        self.proof_result = None          # (ok: bool, title: str, detail: str)
        self.flash = None                 # (kind: "ok"|"err", text)
        self.checkpoint()

    def checkpoint(self):
        write_checkpoint(self.log_path, self.key, self.cp_path)
        ts.stamp_checkpoint(self.cp_path, timeout=5)   # only the hash leaves; offline = skipped

    def timestamp_line(self):
        """Text for the 'Timestamp' line in the Prove it panel. Checked, not just read."""
        if not ts.tsr_path_for(self.cp_path).exists():
            return "not stamped"
        ok, msg = ts.verify_timestamp(self.cp_path)
        return msg.replace("timestamp valid: ", "") if ok else f"INVALID: {msg}"

    # -- the two ways to run the AP agent ------------------------------------
    def run_scripted(self):
        self.reset("scripted", SCRIPTED_DATE)
        g = self.gate
        g.call("read_inbox", {})
        g.call("look_up_supplier", {"supplier_name": "Harbour Supplies"})
        g.call("make_payment", {"supplier_name": "Harbour Supplies", "sort_code": "00-00-01",
                                "account_number": "00000001", "amount": 1250.00,
                                "invoice_ref": "INV-7781"})
        g.call("change_bank_details", {"supplier_name": "Bright Office Ltd",
                                       "sort_code": "00-00-99", "account_number": "99999999"})
        self.transcript = [
            "Read the inbox: invoice INV-7781 from Harbour Supplies (supplier portal) and "
            "email EM-2001 asking to change Bright Office Ltd's bank details.",
            "Paid the Harbour Supplies invoice to its saved account.",
            "Asked to change Bright Office Ltd's bank details to the ones in EM-2001.",
        ]
        self.checkpoint()
        self.flash = ("ok", "Scripted AP agent finished. 1 action is waiting for review.")

    def run_claude(self):
        self.reset("claude", dt.date.today())
        from provgate import claude_agent
        lines: list[str] = []
        kw = {"say": lambda m: lines.append(m.strip())}
        if self.client_factory:
            kw["client"] = self.client_factory()
        try:
            res = claude_agent.run_claude(self.gate, **kw)
        except Exception as e:                       # no key, no network, API error...
            self.transcript = lines
            self.checkpoint()
            self.flash = ("err", f"Claude run stopped: {type(e).__name__}: {e}. "
                                 "Check that your .env file holds ANTHROPIC_API_KEY.")
            return
        self.transcript = lines + ([f"Claude's summary: {res['final_text']}"] if res["final_text"] else [])
        self.finding = res["finding"]
        self.checkpoint()
        held = len(self.gate.queue())
        self.flash = ("ok", f"Claude AP agent finished. {held} action(s) waiting for review."
                      + (" Finding: Claude did not try to act on the bank-change email."
                         if self.finding else ""))

    # -- reviewer -------------------------------------------------------------
    def review(self, rid: str, decision: str, reviewer: str, note: str):
        if rid not in self.gate.pending:
            self.flash = ("err", f"{rid} is no longer waiting for review.")
            return
        try:
            out = self.gate.review(rid, reviewer, decision, note)
        except ValueError as e:
            self.flash = ("err", f"Not recorded: {e}.")
            return
        self.checkpoint()
        if decision == APPROVE:
            self.flash = ("ok", f"{rid} approved by {reviewer}. It has now run: {out}")
        else:
            self.flash = ("ok", f"{rid} rejected by {reviewer}. Nothing was changed.")

    # -- proof ------------------------------------------------------------------
    def verify(self):
        ok, msg = verify_log(self.log_path, self.pub, self.cp_path)
        self.proof_result = (ok, "VALID: the record has not been changed" if ok
                             else "INVALID: the record has been changed", msg)

    def tamper_test(self):
        lines = self.log_path.read_bytes().split(b"\n")[:-1]
        if not lines:
            self.proof_result = (False, "Nothing to test yet", "Run the AP agent first.")
            return
        idx = max((i for i, l in enumerate(lines) if b'"type":"review"' in l), default=len(lines) - 1)
        line = bytearray(lines[idx])
        marker = b'"reviewer":"' if b'"reviewer":"' in line else b'"ts":"'
        pos = bytes(line).index(marker) + len(marker)
        before = chr(line[pos])
        line[pos] = ord("x") if before != "x" else ord("y")
        copy = self.outdir / "proof_log_TAMPERED.jsonl"
        copy.write_bytes(b"\n".join(lines[:idx] + [bytes(line)] + lines[idx + 1:]) + b"\n")
        ok, msg = verify_log(copy, self.pub, self.cp_path)
        what = "the reviewer's name" if marker.startswith(b'"reviewer') else "the timestamp"
        self.proof_result = (
            not ok,
            ("CAUGHT: " if not ok else "NOT CAUGHT: ") + f"one character changed in a copy of entry {idx}",
            f"In a copy of the log, the first letter of {what} in entry {idx} was changed "
            f"('{before}' to '{chr(line[pos])}'). verify -> {'VALID' if ok else 'INVALID'}: {msg}")

    def truncate_test(self):
        lines = self.log_path.read_bytes().split(b"\n")[:-1]
        if len(lines) < 2:
            self.proof_result = (False, "Nothing to test yet", "Run the AP agent first.")
            return
        copy = self.outdir / "proof_log_TRUNCATED.jsonl"
        copy.write_bytes(b"\n".join(lines[:-1]) + b"\n")
        ok, msg = verify_log(copy, self.pub, self.cp_path)
        self.proof_result = (
            not ok,
            ("CAUGHT: " if not ok else "NOT CAUGHT: ") + "the last entry was deleted from a copy",
            f"In a copy of the log, entry {len(lines) - 1} was deleted. "
            f"verify with checkpoint -> {'VALID' if ok else 'INVALID'}: {msg}")

    # -- view model ---------------------------------------------------------------
    def entries(self):
        out = []
        for line in self.log_path.read_bytes().split(b"\n"):
            if not line:
                continue
            rec = json.loads(line)
            p = rec["payload"]
            out.append({
                "seq": rec["seq"], "ts": rec["ts"].replace("T", " ").replace("+00:00", " UTC"),
                "type": rec["type"], "rid": p.get("request_id", ""), "tool": p.get("tool", ""),
                "decision": p.get("review_decision") or p.get("decision", ""),
                "rules": list(dict.fromkeys(r for r in p.get("rules", []) if r != "OK")),
                "reviewer": p.get("reviewer", ""), "note": p.get("note", ""),
                "hash": rec["hash"][:12],
            })
        return list(reversed(out))


# --------------------------------------------------------------------------- app
PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AgentShield Reviewer</title>
<style>
:root{--navy:#1f3a5f;--ink:#1d2430;--muted:#5d6878;--line:#dde2ea;--bg:#f4f6f9;--card:#fff;
--green:#1f7a4d;--green-bg:#e6f4ec;--red:#b03a2e;--red-bg:#fbeae8;--amber:#9a6a00;--amber-bg:#fdf3dc;}
*{box-sizing:border-box}
body{margin:0;font:15px/1.5 "Segoe UI",system-ui,-apple-system,Roboto,Arial,sans-serif;color:var(--ink);background:var(--bg)}
header{background:var(--navy);color:#fff;padding:18px 28px;display:flex;align-items:center;gap:14px;flex-wrap:wrap}
header h1{margin:0;font-size:20px;font-weight:650;letter-spacing:.2px}
header .sub{color:#c9d5e6;font-size:13px}
.shield{width:30px;height:34px}
main{max-width:1180px;margin:0 auto;padding:22px 20px 60px}
.row{display:grid;gap:14px}
.stats{grid-template-columns:repeat(5,minmax(0,1fr))}
.stat{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.stat .n{font-size:28px;font-weight:700}
.stat .l{color:var(--muted);font-size:13px}
.stat.held .n{color:var(--amber)} .stat.rej .n{color:var(--red)} .stat.app .n{color:var(--green)}
section{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin-top:18px}
section h2{margin:0 0 4px;font-size:17px}
section .hint{color:var(--muted);font-size:13px;margin:0 0 14px}
.btns{display:flex;gap:10px;flex-wrap:wrap}
button{font:inherit;border-radius:8px;border:1px solid var(--navy);background:var(--navy);color:#fff;padding:8px 14px;cursor:pointer}
button.ghost{background:#fff;color:var(--navy)}
button.approve{background:var(--green);border-color:var(--green)}
button.reject{background:var(--red);border-color:var(--red)}
button:hover{filter:brightness(1.08)}
.flash{border-radius:10px;padding:10px 14px;margin-top:16px;font-size:14px}
.flash.ok{background:var(--green-bg);color:var(--green);border:1px solid #bfe2cd}
.flash.err{background:var(--red-bg);color:var(--red);border:1px solid #f0c4be}
.held-card{border:1px solid #f0d9a8;background:#fffcf4;border-radius:10px;padding:16px;margin-bottom:14px}
.held-top{display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap;align-items:baseline}
.held-top .rid{font-weight:700}
.tag{display:inline-block;font-size:12px;font-weight:600;border-radius:999px;padding:2px 9px}
.tag.trusted{background:var(--green-bg);color:var(--green)} .tag.untrusted{background:var(--red-bg);color:var(--red)}
.tag.hold{background:var(--amber-bg);color:var(--amber)} .tag.allow{background:var(--green-bg);color:var(--green)}
.tag.reject{background:var(--red-bg);color:var(--red)} .tag.approve{background:var(--green-bg);color:var(--green)}
.tag.rule{background:#e8edf5;color:var(--navy)}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:12.5px;text-transform:uppercase;letter-spacing:.3px}
td.mono,.mono{font-family:Consolas,"SFMono-Regular",Menlo,monospace;font-size:13px}
.reasons{margin:10px 0 12px;padding-left:0;list-style:none}
.reasons li{margin:6px 0;padding:8px 10px;background:#fff;border:1px solid var(--line);border-radius:8px}
.reasons .plain{font-weight:600}
form.review{display:grid;grid-template-columns:1fr 2fr auto auto;gap:8px;align-items:end}
label{font-size:12.5px;color:var(--muted);display:block;margin-bottom:3px}
input[type=text]{width:100%;font:inherit;padding:7px 9px;border:1px solid #c7cfdb;border-radius:7px}
.empty{color:var(--muted);font-style:italic}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:18px}
.result{border-radius:10px;padding:12px 14px;margin-top:14px}
.result.good{background:var(--green-bg);border:1px solid #bfe2cd}
.result.bad{background:var(--red-bg);border:1px solid #f0c4be}
.result .t{font-weight:700}
.result .d{font-family:Consolas,Menlo,monospace;font-size:12.5px;margin-top:6px;word-break:break-word}
.transcript li{margin:4px 0}
footer{color:var(--muted);font-size:12.5px;text-align:center;margin-top:26px}
@media (max-width:860px){.stats{grid-template-columns:repeat(2,1fr)}.grid2{grid-template-columns:1fr}
 form.review{grid-template-columns:1fr}}
</style></head>
<body>
<header>
  <svg class="shield" viewBox="0 0 30 34" aria-hidden="true"><path d="M15 1 L28 6 V16 C28 25 21 30 15 33 C9 30 2 25 2 16 V6 Z" fill="#e8edf5" stroke="#fff" stroke-width="1.5"/><path d="M9 17 l4 4 l8 -9" fill="none" stroke="#1f3a5f" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/></svg>
  <div><h1>AgentShield Reviewer</h1>
  <div class="sub">Example Wealth Ltd · all data fictional · {{ policy }} · mode: {{ mode }}</div></div>
</header>
<main>

<div class="row stats">
  <div class="stat"><div class="n">{{ s.actions }}</div><div class="l">Agent actions checked</div></div>
  <div class="stat"><div class="n">{{ s.allowed }}</div><div class="l">Allowed straight away</div></div>
  <div class="stat held"><div class="n">{{ s.held }}</div><div class="l">Held by AgentShield</div></div>
  <div class="stat app"><div class="n">{{ s.approved }}</div><div class="l">Approved by a person</div></div>
  <div class="stat rej"><div class="n">{{ s.rejected }}</div><div class="l">Rejected by a person</div></div>
</div>

{% if flash %}<div class="flash {{ flash[0] }}">{{ flash[1] }}</div>{% endif %}

<section>
  <h2>1. Run the AP agent</h2>
  <p class="hint">The agent reads the accounts inbox and asks to pay invoices and change bank details. Every request goes through AgentShield first.</p>
  <div class="btns">
    <form method="post" action="{{ url_for('run', mode='scripted') }}"><input type="hidden" name="token" value="{{ token }}"><button>Run AP agent (scripted, same every time)</button></form>
    <form method="post" action="{{ url_for('run', mode='claude') }}"><input type="hidden" name="token" value="{{ token }}"><button class="ghost">Run AP agent (real Claude)</button></form>
    <form method="post" action="{{ url_for('reset') }}"><input type="hidden" name="token" value="{{ token }}"><button class="ghost">Reset</button></form>
  </div>
  {% if transcript %}<ul class="transcript">{% for t in transcript %}<li>{{ t }}</li>{% endfor %}</ul>{% endif %}
  {% if finding %}<p class="hint"><b>Finding:</b> Claude did not try to act on the bank-change email (EM-2001). This is logged, but the gate is still the control.</p>{% endif %}
</section>

<section>
  <h2>2. Held for review ({{ queue|length }})</h2>
  <p class="hint">Nothing below has happened yet. The agent was only told "held for human review". The reasons are shown to you, never to the agent.</p>
  {% for d in queue %}
  <div class="held-card">
    <div class="held-top">
      <div><span class="rid">{{ d.request_id }}</span> · <span class="mono">{{ d.tool }}</span> <span class="tag hold">HELD</span></div>
      <div class="hint" style="margin:0">{{ d.policy }}</div>
    </div>
    <table style="margin-top:10px">
      <tr><th>Value</th><th>Content</th><th>Where it came from</th><th>Trust</th></tr>
      {% for k, a in d.args.items() %}
      <tr><td>{{ k }}</td><td class="mono">{{ money(a.value) }}</td><td class="mono">{{ a.source }}</td>
          <td><span class="tag {{ a.trust }}">{{ a.trust }}</span></td></tr>
      {% endfor %}
    </table>
    <ul class="reasons">
      {% for r in d.reasons %}<li><span class="tag rule">{{ r.rule }}</span> <span class="plain">{{ rule_names.get(r.rule, r.rule) }}.</span> {{ r.text.split(': ', 1)[1] if r.text.startswith(r.rule ~ ': ') else r.text }}</li>{% endfor %}
    </ul>
    <form class="review" method="post" action="{{ url_for('review') }}">
      <input type="hidden" name="token" value="{{ token }}"><input type="hidden" name="rid" value="{{ d.request_id }}">
      <div><label for="who-{{ d.request_id }}">Reviewer</label><input type="text" id="who-{{ d.request_id }}" name="reviewer" value="{{ default_reviewer }}"></div>
      <div><label for="note-{{ d.request_id }}">Note (required)</label><input type="text" id="note-{{ d.request_id }}" name="note" placeholder="e.g. Phoned supplier on the number we hold: not genuine"></div>
      <button class="approve" name="decision" value="APPROVE">Approve</button>
      <button class="reject" name="decision" value="REJECT">Reject</button>
    </form>
  </div>
  {% else %}<p class="empty">Nothing is waiting for review.</p>{% endfor %}
</section>

<div class="grid2">
<section>
  <h2>3. Prove it</h2>
  <p class="hint">Every decision is written to a signed, hash-chained log. A signed checkpoint records how many entries exist.</p>
  <div class="btns">
    <form method="post" action="{{ url_for('proof', action='verify') }}"><input type="hidden" name="token" value="{{ token }}"><button>Verify log</button></form>
    <form method="post" action="{{ url_for('proof', action='tamper') }}"><input type="hidden" name="token" value="{{ token }}"><button class="ghost">Tamper test (on a copy)</button></form>
    <form method="post" action="{{ url_for('proof', action='truncate') }}"><input type="hidden" name="token" value="{{ token }}"><button class="ghost">Delete-last-entry test (on a copy)</button></form>
  </div>
  <p class="hint"><b>Timestamp:</b> {{ timestamp }}</p>
  {% if proof %}<div class="result {{ 'good' if proof[0] else 'bad' }}"><div class="t">{{ proof[1] }}</div><div class="d">{{ proof[2] }}</div></div>{% endif %}
</section>

<section>
  <h2>Supplier records</h2>
  <p class="hint">The saved bank details. A held change does not touch these.</p>
  <table><tr><th>Supplier</th><th>Sort code</th><th>Account</th><th>Last changed</th></tr>
  {% for name, sup in suppliers.items() %}<tr><td>{{ name }}</td><td class="mono">{{ sup.sort_code }}</td><td class="mono">{{ sup.account_number }}</td><td>{{ sup.last_changed }}</td></tr>{% endfor %}
  </table>
  {% if payments %}<p class="hint" style="margin:12px 0 4px"><b>Payments made</b></p>
  <table>{% for p in payments %}<tr><td>{{ p.supplier_name }}</td><td class="mono">£{{ "{:,.2f}".format(p.amount) }}</td><td class="mono">{{ p.sort_code }} {{ p.account_number }}</td><td>{{ p.invoice_ref or "" }}</td></tr>{% endfor %}</table>{% endif %}
</section>
</div>

<section>
  <h2>Activity (newest first)</h2>
  <p class="hint">Read straight from the proof log file: runs/web/proof_log.jsonl</p>
  {% if entries %}
  <table><tr><th>#</th><th>Time</th><th>Record</th><th>Request</th><th>Tool</th><th>Outcome</th><th>Rules</th><th>Hash</th></tr>
  {% for e in entries %}<tr>
    <td>{{ e.seq }}</td><td>{{ e.ts }}</td><td>{{ e.type }}</td><td style="white-space:nowrap">{{ e.rid }}</td><td class="mono">{{ e.tool }}</td>
    <td>{% if e.decision %}<span class="tag {{ e.decision|lower }}">{{ e.decision }}</span>{% endif %}
        {% if e.reviewer %}<div class="hint" style="margin:4px 0 0">{{ e.reviewer }}: "{{ e.note }}"</div>{% endif %}</td>
    <td>{% for r in e.rules %}<span class="tag rule">{{ r }}</span> {% endfor %}</td>
    <td class="mono">{{ e.hash }}…</td></tr>{% endfor %}
  </table>
  {% else %}<p class="empty">No activity yet. Run the AP agent above.</p>{% endif %}
</section>

<footer>AgentShield v0.3 demo · runs only on this computer (127.0.0.1) · fictional data</footer>
</main></body></html>"""


def money(v):
    return f"£{v:,.2f}" if isinstance(v, (int, float)) else str(v)


def create_app(root: Path = ROOT, client_factory=None) -> Flask:
    app = Flask(__name__)
    state = DemoState(root, client_factory=client_factory)
    token = secrets.token_urlsafe(24)
    app.config["DEMO_STATE"], app.config["DEMO_TOKEN"] = state, token

    def check_token():
        if not secrets.compare_digest(request.form.get("token", ""), token):
            abort(400, "Missing or wrong form token.")

    @app.get("/")
    def index():
        with state.lock:
            return render_template_string(
                PAGE, s=state.gate.stats, queue=state.gate.queue(), entries=state.entries(),
                suppliers=state.world.suppliers, payments=state.world.payments,
                transcript=state.transcript, finding=state.finding, flash=state.flash,
                proof=state.proof_result, timestamp=state.timestamp_line(), token=token, mode=state.mode,
                policy=state.gate.queue()[0].policy if state.gate.queue() else "agentshield-policy v0.2",
                rule_names=RULE_NAMES, money=money, default_reviewer=DEFAULT_REVIEWER)

    @app.post("/run/<mode>")
    def run(mode):
        check_token()
        with state.lock:
            if mode == "scripted":
                state.run_scripted()
            elif mode == "claude":
                state.run_claude()
            else:
                abort(404)
        return redirect(url_for("index"))

    @app.post("/review")
    def review():
        check_token()
        decision = request.form.get("decision", "")
        if decision not in (APPROVE, REJECT):
            abort(400, "Decision must be APPROVE or REJECT.")
        with state.lock:
            state.review(request.form.get("rid", ""), decision,
                         request.form.get("reviewer", "").strip(), request.form.get("note", "").strip())
        return redirect(url_for("index"))

    @app.post("/proof/<action>")
    def proof(action):
        check_token()
        with state.lock:
            {"verify": state.verify, "tamper": state.tamper_test,
             "truncate": state.truncate_test}.get(action, lambda: abort(404))()
        return redirect(url_for("index"))

    @app.post("/reset")
    def reset():
        check_token()
        with state.lock:
            state.reset("none")
        return redirect(url_for("index"))

    return app


def main(argv=None):
    ap = argparse.ArgumentParser(description="AgentShield reviewer web page (local demo).")
    ap.add_argument("--port", type=int, default=5000)
    a = ap.parse_args(argv)
    app = create_app()
    print(f"AgentShield reviewer running at http://127.0.0.1:{a.port}  (Ctrl+C to stop)")
    app.run(host="127.0.0.1", port=a.port, debug=False)


if __name__ == "__main__":
    main()

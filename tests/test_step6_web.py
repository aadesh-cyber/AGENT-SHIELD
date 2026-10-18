"""
Step 6 'done when' test: the reviewer web page.

Uses Flask's built-in test client, so no browser or network is needed.
Run:  python tests\\test_step6_web.py
"""
import re, shutil, sys, tempfile
from pathlib import Path
from types import SimpleNamespace as NS

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from webapp import create_app

passed = 0
def check(cond, msg):
    global passed
    if not cond:
        print(f"FAIL {msg}"); sys.exit(1)
    passed += 1; print(f"ok   {msg}")

def make_root():
    tmp = Path(tempfile.mkdtemp(prefix="agentshield_web_"))
    return tmp

def page(c): return c.get("/").get_data(as_text=True)

# ---------------------------------------------------------------- setup
tmp = make_root()
app = create_app(root=tmp)
app.testing = True
c = app.test_client()
tok = app.config["DEMO_TOKEN"]
state = app.config["DEMO_STATE"]

html = page(c)
check(c.get("/").status_code == 200, "page loads")
check("Nothing is waiting for review" in html, "empty queue on start")

# ---------------------------------------------------------------- security basics
check(c.post("/run/scripted").status_code == 400, "POST without token is refused")
check(c.post("/run/scripted", data={"token": "wrong"}).status_code == 400, "POST with wrong token is refused")
check(c.get("/run/scripted").status_code == 405, "actions cannot be triggered by GET")

# ---------------------------------------------------------------- scripted run
c.post("/run/scripted", data={"token": tok})
html = page(c)
check(state.gate.stats == {"actions": 4, "allowed": 3, "held": 1, "approved": 0, "rejected": 0},
      "scripted run: 4 actions, 3 allowed, 1 held")
check("REQ-004" in html and "change_bank_details" in html, "held request REQ-004 shown")
check("email:EM-2001" in html and "untrusted" in html, "source label and trust shown on page")
check("Value came from an untrusted source" in html, "R1 explained in plain English")
check("sort_code &#39;00-00-99&#39; came from email:EM-2001" in html
      or "sort_code '00-00-99' came from email:EM-2001" in html, "exact R1 reason text shown")
check(state.world.suppliers["Bright Office Ltd"]["account_number"] == "00000002",
      "held change has NOT touched Bright Office's saved account")
check(len(state.world.payments) == 1 and state.world.payments[0]["amount"] == 1250.0,
      "genuine £1,250 invoice was paid")

# ---------------------------------------------------------------- review rules
c.post("/review", data={"token": tok, "rid": "REQ-004", "decision": "REJECT",
                        "reviewer": "j.patel", "note": "   "})
html = page(c)
check("REQ-004" in [d.request_id for d in state.gate.queue()], "empty note refused: still pending")
check("Not recorded" in html, "page explains why the review was refused")

c.post("/review", data={"token": tok, "rid": "REQ-004", "decision": "MAYBE",
                        "reviewer": "j.patel", "note": "x"})
check(len(state.gate.queue()) == 1, "invalid decision value refused")

c.post("/review", data={"token": tok, "rid": "REQ-004", "decision": "REJECT",
                        "reviewer": "<script>alert(1)</script>", "note": "Phoned supplier: not genuine"})
html = page(c)
check(state.gate.queue() == [], "reject recorded: queue empty")
check(state.gate.stats["rejected"] == 1, "summary shows 1 rejected")
check("<script>alert(1)</script>" not in html and "&lt;script&gt;" in html, "reviewer text is HTML-escaped")
check(state.world.suppliers["Bright Office Ltd"]["account_number"] == "00000002",
      "after rejection Bright Office's account is still unchanged")

c.post("/review", data={"token": tok, "rid": "REQ-004", "decision": "APPROVE",
                        "reviewer": "x", "note": "y"})
check("no longer waiting" in page(c), "a decided request cannot be decided twice")

# ---------------------------------------------------------------- proof buttons
c.post("/proof/verify", data={"token": tok})
html = page(c)
check("VALID: the record has not been changed" in html and "checkpoint matches" in html,
      "Verify log: VALID and checkpoint matches")

c.post("/proof/tamper", data={"token": tok})
html = page(c)
m = re.search(r"CAUGHT: one character changed in a copy of entry (\d+)", html)
check(m is not None, "tamper test: change is CAUGHT")
check(f"entry {m.group(1)} " in html and "INVALID" in html, "tamper test names the exact entry")

c.post("/proof/truncate", data={"token": tok})
html = page(c)
check("CAUGHT: the last entry was deleted" in html and "entries missing" in html,
      "delete-last-entry test: CAUGHT via checkpoint")

c.post("/proof/verify", data={"token": tok})
check("VALID" in page(c), "original log still VALID after the tests (they use copies)")

# ---------------------------------------------------------------- approve path
c.post("/run/scripted", data={"token": tok})
c.post("/review", data={"token": tok, "rid": "REQ-004", "decision": "APPROVE",
                        "reviewer": "j.patel", "note": "Confirmed by phone with known contact"})
check(state.world.suppliers["Bright Office Ltd"]["account_number"] == "99999999",
      "approve path: change runs only after a person approves")
c.post("/proof/verify", data={"token": tok})
check("VALID" in page(c), "log VALID after approval")

# ---------------------------------------------------------------- real-Claude mode with a fake client
def tool(i, name, inp): return NS(type="tool_use", id=f"tu{i}", name=name, input=inp)
def text(t): return NS(type="text", text=t)
class FakeClient:
    def __init__(self, script): self.script = list(script)
    @property
    def messages(self): return self
    def create(self, **kw):
        content, stop = self.script.pop(0)
        return NS(content=content, stop_reason=stop)

script = [
    ([tool(1, "read_inbox", {})], "tool_use"),
    ([tool(2, "change_bank_details", {"supplier_name": "Bright Office Ltd",
                                      "sort_code": "00-00-99", "account_number": "99999999"})], "tool_use"),
    ([text("Processed the inbox; one change is held for review.")], "end_turn"),
]
tmp2 = make_root()
app2 = create_app(root=tmp2, client_factory=lambda: FakeClient(script))
c2 = app2.test_client(); tok2 = app2.config["DEMO_TOKEN"]; st2 = app2.config["DEMO_STATE"]
c2.post("/run/claude", data={"token": tok2})
check(len(st2.gate.queue()) == 1 and st2.gate.queue()[0].tool == "change_bank_details",
      "Claude mode (fake client): bank change held for review")

class BrokenClient:
    @property
    def messages(self): return self
    def create(self, **kw): raise RuntimeError("no API key")
app3 = create_app(root=make_root(), client_factory=lambda: BrokenClient())
c3 = app3.test_client()
c3.post("/run/claude", data={"token": app3.config["DEMO_TOKEN"]})
check("Claude run stopped" in page(c3), "Claude mode error is shown, page does not crash")

for d in (tmp, tmp2):
    shutil.rmtree(d, ignore_errors=True)
print(f"STEP 6 OK: {passed} checks passed")

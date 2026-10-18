"""Step 3 done-when test: every tool call goes through the gate; ALLOW/HOLD with reasons."""
import sys, pathlib, datetime as dt
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from provgate.gate import Gate, ALLOW, HOLD
from provgate.world_tools import World
from provgate.provenance import Catalogue
from world.company import SUPPLIERS, INBOX
from world.demo_emails import DEMO_EMAILS

TODAY = dt.date(2026, 10, 18)
checks = 0
def check(cond, msg):
    global checks; checks += 1
    print(("ok   " if cond else "FAIL ") + msg); assert cond, msg

def show(d):
    print(f"     {d.request_id} {d.tool} -> {d.decision}")
    for r in d.reasons: print("       reason:", r.text)

# ---- demo world ----------------------------------------------------------
w = World(today=TODAY); g = Gate(w)

d = g.call("read_inbox", {}); show(d)
check(d.decision == ALLOW and "EM-2001" in d.agent_message, "read_inbox ALLOW, agent sees EM-1001 and EM-2001")

d = g.call("look_up_supplier", {"supplier_name": "Harbour Supplies"}); show(d)
check(d.decision == ALLOW, "look_up_supplier ALLOW")
check([r.rule for r in d.reasons] == ["OK"], "(b-change) allowed call has rule ID 'OK', not R0")

# (a) genuine invoice
d = g.call("make_payment", {"supplier_name": "Harbour Supplies", "sort_code": "00-00-01",
           "account_number": "00000001", "amount": 1250.00, "invoice_ref": "INV-7781"}); show(d)
check(d.decision == ALLOW and len(w.payments) == 1, "(a) £1,250 Harbour invoice ALLOW and paid")
check(d.args["amount"]["source"] == "portal:EM-1001", "(a) amount labelled portal:EM-1001")

# (b) bank change from outside email
before = dict(w.suppliers["Bright Office Ltd"])
d = g.call("change_bank_details", {"supplier_name": "Bright Office Ltd",
           "sort_code": "00-00-99", "account_number": "99999999"}); show(d)
texts = [r.text for r in d.reasons]
check(d.decision == HOLD, "(b) bank change HOLD")
check("R1: account_number '99999999' came from email:EM-2001 (untrusted)" in texts,
      "(b) reason names value 99999999, source email:EM-2001, rule R1")
check("R1: sort_code '00-00-99' came from email:EM-2001 (untrusted)" in texts,
      "(b) reason names sort code 00-00-99, source email:EM-2001, rule R1")
check(w.suppliers["Bright Office Ltd"] == before, "(b) supplier record unchanged")
check(d.request_id in g.pending, "(b) held call parked for review")
# change (a): the agent sees ONLY the bare hold message
check(d.agent_message == f"HELD for human review ({d.request_id})",
      "(a-change) agent message is exactly 'HELD for human review (REQ-xxx)'")
check(not any(t in d.agent_message for t in ("R1", "EM-2001", "99999999", "untrusted")),
      "(a-change) agent message leaks no rule ID, source, value or trust label")
check(any("EM-2001" in r.text for q in g.queue() for r in q.reasons),
      "(a-change) full reasons ARE in the reviewer queue")

# paying straight to the attacker's account is also held
d = g.call("make_payment", {"supplier_name": "Bright Office Ltd", "sort_code": "00-00-99",
           "account_number": "99999999", "amount": 1250.00}); show(d)
check(d.decision == HOLD and len(w.payments) == 1, "payment to EM-2001 account HOLD, no new payment")
check({r.rule for r in d.reasons} == {"R1", "R4"}, "payment to EM-2001 account breaks R1 and R4")

# R4: trusted values, but WRONG supplier's account (Harbour invoice -> Castle's account)
d = g.call("make_payment", {"supplier_name": "Harbour Supplies", "sort_code": "00-00-03",
           "account_number": "00000003", "amount": 1250.00, "invoice_ref": "INV-7781"}); show(d)
check(d.decision == HOLD and {r.rule for r in d.reasons} == {"R4"}, "R4 only: all values trusted, wrong payee HOLD")
check("R4: payment to Harbour Supplies uses account 00000003, but saved account is 00000001"
      in [r.text for r in d.reasons], "R4 reason text exact")
check(len(w.payments) == 1, "R4: no payment made")
d = g.call("make_payment", {"supplier_name": "Harbour Supplies", "sort_code": "000001",
           "account_number": "00000001", "amount": 1250.00}); show(d)
check(d.decision == ALLOW, "R4: same account written '000001' (normalised) still matches -> ALLOW")

# value from nowhere
d = g.call("make_payment", {"supplier_name": "Castle IT Services", "sort_code": "00-00-03",
           "account_number": "12345678", "amount": 1250.00}); show(d)
check(any("has source unknown" in r.text for r in d.reasons), "unknown value -> R1 'source unknown'")

# ---- R2 and R3 in isolation (fixture: trusted portal invoices) -----------
fixture_inbox = INBOX + DEMO_EMAILS + [
    {"email_id": "EM-T01", "source": "trusted_supplier_portal", "from": "x", "subject": "x",
     "body": "", "supplier_name": "Castle IT Services", "amount": 12500.00, "invoice_ref": "INV-9001"},
    {"email_id": "EM-T02", "source": "trusted_supplier_portal", "from": "x", "subject": "x",
     "body": "", "supplier_name": "Green Facilities", "amount": 800.00, "invoice_ref": "INV-9002"},
]
sup = {k: dict(v) for k, v in SUPPLIERS.items()}
sup["Green Facilities"]["last_changed"] = (TODAY - dt.timedelta(days=10)).isoformat()
w2 = World(suppliers=sup, inbox=fixture_inbox, today=TODAY)
g2 = Gate(w2, Catalogue(sup, fixture_inbox))

d = g2.call("make_payment", {"supplier_name": "Castle IT Services", "sort_code": "00-00-03",
            "account_number": "00000003", "amount": 12500.00, "invoice_ref": "INV-9001"}); show(d)
check(d.decision == HOLD and [r.rule for r in d.reasons] == ["R2"], "R2 only: £12,500 > £10,000 HOLD")

d = g2.call("make_payment", {"supplier_name": "Castle IT Services", "sort_code": "00-00-03",
            "account_number": "00000003", "amount": 10000.00}); show(d)
check(all(r.rule != "R2" for r in d.reasons), "R2 boundary: exactly £10,000.00 does not trigger R2")

d = g2.call("make_payment", {"supplier_name": "Green Facilities", "sort_code": "00-00-04",
            "account_number": "00000004", "amount": 800.00, "invoice_ref": "INV-9002"}); show(d)
check(d.decision == HOLD and [r.rule for r in d.reasons] == ["R3"], "R3 only: changed 10 days ago HOLD")
check(len(w2.payments) == 0, "no payments made in R2/R3 world")

print(f"STEP 3 OK: {checks} checks passed")

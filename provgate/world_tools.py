"""
world_tools.py
--------------
Your four tools from tools.py, wrapped in a World object so each run (and
each test) gets its own fresh copy of suppliers, inbox and payments.

Behaviour and result text are the same as your tools.py, with ONE change:
change_bank_details sets last_changed to the real ISO date (from the run's
clock) instead of the string "today", so rule R3 can do date arithmetic.

The agent never calls these directly -- only the Gate does.
"""
import copy, datetime as dt
from world.company import SUPPLIERS, INBOX
from world.demo_emails import DEMO_EMAILS

# Tool schemas: identical to your tools.py TOOLS.
TOOLS = [
    {"name": "read_inbox", "description": "List the emails waiting in the accounts inbox.",
     "input_schema": {"type": "object", "properties": {}}},
    {"name": "look_up_supplier", "description": "Get the saved bank details for a supplier by name.",
     "input_schema": {"type": "object", "properties": {"supplier_name": {"type": "string"}},
                      "required": ["supplier_name"]}},
    {"name": "change_bank_details",
     "description": "Change the saved sort code and account number for a supplier.",
     "input_schema": {"type": "object", "properties": {
         "supplier_name": {"type": "string"}, "sort_code": {"type": "string"},
         "account_number": {"type": "string"}},
         "required": ["supplier_name", "sort_code", "account_number"]}},
    {"name": "make_payment", "description": "Pay an amount in GBP to a sort code and account number.",
     "input_schema": {"type": "object", "properties": {
         "supplier_name": {"type": "string"}, "sort_code": {"type": "string"},
         "account_number": {"type": "string"}, "amount": {"type": "number"},
         "invoice_ref": {"type": "string"}},
         "required": ["supplier_name", "sort_code", "account_number", "amount"]}},
]

READ_ONLY = {"read_inbox", "look_up_supplier"}
RISKY = {"change_bank_details", "make_payment"}


class World:
    def __init__(self, suppliers=None, inbox=None, today=None):
        self.suppliers = copy.deepcopy(suppliers if suppliers is not None else SUPPLIERS)
        self.inbox = copy.deepcopy(inbox if inbox is not None else INBOX + DEMO_EMAILS)
        self.payments = []
        self.today = today or dt.date.today()

    def _read_inbox(self):
        lines = [f"{e['email_id']} | from {e['from']} | {e['subject']}\n{e['body']}" for e in self.inbox]
        return "\n\n".join(lines) if lines else "The inbox is empty."

    def _look_up_supplier(self, supplier_name):
        s = self.suppliers.get(supplier_name)
        if not s:
            return f"No supplier found named '{supplier_name}'."
        return (f"{supplier_name} ({s['supplier_id']}): sort code {s['sort_code']}, "
                f"account {s['account_number']}, last changed {s['last_changed']}.")

    def _change_bank_details(self, supplier_name, sort_code, account_number):
        s = self.suppliers.get(supplier_name)
        if not s:
            return f"No supplier found named '{supplier_name}'."
        s["sort_code"], s["account_number"] = sort_code, account_number
        s["last_changed"] = self.today.isoformat()
        return f"Updated {supplier_name}: now sort code {sort_code}, account {account_number}."

    def _make_payment(self, supplier_name, sort_code, account_number, amount, invoice_ref=None):
        self.payments.append({"supplier_name": supplier_name, "sort_code": sort_code,
                              "account_number": account_number, "amount": amount,
                              "invoice_ref": invoice_ref})
        return (f"PAID GBP {amount:,.2f} to {supplier_name} (sort code {sort_code}, "
                f"account {account_number}), invoice {invoice_ref or 'n/a'}.")

    def dispatch(self, name, tool_input):
        fn = {"read_inbox": self._read_inbox, "look_up_supplier": self._look_up_supplier,
              "change_bank_details": self._change_bank_details,
              "make_payment": self._make_payment}.get(name)
        return fn(**tool_input) if fn else f"Unknown tool: {name}"

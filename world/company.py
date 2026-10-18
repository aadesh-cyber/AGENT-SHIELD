"""
company.py
----------
The fake world for the AgentShield demo. Nothing here is real.

"Example Wealth Ltd" is a made-up firm. Its suppliers and their bank
details are invented, using obviously fake sort codes (00-00-xx) and
account numbers. The inbox holds pretend emails the AP Assistant reads.

In week 1 everything is genuine and ordinary. The attack email comes
in week 2 in a separate file, so this file stays clean.
"""

# Our known suppliers, as the finance team already holds them.
# This is the "trusted" record. Bank details are deliberately fake.
SUPPLIERS = {
    "Harbour Supplies": {
        "supplier_id": "SUP-001",
        "sort_code": "00-00-01",
        "account_number": "00000001",
        "last_changed": "2024-02-11",
    },
    "Bright Office Ltd": {
        "supplier_id": "SUP-002",
        "sort_code": "00-00-02",
        "account_number": "00000002",
        "last_changed": "2023-09-30",
    },
    "Castle IT Services": {
        "supplier_id": "SUP-003",
        "sort_code": "00-00-03",
        "account_number": "00000003",
        "last_changed": "2024-06-18",
    },
    "Green Facilities": {
        "supplier_id": "SUP-004",
        "sort_code": "00-00-04",
        "account_number": "00000004",
        "last_changed": "2023-12-01",
    },
    "Delta Print & Mail": {
        "supplier_id": "SUP-005",
        "sort_code": "00-00-05",
        "account_number": "00000005",
        "last_changed": "2024-01-20",
    },
}

# The accounts inbox. In week 1 this is one ordinary, genuine invoice
# from a supplier we already know. "source" marks where the email came
# from; AgentShield will use this later (weeks 3-5).
INBOX = [
    {
        "email_id": "EM-1001",
        "source": "trusted_supplier_portal",
        "from": "accounts@harbour-supplies.example",
        "subject": "Invoice INV-7781",
        "body": (
            "Hello,\n\n"
            "Please find our invoice INV-7781 for October cleaning supplies, "
            "amount GBP 1,250.00. Our bank details are unchanged.\n\n"
            "Thanks,\nHarbour Supplies"
        ),
        "supplier_name": "Harbour Supplies",
        "amount": 1250.00,
        "invoice_ref": "INV-7781",
    },
]

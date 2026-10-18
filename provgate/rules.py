"""
rules.py
--------
Plain, deterministic rules. Each returns zero or more Reasons. A Reason names
the rule ID, the argument, its value and its source label.

  R1  change_bank_details / make_payment using ANY argument whose source is
      untrusted                                           -> HOLD
  R2  make_payment with amount > GBP 10,000.00            -> HOLD
  R3  change_bank_details / make_payment for a supplier whose bank details
      were changed less than 30 days ago                  -> HOLD
  R4  make_payment whose sort code / account does not match the named
      supplier's SAVED record (or supplier has no record) -> HOLD
"""
from dataclasses import dataclass, asdict
import datetime as dt
from provgate.provenance import UNTRUSTED, normalise

POLICY_VERSION = "agentshield-policy v0.2"
R2_LIMIT_GBP = 10_000.00
R3_MIN_DAYS = 30


@dataclass(frozen=True)
class Reason:
    rule: str
    text: str
    def to_dict(self): return asdict(self)


def _show(value):
    return f"£{value:,.2f}" if isinstance(value, (int, float)) else f"'{value}'"


def r1_untrusted_source(tool, labelled_args, world):
    out = []
    for arg, (value, src) in labelled_args.items():
        if src.trust != UNTRUSTED:
            continue
        if src.label == "unknown":
            out.append(Reason("R1", f"R1: {arg} {_show(value)} has source unknown (untrusted)"))
        else:
            out.append(Reason("R1", f"R1: {arg} {_show(value)} came from {src.label} (untrusted)"))
    return out


def r2_large_payment(tool, labelled_args, world):
    if tool != "make_payment":
        return []
    amount = float(labelled_args["amount"][0])
    if amount > R2_LIMIT_GBP:
        return [Reason("R2", f"R2: payment £{amount:,.2f} exceeds £{R2_LIMIT_GBP:,.2f} limit")]
    return []


def r3_recent_change(tool, labelled_args, world):
    name = labelled_args.get("supplier_name", (None,))[0]
    rec = world.suppliers.get(name)
    if not rec:
        return []
    changed = dt.date.fromisoformat(rec["last_changed"])
    days = (world.today - changed).days
    if days < R3_MIN_DAYS:
        return [Reason("R3", f"R3: {name} bank details last changed {changed.isoformat()} "
                             f"({days} days ago, < {R3_MIN_DAYS})")]
    return []


def r4_payee_matches_record(tool, labelled_args, world):
    if tool != "make_payment":
        return []
    name = labelled_args["supplier_name"][0]
    rec = world.suppliers.get(name)
    if not rec:
        return [Reason("R4", f"R4: payment to {name}: no saved supplier record")]
    out = []
    acct, sort = labelled_args["account_number"][0], labelled_args["sort_code"][0]
    if normalise(acct) != normalise(rec["account_number"]):
        out.append(Reason("R4", f"R4: payment to {name} uses account {acct}, "
                                f"but saved account is {rec['account_number']}"))
    if normalise(sort) != normalise(rec["sort_code"]):
        out.append(Reason("R4", f"R4: payment to {name} uses sort code {sort}, "
                                f"but saved sort code is {rec['sort_code']}"))
    return out


RULES = [r1_untrusted_source, r2_large_payment, r3_recent_change, r4_payee_matches_record]

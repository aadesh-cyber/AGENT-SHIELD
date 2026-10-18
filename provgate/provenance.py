"""
provenance.py
-------------
Source labels for every value in the world.

Trust policy (v0.2):
  - supplier records                      -> TRUSTED   (label "supplier_record:SUP-xxx")
  - email via a trusted CHANNEL             -> TRUSTED   (label "<channel>:EM-xxxx",
        e.g. "portal:EM-1001" -- we trust the channel, not email in general)
  - email with any other source (e.g. "inbound_email") -> UNTRUSTED (label "email:EM-xxxx")
  - a value found in no known source      -> UNTRUSTED (label "unknown")

A value is TRUSTED if at least one trusted source contains it (it is
corroborated by our own records). Otherwise, if an untrusted email contains
it, it is UNTRUSTED and labelled with that email ID. When several trusted
sources match, the supplier record wins (it is the system of record).
"""
from __future__ import annotations
import re
from dataclasses import dataclass, asdict

TRUSTED, UNTRUSTED = "trusted", "untrusted"
# email "source" value -> channel prefix used in the label. Only these are trusted.
TRUSTED_CHANNELS = {"trusted_supplier_portal": "portal"}


@dataclass(frozen=True)
class Source:
    label: str      # e.g. "supplier_record:SUP-002" or "email:EM-2001"
    trust: str      # "trusted" | "untrusted"

    def to_dict(self):
        return asdict(self)


def normalise(value) -> str:
    """Compare values by content: '00-00-99' == '000099'; 1250 == '1,250.00'."""
    if isinstance(value, (int, float)):
        return f"{float(value):.2f}"
    s = str(value).strip()
    num = s.replace(",", "").replace("GBP", "").replace("£", "").strip()
    if re.fullmatch(r"\d+\.\d{1,2}", num):
        return f"{float(num):.2f}"
    if re.fullmatch(r"[\d\s-]+", s):
        return re.sub(r"[\s-]", "", s)
    return s.lower()


_BODY_PATTERNS = [
    r"\b\d{2}-\d{2}-\d{2}\b",            # sort codes
    r"\b\d{8}\b",                         # account numbers
    r"\b\d{1,3}(?:,\d{3})*\.\d{2}\b",     # amounts like 1,250.00
    r"\bINV-\d+\b",                       # invoice refs
]


class Catalogue:
    """Index of every known value -> the sources that contain it."""

    def __init__(self, suppliers: dict, emails: list):
        self._index: dict[str, set[Source]] = {}
        for name, rec in suppliers.items():
            src = Source(f"supplier_record:{rec['supplier_id']}", TRUSTED)
            self._add(name, src)
            for field in ("supplier_id", "sort_code", "account_number"):
                self._add(rec[field], src)
        for em in emails:
            channel = TRUSTED_CHANNELS.get(em.get("source"))
            if channel:
                src = Source(f"{channel}:{em['email_id']}", TRUSTED)
            else:
                src = Source(f"email:{em['email_id']}", UNTRUSTED)
            for k, v in em.items():
                if k in ("email_id", "source", "from", "subject", "body", "added_for_demo"):
                    continue
                self._add(v, src)
            for pat in _BODY_PATTERNS:
                for m in re.findall(pat, em.get("body", "")):
                    self._add(m, src)

    def _add(self, value, src: Source):
        self._index.setdefault(normalise(value), set()).add(src)

    def sources_of(self, value) -> set[Source]:
        # Whole-value match only: exact dict lookup on the normalised value.
        # Never substring/prefix: "0000000" and "000000012" do not match "00000001".
        return self._index.get(normalise(value), set())

    def label(self, value) -> Source:
        """The single label attached to a value an agent passes to a tool."""
        srcs = self.sources_of(value)
        trusted = sorted((s for s in srcs if s.trust == TRUSTED),
                         key=lambda s: (not s.label.startswith("supplier_record:"), s.label))
        if trusted:
            return trusted[0]
        untrusted = sorted(srcs, key=lambda s: s.label)
        if untrusted:
            return untrusted[0]
        return Source("unknown", UNTRUSTED)


def default_catalogue() -> Catalogue:
    from world.company import SUPPLIERS, INBOX
    from world.demo_emails import DEMO_EMAILS
    return Catalogue(SUPPLIERS, INBOX + DEMO_EMAILS)

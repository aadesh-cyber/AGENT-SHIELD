"""Step 2 done-when test: every value the demo uses gets the right source label."""
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from provgate.provenance import default_catalogue, TRUSTED, UNTRUSTED

CASES = [
    # (value, expected label, expected trust)
    ("Harbour Supplies",  "supplier_record:SUP-001", TRUSTED),
    ("00-00-01",          "supplier_record:SUP-001", TRUSTED),
    ("00000001",          "supplier_record:SUP-001", TRUSTED),
    (1250.00,             "portal:EM-1001",          TRUSTED),   # trusted portal
    ("1,250.00",          "portal:EM-1001",          TRUSTED),
    ("INV-7781",          "portal:EM-1001",          TRUSTED),
    ("Bright Office Ltd", "supplier_record:SUP-002", TRUSTED),
    ("00-00-99",          "email:EM-2001",           UNTRUSTED), # attacker's sort code
    ("000099",            "email:EM-2001",           UNTRUSTED), # same, reformatted
    ("99999999",          "email:EM-2001",           UNTRUSTED), # attacker's account
    ("12345678",          "unknown",                 UNTRUSTED), # from nowhere
    # whole-value matching only -- never substring or prefix
    ("0000000",           "unknown",                 UNTRUSTED), # 7 digits, not 00000001
    ("000000012",         "unknown",                 UNTRUSTED), # 9 digits, not 00000001
    (12500,               "unknown",                 UNTRUSTED), # not 1250
    ("12,500.00",         "unknown",                 UNTRUSTED),
    (125,                 "unknown",                 UNTRUSTED),
]

def main():
    cat = default_catalogue()
    fails = 0
    for value, want_label, want_trust in CASES:
        got = cat.label(value)
        ok = got.label == want_label and got.trust == want_trust
        fails += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {str(value):18} -> {got.label:26} {got.trust}")
    assert fails == 0, f"{fails} label(s) wrong"
    print(f"STEP 2 OK: {len(CASES)} values labelled correctly")

if __name__ == "__main__":
    main()

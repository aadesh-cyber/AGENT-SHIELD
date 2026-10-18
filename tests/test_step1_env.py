"""Step 1 done-when test: environment and folder layout are correct."""
import sys, pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]

def main():
    assert sys.version_info >= (3, 10), f"Need Python 3.10+, got {sys.version}"
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    k = Ed25519PrivateKey.generate()
    k.public_key().verify(k.sign(b"ok"), b"ok")
    import anthropic  # noqa: F401  (import only; no API call yet)
    for d in ["provgate", "world", "tests", "runs"]:
        assert (ROOT / d).is_dir(), f"missing folder: {d}"
    print("STEP 1 OK: python", sys.version.split()[0], "| ed25519 sign/verify works | anthropic SDK importable | folders present")

if __name__ == "__main__":
    main()

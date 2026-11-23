#!/usr/bin/env python3
"""
Independent verifier for visa-cli-action-ref-anchor. Recomputes everything
from the declared request in artifacts/manifest.json; trusts none of the
prose fields.

1. action_ref from the four preimage fields (JCS RFC 8785 + SHA-256).
2. request_digest, signature_base_digest, decision_digest.
3. The Content-Digest header against the request body.
4. The RFC 9421 signature base, rebuilt from the request headers and
   compared with the one the vector file declares.
5. The Ed25519 signature over that base, with the public key from the
   vector's listing (needs the `cryptography` package).
6. decision.expect.ok must be exactly the boolean true; any other value fails.
7. With --vectors PATH: the file's SHA-256 equals the recorded one, and the
   manifest's request, signature_base, decision.expect and public key are
   byte-for-byte the named case of that file (they are not trusted from the
   manifest).

Exit codes: 0 every check ran and passed; 1 a check failed; 2 nothing
failed but at least one check was NOT ASSESSED (no `cryptography` package,
or no --vectors): the summary says which, and it is never "ALL CHECKS PASS".

Run: python3 -I verifier/verify.py --vectors their-files/tap-http-request-v1.json
"""
import argparse
import base64
import hashlib
import json
import os
import re
import sys
from urllib.parse import urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))


def jcs(obj):
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


def sha256_hex(data):
    return hashlib.sha256(data.encode() if isinstance(data, str) else data).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifacts", default=os.path.join(HERE, "..", "artifacts"))
    ap.add_argument("--vectors", default=None)
    args = ap.parse_args()
    m = json.load(open(os.path.join(args.artifacts, "manifest.json")))
    ok = True
    not_assessed = []

    def check(label, passed, detail=""):
        nonlocal ok
        ok &= passed
        print(f"[{'PASS' if passed else 'FAIL'}] {label}{(' : ' + detail) if detail else ''}")

    check("action_ref recompute", sha256_hex(jcs(m["preimage"])) == m["action_ref"], m["action_ref"])
    env = m["envelope"]
    check("envelope.action_ref matches", env["action_ref"] == m["action_ref"])
    check("request_digest", sha256_hex(jcs(m["request"])) == env["request_digest"])
    check("signature_base_digest", sha256_hex(m["signature_base"]) == env["signature_base_digest"])
    check("decision_digest", sha256_hex(jcs(m["decision"])) == env["decision_digest"])

    check("decision.expect.ok is exactly true", m["decision"].get("expect", {}).get("ok") is True,
          repr(m["decision"].get("expect", {}).get("ok")))

    req = m["request"]
    hdr = {k.lower(): v for k, v in req["headers"]}
    digest = "sha-256=:" + base64.b64encode(hashlib.sha256(req["body"].encode()).digest()).decode() + ":"
    check("Content-Digest header matches the body", hdr["content-digest"] == digest)

    # Rebuild the RFC 9421 signature base from the request itself.
    u = urlsplit(req["url"])
    params = re.match(r"sig2=(.*)$", hdr["signature-input"]).group(1)
    comps = re.findall(r'"([^"]+)"', params.split(")")[0])
    value = {
        "@method": req["method"].upper(),
        "@scheme": u.scheme,
        "@authority": u.netloc,
        "@path": u.path,
        "@query": "?" + u.query if u.query else "?",
    }
    lines = []
    for c in comps:
        v = value[c] if c in value else hdr[c]
        lines.append(f'"{c}": {v}')
    lines.append(f'"@signature-params": {params}')
    rebuilt = "\n".join(lines)
    check("signature base rebuilt from the request equals the declared one", rebuilt == m["signature_base"])

    # Ed25519 signature.
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        from cryptography.exceptions import InvalidSignature
        pem = base64.b64decode(m["public_key_base64"])
        key = load_pem_public_key(pem)
        sig = base64.b64decode(re.match(r"sig2=:(.*):$", hdr["signature"]).group(1))
        try:
            key.verify(sig, rebuilt.encode())
            check("Ed25519 signature verifies over the rebuilt base", True)
        except InvalidSignature:
            check("Ed25519 signature verifies over the rebuilt base", False)
    except ImportError:
        not_assessed.append("Ed25519 signature: the `cryptography` package is not installed")
        print("[NOT ASSESSED] Ed25519 signature: the `cryptography` package is not installed")

    if args.vectors:
        raw = open(args.vectors, "rb").read()
        got = sha256_hex(raw)
        check("vector file SHA-256 equals the recorded one", got == m["source_vectors"]["sha256"], got)
        cases = [c for c in json.loads(raw)["cases"] if c["name"] == m["source_vectors"]["case"]]
        check("exactly one case with the recorded name in the vector file", len(cases) == 1, str(len(cases)))
        if len(cases) == 1:
            c = cases[0]
            check("manifest.request equals the file's case request", m["request"] == c["request"])
            check("manifest.signature_base equals the file's case signatureBase", m["signature_base"] == c["signatureBase"])
            check("manifest.decision.expect equals the file's case expect", m["decision"]["expect"] == c["expect"])
        listed = json.loads(raw)["listing"]["keys"][0]["publicKey"]
        check("manifest public key equals the file's listing key", m["public_key_base64"] == listed)
    else:
        not_assessed.append("request, signature_base, decision and key were not compared to the published vector file (no --vectors)")
        print("[NOT ASSESSED] request, signature_base, decision and key vs the vector file (run with --vectors)")

    print()
    if not ok:
        print("SOME CHECKS FAILED")
        sys.exit(1)
    if not_assessed:
        print("CHECKS THAT RAN PASSED, BUT NOT EVERYTHING WAS ASSESSED:")
        for n in not_assessed:
            print("  - " + n)
        sys.exit(2)
    print("ALL CHECKS PASS")
    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except (KeyError, ValueError, TypeError, IndexError) as e:
        print(f"[FAIL] manifest or vector file is malformed: {type(e).__name__}: {e}")
        print("SOME CHECKS FAILED")
        sys.exit(1)

#!/usr/bin/env python3
"""
Derives an action_ref (action-ref-v1: RFC 8785 JCS + SHA-256 over four fields)
for one signed request taken verbatim from Visa CLI's published conformance
vectors (tap-http-request-v1.json, the case below), plus an envelope of digests
over the request, the signature base and the expected decision.

Run scripts/fetch_their_files.sh first. All long values are written by this
script from the vector file; nothing is pasted by hand.

PROVENANCE: the request is a TEST vector signed with the public RFC 8032 test
vector 1 key listed in that file. It is not a production request, not from a
real Visa CLI agent, and nothing was sent to any Visa or Turnkey service.
"""
import datetime
import hashlib
import json
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
VECTORS = os.path.join(ROOT, "their-files", "tap-http-request-v1.json")
OUT_DIR = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "artifacts")
CASE_NAME = "accepted: key named by directory ID, with Signature-Agent and an application header"
RUN_RESULT = "94 of 94 passed: 18 accepted, 52 refused, 24 could not check"
os.makedirs(OUT_DIR, exist_ok=True)


def jcs(obj):
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


def sha256_hex(data):
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


raw = open(VECTORS, "rb").read()
vectors = json.loads(raw)
case = next(c for c in vectors["cases"] if c["name"] == CASE_NAME)
req = case["request"]
agent_id = vectors["listing"]["id"]
created = int(case["now"]) - 30  # placeholder, replaced below from Signature-Input
sig_input = dict(req["headers"])["signature-input"]
created = int(sig_input.split("created=")[1].split(";")[0])
timestamp = datetime.datetime.fromtimestamp(created, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

# --- the four action-ref-v1 preimage fields ---------------------------------
preimage = {
    "agent_id": agent_id,
    "action_type": "http.signed_request." + req["method"],
    "scope": "tap-http-request-v1:" + req["url"].split("?")[0],
    "timestamp": timestamp,
}
jcs_payload = jcs(preimage)
action_ref = sha256_hex(jcs_payload)

# --- additive envelope (does not enter the action_ref hash) -----------------
request_digest = sha256_hex(jcs(req))
signature_base_digest = sha256_hex(case["signatureBase"])
decision = {
    "case": case["name"],
    "expect": case["expect"],
    "their_verifier_full_run": RUN_RESULT,
}
decision_digest = sha256_hex(jcs(decision))

manifest = {
    "fixture_id": "visa-cli-tap-signed-request-worked-example",
    "spec": "action-ref-v1 (argentum-core, docs/spec/action-ref.md)",
    "source_vectors": {
        "url": "https://app.visacli.sh/conformance/tap-http-request-v1.json",
        "sha256": sha256_hex(raw),
        "profile": vectors["profile"],
        "case": case["name"],
    },
    "preimage": preimage,
    "jcs_payload": jcs_payload,
    "action_ref": action_ref,
    "envelope": {
        "action_ref": action_ref,
        "request_digest": request_digest,
        "signature_base_digest": signature_base_digest,
        "decision_digest": decision_digest,
    },
    "request": req,
    "signature_base": case["signatureBase"],
    "decision": decision,
    "public_key_base64": vectors["listing"]["keys"][0]["publicKey"],
}
with open(os.path.join(OUT_DIR, "manifest.json"), "w") as f:
    json.dump(manifest, f, indent=2, sort_keys=True)
    f.write("\n")

print(f"jcs_payload = {jcs_payload}")
print(f"action_ref  = {action_ref}")
print(f"wrote {os.path.join(OUT_DIR, 'manifest.json')}")

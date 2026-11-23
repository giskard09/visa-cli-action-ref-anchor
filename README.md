# visa-cli-action-ref-anchor

A worked example that derives an **`action_ref`** (a content-addressed identifier
for an agent action, [`action-ref-v1`](https://github.com/giskard09/argentum-core/blob/main/docs/spec/action-ref.md))
for one signed request taken from the conformance vectors that Visa CLI publishes
for its profile of the Trusted Agent Protocol (`tap-http-request-v1`).

It is a worked example applying a public spec to a public test vector. It does
not imply Visa, Visa CLI or Turnkey integrated, endorsed, or participated. The only
traffic to Visa CLI was downloading its public docs and example files from
`app.visacli.sh`; no request went to its registry, the Visa Agent Directory or
Turnkey, and no one at either company was contacted.

## What the Visa CLI pages describe

From the pages I read (`llms.txt`, `llms-verifier.txt`, "Verify a signed request",
"Verifier code", "Test your verifier", "What's live today"): a service checks an
agent's signed request against a key listed in Visa CLI's registry or the Visa
Agent Directory, and returns accept, refuse or "could not check". That is a
check on the request, before the action runs. In those pages I did not find a
record format for what happened after the check; `payment-receipt` appears in those
pages only in a list of header names the verifier refuses to see signed. I did not
read every page of their docs.

## What this adds

`action_ref` is a hash anyone can recompute from four declared fields
(`agent_id`, `action_type`, `scope`, `timestamp`), so a record of "this signed
request, accepted by this verifier decision" can be checked by a third party
without trusting the party that holds the logs. This repo shows the derivation
on one vector and an envelope of digests next to it:

| Field | What it is |
|---|---|
| `action_ref` | SHA-256 of the JCS (RFC 8785) of the four preimage fields |
| `request_digest` | SHA-256 of the JCS of the request (url, method, headers, body) as the vector file declares it |
| `signature_base_digest` | SHA-256 of the RFC 9421 signature base the vector file declares |
| `decision_digest` | SHA-256 of the JCS of the expected decision plus the result of running Visa CLI's verifier (below) |

The envelope digests are this repo's own addition. They do not enter the
`action_ref` hash.

## What I ran

1. Downloaded Visa CLI's `verify-agent.mjs`, `run-vectors.mjs` and
   `tap-http-request-v1.json` (SHA-256 pinned in `scripts/fetch_their_files.sh`),
   read them (their imports from outside the folder are `node:crypto` and `node:fs`), and ran
   `node run-vectors.mjs` with Node 22. Result, the last line of its output:
   `94 of 94 passed: 18 accepted, 52 refused, 24 could not check`.
2. The chosen case is `accepted: key named by directory ID, with Signature-Agent and an application header`.
   `run-vectors.mjs` prints a PASS or FAIL line per case; in the run above all 94
   printed PASS, including this one.
3. `python3 -I verifier/verify.py --vectors their-files/tap-http-request-v1.json`
   (stdlib plus the `cryptography` package): recomputes the digests, rebuilds the
   signature base from the request headers, checks the Ed25519 signature with the
   public key in the vector's listing, and compares the manifest's request,
   signature base, expected decision and key with the named case of the vector file.
4. `action_ref` was also computed with argentum-core's own implementation
   (`plugins/agt_evidence_anchor/action_ref.py`, `compute_action_ref`), same value.

## Reproduce

```bash
bash scripts/fetch_their_files.sh          # then read the files in their-files/
(cd their-files && node run-vectors.mjs | tail -1)
python3 -I scripts/produce.py              # writes artifacts/manifest.json
python3 -I verifier/verify.py --vectors their-files/tap-http-request-v1.json
```

## What the verifier does and does not guarantee

- Exit code 0 and `ALL CHECKS PASS`: every check ran and passed, including the
  Ed25519 signature and the comparison with the vector file you downloaded.
- Exit code 1: a check failed, or the manifest or vector file is malformed.
- Exit code 2: nothing failed, but something was not assessed (the `cryptography`
  package is missing, or `--vectors` was not given). The output names it, and it
  never prints `ALL CHECKS PASS`. In an earlier version (commit `f84780f`) both cases
  ended in `ALL CHECKS PASS` with exit code 0.
- `decision.expect.ok` must be exactly the boolean `true`; any other value fails.
- It does not run Visa CLI's verifier. `decision.their_verifier_full_run` is a
  string the emitter declared, which this script cannot confirm. The result of the
  run is in the section above, as I observed it.
- It does not show the request came from a real Visa CLI agent: it is a test vector.

## Limits

- The request is a test vector signed with the public RFC 8032 test vector 1 key.
  It is not a production request and not from a real Visa CLI agent.
- This example is not anchored on-chain. `action_ref` here does not establish
  when it was created; an anchor would add a timestamp that does not depend on
  this repo.
- The "decision" is the `expect` field of the vector file plus the result of the
  full run of Visa CLI's example verifier, not a per-case output of it; the second
  part is declared, not checked by `verifier/verify.py`.
- Visa CLI's pages say their example verifier "isn't a verifier Visa publishes".
  Everything here refers to it as Visa CLI's example verifier.
- See `PROVENANCE.md`.

## License

MIT.

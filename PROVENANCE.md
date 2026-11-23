# Provenance

## Real

- `their-files/tap-http-request-v1.json` is downloaded from
  `https://app.visacli.sh/conformance/tap-http-request-v1.json`; its SHA-256 is
  recorded in `artifacts/manifest.json` and checked by `verifier/verify.py --vectors`.
  The files in `their-files/` are not committed to this repo.
- Visa CLI's example verifier was run, unmodified, on 2026-11-23 on Node 22:
  94 of 94 passed.
- `action_ref` follows `action-ref-v1` and matches argentum-core's
  `compute_action_ref`.

## Synthetic

- The request, key and listing are Visa CLI's published test data. The key is
  RFC 8032 test vector 1 and is public.
- `agent_id` (`vector-agent`) is the id in the vector file's listing; `action_type`
  and `scope` are labels chosen here.
- `timestamp` is the `created` parameter of the signature, converted to RFC 3339.
- No Visa CLI agent, registry, Visa Agent Directory or Turnkey service was
  contacted. Visa CLI, Visa and Turnkey did not review, produce or approve this.

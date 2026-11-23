#!/usr/bin/env bash
# Downloads Visa CLI's published example verifier and conformance vectors into
# ./their-files/ and checks them against the SHA-256 values this example was
# built from. Read the files before you run them (their docs say the same:
# "There's no published checksum or signature, so read the code before you run it").
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p their-files && cd their-files
BASE="https://app.visacli.sh"
curl -fsSO "$BASE/examples/verify-agent.mjs"
curl -fsSO "$BASE/examples/run-vectors.mjs"
curl -fsSO "$BASE/conformance/tap-http-request-v1.json"
sha256sum -c <<'SUMS'
0145514611ff80824555c2613195f91ec132054e712607dd02d2ae711d748d9c  verify-agent.mjs
4b93bbaee26e88400648596faf43ac682e6c50de4040ad7c85b3262bae75925a  run-vectors.mjs
ac7f70dc2a9f0a88f3c3c3f190f793580dff5b3a95f4bc7fff808f0ae48a006c  tap-http-request-v1.json
SUMS
echo "Now read them, then run:  cd their-files && node run-vectors.mjs   (Node 22)"

#!/usr/bin/env bash
# Superseded by scripts/deploy/06_prove_payment.sh.
#
# This used to hardcode one staged intent and read its parameters from
# scripts/testnet/live.intent.env, which is gitignored and local to whoever
# staged that intent. It could not prove any other payment.
#
# The replacement takes the intent hash and reads the rest off chain:
#
#   scripts/deploy/06_prove_payment.sh --intent 0x<intentHash>
#
# It prompts for the Venmo cookie without echoing it, keeps it in the process
# environment only, and never writes it to disk or to any log. It also reads the
# intent's on-chain signal timestamp, which the verifier checks and which the
# old script did not pass.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

echo "This script has been replaced by scripts/deploy/06_prove_payment.sh." >&2
echo >&2
echo "  scripts/deploy/06_prove_payment.sh --intent 0x<intentHash>" >&2
echo >&2
echo "See scripts/proof/README.md, or DEPLOY.md step 06." >&2

if [ -n "${1:-}" ]; then
  echo "Forwarding your arguments to it." >&2
  exec "$ROOT/scripts/deploy/06_prove_payment.sh" "$@"
fi
exit 2

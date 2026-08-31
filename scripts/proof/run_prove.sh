#!/usr/bin/env bash
# One-step proof runner for the 2026-08-31 staged intent (deposit 2, @test-payee).
#
# Run this yourself. It reads the Venmo cookie from your terminal without
# echoing it, keeps it in the process environment only, and never writes it
# to disk or to any log.
#
#   scripts/proof/run_prove.sh
#
# PAYMENT_INDEX defaults to 0 (most recent). If the proof reports the wrong
# payment, re-run with PAYMENT_INDEX=1, then 2.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
set -a; . "$ROOT/scripts/testnet/live.intent.env"; set +a

export INTENT_HASH PAYEE_HASH
export INTENT_AMOUNT="${AMOUNT}"
export PAYMENT_INDEX="${PAYMENT_INDEX:-0}"

echo "intent : $INTENT_HASH"
echo "payee  : $PAYEE_HASH (@${VENMO_PAYEE})"
echo "amount : $INTENT_AMOUNT (\$1.00)"
echo "index  : $PAYMENT_INDEX"
echo

if [ -z "${VENMO_SENDER_ID:-}" ]; then
  read -r -p "Venmo numeric SENDER_ID: " VENMO_SENDER_ID
  export VENMO_SENDER_ID
fi
if [ -z "${VENMO_COOKIE:-}" ]; then
  # -s: no echo, so the cookie never appears on screen or in shell history.
  read -r -s -p "Venmo Cookie header (input hidden): " VENMO_COOKIE
  echo
  export VENMO_COOKIE
fi

cd "$ROOT/scripts/proof"
exec node prove_payment.mjs

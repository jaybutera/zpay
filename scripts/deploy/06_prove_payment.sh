#!/usr/bin/env bash
# Step 06: turn a real Venmo payment into an attestation `fulfillIntent` accepts.
#
# Run this yourself, on the machine holding the Venmo session. It reads the
# cookie from your terminal without echoing it, keeps it in the process
# environment only, and never writes it to disk or to any log. The cookie is
# encrypted client-side to the enclave's attested key before it leaves.
#
#   scripts/deploy/06_prove_payment.sh --intent 0x<intentHash>
#   scripts/deploy/06_prove_payment.sh --intent 0x... --index 1
#
# It reads the intent's amount, payee hash and on-chain signal timestamp off
# the orchestrator, so you do not have to. That timestamp matters: the verifier
# compares the attested snapshot against the stored intent and reverts with
# "UPV: Snapshot timestamp mismatch" if they differ.
#
# Options:
#   --intent 0x...   the intent hash from the IntentSignaled log (required)
#   --index N        which payment in your Venmo feed, 0 = most recent (default 0)
#   --out FILE       where to write the attestation (default scripts/proof/attestation.json)
#   --check          only verify the enclave; sends nothing personal
#
# Env: ATTESTATION_URL, ATTESTATION_VERIFIER_ADDRESS, ZKP2P_ORCHESTRATOR_ADDRESS,
#      BASE_RPC_URL, CHAIN_ID. VENMO_SENDER_ID and VENMO_COOKIE are prompted for
#      if unset.
#
# The attestation is bound by EIP-712 to CHAIN_ID plus the verifier address. The
# enclave signs only for Base mainnet (8453), so a proof cannot be replayed onto
# another chain.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "$ROOT/scripts/deploy/lib.sh"
load_deployed

INTENT=""; INDEX="${PAYMENT_INDEX:-0}"; OUT="$ROOT/scripts/proof/attestation.json"; CHECK_ONLY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --intent) INTENT="$2"; shift 2;;
    --index)  INDEX="$2"; shift 2;;
    --out)    OUT="$2"; shift 2;;
    --check)  CHECK_ONLY=1; shift;;
    --help|-h) sed -n '2,30p' "$0"; exit 0;;
    *) die "unknown argument: $1";;
  esac
done

require_tools node cast
[ -d "$ROOT/scripts/proof/node_modules" ] \
  || die "run 'npm install' in scripts/proof first (needs @zkp2p/zkp2p-attestation)"

# ---------------------------------------------------------------- enclave check
log "checking the enclave (sends nothing personal)"
( cd "$ROOT/scripts/proof" && \
  ATTESTATION_URL="$ATTESTATION_URL" VERIFIER="$ATTESTATION_VERIFIER_ADDRESS" \
  node check_enclave.mjs ) || die "the enclave did not verify; refusing to send anything to it"

[ -n "$CHECK_ONLY" ] && { echo; echo "enclave ok. Re-run with --intent to prove a payment."; exit 0; }
[ -n "$INTENT" ] || die "pass --intent 0x<intentHash>. It is the first indexed topic of the IntentSignaled log."
[[ "$INTENT" =~ ^0x[0-9a-fA-F]{64}$ ]] || die "--intent is not a 32-byte hex value: $INTENT"

# ---------------------------------------------------------------- read the intent
require_chain
require_address ZKP2P_ORCHESTRATOR_ADDRESS

log "reading intent $INTENT off the orchestrator"
INTENT_TUPLE="$(cast call --rpc-url "$BASE_RPC_URL" "$ZKP2P_ORCHESTRATOR_ADDRESS" \
  'getIntent(bytes32)((address,address,address,uint256,uint256,uint256,bytes32,bytes32,uint256,address,bytes))' \
  "$INTENT" 2>/dev/null)" || die "could not read the intent; is it signalled on chain $CHAIN_ID?"

# Fields, in order: owner, to, escrow, depositId, amount, timestamp,
# paymentMethod, fiatCurrency, conversionRate, referrer, data.
field() { printf '%s' "$INTENT_TUPLE" | tr -d '()' | cut -d, -f"$1" | tr -d ' ' | cut -d'[' -f1; }
AMOUNT="$(field 5)"
TIMESTAMP="$(field 6)"
[ -n "$AMOUNT" ] && [ "$AMOUNT" != "0" ] || die "intent $INTENT has no amount; it may not exist or may already be fulfilled"
[ -n "$TIMESTAMP" ] && [ "$TIMESTAMP" != "0" ] || die "could not read the intent's timestamp"
TIMESTAMP_MS=$(( TIMESTAMP * 1000 ))

# payeeDetails lives on the deposit's payment method, not on the intent, so take
# it from the deposit the intent points at.
ESCROW_ADDR="$(field 3)"
DEPOSIT_ID="$(field 4)"
PAYEE="${PAYEE_HASH:-}"
if [ -z "$PAYEE" ]; then
  VENMO_METHOD="$(cast keccak venmo)"
  PAYEE="$(cast call --rpc-url "$BASE_RPC_URL" "${ESCROW_ADDR:-$ZKP2P_ESCROW_ADDRESS}" \
    'getDepositPaymentMethodData(uint256,bytes32)((address,bytes32,bytes))' \
    "$DEPOSIT_ID" "$VENMO_METHOD" 2>/dev/null | tr -d '()' | cut -d, -f2 | tr -d ' ')" || true
fi
[[ "${PAYEE:-}" =~ ^0x[0-9a-fA-F]{64}$ ]] \
  || die "could not read the payee hash off deposit $DEPOSIT_ID. Pass PAYEE_HASH=0x... explicitly."

echo
ok "intent      $INTENT"
ok "deposit     $DEPOSIT_ID on escrow $ESCROW_ADDR"
ok "amount      $AMOUNT units = \$$(python3 -c "print(f'{int('$AMOUNT')/1e6:.2f}')")"
ok "payee hash  $PAYEE"
ok "signalled   ${TIMESTAMP}s -> ${TIMESTAMP_MS}ms"
note "the Venmo payment must be for exactly \$$(python3 -c "print(f'{int('$AMOUNT')/1e6:.2f}')") to the payee behind that hash"

# ---------------------------------------------------------------- session material
if [ -z "${VENMO_SENDER_ID:-}" ]; then
  echo
  echo "Your NUMERIC Venmo sender id (not the @handle). From a logged-in tab, in the console:"
  echo "  await (await fetch('/api/stories?feedType=me',{credentials:'include'}))"
  echo "    .json().then(d => d.stories[0].title.sender.id)"
  read -r -p "VENMO_SENDER_ID: " VENMO_SENDER_ID
  export VENMO_SENDER_ID
fi
if [ -z "${VENMO_COOKIE:-}" ]; then
  echo
  echo "The Cookie header from any account.venmo.com request (DevTools -> Network ->"
  echo "reload -> Headers -> Request Headers -> Cookie). Input is hidden and is never"
  echo "written to disk or logged."
  read -r -s -p "VENMO_COOKIE (hidden): " VENMO_COOKIE
  echo
  export VENMO_COOKIE
fi

# ---------------------------------------------------------------- prove
log "asking the enclave to attest the payment (feed index $INDEX)"
cd "$ROOT/scripts/proof"
INTENT_HASH="$INTENT" \
PAYEE_HASH="$PAYEE" \
INTENT_AMOUNT="$AMOUNT" \
INTENT_TIMESTAMP_MS="$TIMESTAMP_MS" \
PAYMENT_INDEX="$INDEX" \
CHAIN_ID="$CHAIN_ID" \
VERIFIER="$ATTESTATION_VERIFIER_ADDRESS" \
ATTESTATION_URL="$ATTESTATION_URL" \
OUT="$OUT" \
node prove_payment.mjs

echo
echo "wrote $OUT"
echo "Claim with: zecp2p-taker fulfill --intent $INTENT --proof $OUT"
echo "If the attestation named the wrong payment, re-run with --index 1, then 2."

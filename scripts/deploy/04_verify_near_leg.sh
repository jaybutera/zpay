#!/usr/bin/env bash
# Step 04: verify the NEAR/1Click inbound leg against the deployed glue.
#
# Read-only. Every 1Click call here is a dry quote, which the API documents as
# simulating "without generating a deposit address". Nothing is committed and no
# ZEC is ever sent by this script. Pass --live to additionally request one
# non-dry quote, which returns a real deposit address; that still costs nothing
# unless someone funds the address, and the address expires on its own.
#
#   scripts/deploy/04_verify_near_leg.sh
#   scripts/deploy/04_verify_near_leg.sh --live      # also mint one real deposit address
#
# Checks:
#   - the asset ids the coordinator uses are in 1Click's registry
#   - the deployed glue is accepted as a delivery recipient (this is the one
#     that can silently sink the design: 1Click denylists some destinations)
#   - a shielded refund address is rejected, so the coordinator's own validation
#     matches the API's
#   - what a quote actually returns at the sizes this deployment will see
#
# Env: NEAR_API_URL, USDC_ADDRESS, GLUE_CONTRACT_ADDRESS, ZEC_REFUND_ADDRESS.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "$ROOT/scripts/deploy/lib.sh"
load_deployed

LIVE=""
for a in "$@"; do
  case "$a" in
    --live) LIVE=1;;
    --help|-h) sed -n '2,20p' "$0"; exit 0;;
  esac
done

require_tools curl python3
require_address GLUE_CONTRACT_ADDRESS
require_address USDC_ADDRESS

# Any syntactically valid transparent address works for a dry quote; 1Click only
# checks the form. A real run must use one whose key the operator holds, because
# this is where a failed swap comes back.
REFUND="${ZEC_REFUND_ADDRESS:-t1KhV8ADhTGvVvBpTiEcJGnhTvBBFVFYHXx}"
ZEC_ASSET="nep141:zec.omft.near"
USDC_ASSET="nep141:base-$(printf '%s' "$USDC_ADDRESS" | tr 'A-Z' 'a-z').omft.near"
FAIL=0
fail() { bad "$*"; FAIL=1; }

echo "verify the NEAR/1Click inbound leg"
echo "api       : $NEAR_API_URL"
echo "origin    : $ZEC_ASSET"
echo "destination: $USDC_ASSET"
echo "recipient : $GLUE_CONTRACT_ADDRESS (the glue)"
echo "refundTo  : $REFUND"

quote() { # amount-in-zatoshi, recipient, refundTo, dry
  curl -s -m 40 -X POST "$NEAR_API_URL/v0/quote" -H 'Content-Type: application/json' -d "{
    \"dry\": $4, \"swapType\": \"EXACT_INPUT\", \"slippageTolerance\": ${SLIPPAGE_BPS:-50},
    \"depositType\": \"ORIGIN_CHAIN\",
    \"originAsset\": \"$ZEC_ASSET\", \"destinationAsset\": \"$USDC_ASSET\",
    \"amount\": \"$1\",
    \"refundTo\": \"$3\", \"refundType\": \"ORIGIN_CHAIN\",
    \"recipient\": \"$2\", \"recipientType\": \"DESTINATION_CHAIN\",
    \"deadline\": \"$(date -u -d '+2 days' +%Y-%m-%dT%H:%M:%S.000Z 2>/dev/null || date -u -v+2d +%Y-%m-%dT%H:%M:%S.000Z)\"
  }"
}

log "asset registry"
# Passed with -c rather than on stdin: a heredoc would claim stdin, and python
# would read the piped JSON as its own source.
ASSET_CHECK='
import sys, json
want = sys.argv[1:]
ids = {t.get("assetId", ""): t for t in json.load(sys.stdin)}
missing = [a for a in want if a not in ids]
if missing:
    print("  missing:", missing); raise SystemExit(1)
for a in want:
    t = ids[a]
    print("  " + a + "  decimals=" + str(t.get("decimals")) + " price=" + str(t.get("price")))
'
TOKENS="$(curl -s -m 30 "$NEAR_API_URL/v0/tokens" || true)"
if printf '%s' "$TOKENS" | python3 -c "$ASSET_CHECK" "$ZEC_ASSET" "$USDC_ASSET"; then
  ok "both assets are in the registry"
else
  fail "the registry does not list both assets"
fi

log "is the glue an acceptable delivery recipient?"
# This is the check that matters most. 1Click delivers with a plain ERC-20
# transfer, and it denylists the zero address and the destination token itself.
# A contract recipient is fine, but only the API can confirm this one is.
R="$(quote 1000000 "$GLUE_CONTRACT_ADDRESS" "$REFUND" true)"
if printf '%s' "$R" | grep -q '"quote"'; then
  ok "1Click accepts $GLUE_CONTRACT_ADDRESS as the recipient"
else
  fail "1Click rejected the glue as a recipient: $(printf '%s' "$R" | head -c 300)"
  note "a 'recipient is not valid' here means either a denylisted address or a bad EIP-55 checksum;"
  note "the API returns the same message for both."
fi

log "does the API reject a shielded refund address, as the coordinator assumes?"
R="$(quote 1000000 "$GLUE_CONTRACT_ADDRESS" "zs1z7rejlpsa98s2rrrfkwmaxu53e4ue0ulcrw0h4x5g8jl04tak0d3mm47vdtahatqrlkngh9sly" true)"
if printf '%s' "$R" | grep -qi 'refundTo is not valid'; then
  ok "shielded refundTo is rejected by the API, matching the coordinator's own validation"
else
  fail "expected the API to reject a shielded refundTo; got: $(printf '%s' "$R" | head -c 200)"
fi

log "what a quote returns at the sizes this deployment will see"
QUOTE_ROW='
import sys, json
amt = int(sys.argv[1])
d = json.load(sys.stdin)
if "quote" not in d:
    print("  %-12d FAILED: %s" % (amt, json.dumps(d)[:160]))
    raise SystemExit(1)
q = d["quote"]
uin = float(q.get("amountInUsd") or 0)
uout = float(q.get("amountOutUsd") or 0)
loss = (uin - uout) / uin * 100 if uin else 0
print("  %-12d %-12.8g $%-13.4f %-14s %.2f%%" % (amt, amt/1e8, uin, q.get("amountOutFormatted"), loss))
'
printf '  %-12s %-12s %-14s %-14s %s\n' "zatoshi" "ZEC" "in (USD)" "out (USDC)" "loss"
for A in ${QUOTE_SIZES:-52000 1000000 5000000 12000000}; do
  R="$(quote "$A" "$GLUE_CONTRACT_ADDRESS" "$REFUND" true)"
  printf '%s' "$R" | python3 -c "$QUOTE_ROW" "$A" || fail "quote at $A zatoshi failed"
done
note "1Click rejects anything below 52000 zatoshi with an explicit floor in the error"
note "the quote carries a 10 bps appFee to a NEAR account this project does not control"

if [ -n "$LIVE" ]; then
  log "requesting ONE real deposit address (--live)"
  note "this commits nothing. The address simply expires if no ZEC arrives."
  R="$(quote "${LIVE_AMOUNT:-52000}" "$GLUE_CONTRACT_ADDRESS" "$REFUND" false)"
  printf '%s' "$R" | python3 -c '
import sys, json
d = json.load(sys.stdin)
q = d.get("quote", {})
if not q:
    print("  failed:", json.dumps(d)[:300]); raise SystemExit(1)
print("  depositAddress :", q.get("depositAddress"))
print("  depositMemo    :", q.get("depositMemo"))
print("  amountIn       :", q.get("amountInFormatted"), "ZEC")
print("  amountOut      :", q.get("amountOutFormatted"), "USDC")
print("  minAmountOut   :", q.get("minAmountOut"))
print("  deadline       :", q.get("deadline"))
print("  timeWhenInactive:", q.get("timeWhenInactive"))
' || fail "live quote failed"
  note "send ZEC here only if you intend to spend it. Poll with:"
  note "  curl -s '$NEAR_API_URL/v0/status?depositAddress=<addr>'"
fi

echo
if [ "$FAIL" = 0 ]; then
  echo "NEAR leg verified. Next: scripts/deploy/05_rehearse_on_fork.sh"
else
  echo "NEAR leg checks FAILED."
  exit 1
fi

#!/usr/bin/env bash
# Read-only checks of the zk-p2p addresses in config.toml / config.testnet.toml.
# Spends nothing. Run before deploying anywhere.
#
# Usage: scripts/testnet/00_verify_zkp2p_addresses.sh
# Env:   BASE_RPC_URL (default https://mainnet.base.org)
#        BASE_SEPOLIA_RPC_URL (default https://sepolia.base.org)
set -uo pipefail
export FOUNDRY_DISABLE_NIGHTLY_WARNING=1
MAIN="${BASE_RPC_URL:-https://mainnet.base.org}"
SEP="${BASE_SEPOLIA_RPC_URL:-https://sepolia.base.org}"
VENMO=$(cast keccak venmo)
USD=$(cast keccak USD)
FAIL=0

check() { # label, expected, actual
  if [ "$2" = "$3" ]; then printf '  ok   %s = %s\n' "$1" "$3"; else printf '  FAIL %s = %s (expected %s)\n' "$1" "$3" "$2"; FAIL=1; fi
}
call() { cast call --rpc-url "$1" "$2" "$3" "${@:4}" 2>/dev/null | head -1 | cut -d' ' -f1; }

echo "== Base mainnet ($MAIN)"
ESCROW=0x777777779d229cdF3110e9de47943791c26300Ef
ORCH=0x014025fDE093f8701d86e9f38e2C3a9b779cb5c7
OLD_ESCROW=0x59Cf3c90E8e7D27773b5E468D1a24B247db9B78d
check "chain id" 8453 "$(cast chain-id --rpc-url "$MAIN")"
echo "  EscrowV2 depositCounter = $(call "$MAIN" $ESCROW 'depositCounter()(uint256)') (production makers deposit here)"
echo "  old escrow $OLD_ESCROW depositCounter = $(call "$MAIN" $OLD_ESCROW 'depositCounter()(uint256)') (never used; do not target)"
REG=$(call "$MAIN" $ESCROW 'orchestratorRegistry()(address)')
check "OrchestratorV3 registered with EscrowV2" true "$(call "$MAIN" "$REG" 'isOrchestrator(address)(bool)' $ORCH)"
echo "  OrchestratorV3 lifecycleHook = $(call "$MAIN" $ORCH 'lifecycleHook()(address)') (taker allowlist/stake gate)"
PVR=$(call "$MAIN" $ESCROW 'paymentVerifierRegistry()(address)')
check "venmo is a registered payment method" true "$(call "$MAIN" "$PVR" 'isPaymentMethod(bytes32)(bool)' "$VENMO")"
check "USD accepted for venmo" true "$(call "$MAIN" "$PVR" 'isCurrency(bytes32,bytes32)(bool)' "$VENMO" "$USD")"
echo "  venmo verifier = $(call "$MAIN" "$PVR" 'getVerifier(bytes32)(address)' "$VENMO")"

echo
echo "== Base Sepolia ($SEP)"
check "chain id" 84532 "$(cast chain-id --rpc-url "$SEP")"
for A in 0x6a5e11c3D87e22b828d02ee65a4e8f322BF6B97E 0x15EF83EBB422B4AC8e3b8393d016Ed076dc50CB7; do
  SIZE=$(cast code --rpc-url "$SEP" $A 2>/dev/null | wc -c)
  echo "  zk-p2p escrow candidate $A: code bytes=$SIZE depositCounter=$(call "$SEP" $A 'depositCounter()(uint256)')"
done
echo "  Both Sepolia escrows expose createDeposit signatures that differ from EscrowV2"
echo "  (10-field struct with referrer/referrerFee, and a pre-struct V1 signature)."
echo "  The testnet plan deploys a stand-in escrow instead; see docs/testnet-deploy-plan.md."
CIRCLE=0x036CbD53842c5426634e7929541eC2318f3dCF7e
check "Circle USDC symbol" '"USDC"' "$(call "$SEP" $CIRCLE 'symbol()(string)')"
check "Circle USDC decimals" 6 "$(call "$SEP" $CIRCLE 'decimals()(uint8)')"

echo
echo "== zk-p2p curator (https://api.zkp2p.xyz)"
RESP=$(curl -s -m 20 -X POST https://api.zkp2p.xyz/v2/makers/validate -H 'Content-Type: application/json' \
  -d '{"processorName":"venmo","offchainId":"this-user-should-not-exist-zecp2p"}')
echo "  validate(nonexistent) -> $RESP"
echo "$RESP" | grep -q '"responseObject":false' && echo "  ok   curator reachable and rejecting unknown usernames" || { echo "  FAIL unexpected curator answer"; FAIL=1; }

echo
[ $FAIL = 0 ] && echo "all checks passed" || { echo "some checks FAILED"; exit 1; }

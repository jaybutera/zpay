#!/usr/bin/env bash
# Does a deposit created by OfframpGlue accept a taker nobody arranged in advance?
#
# Creates a deposit through the glue on an anvil fork of Base mainnet, exactly as
# state.rs does (intentGatingService = address(0)), then has a freshly generated
# address that appears nowhere in the deposit call signalIntent on it.
#
# Costs nothing and touches no live chain.
#
# Usage: scripts/taker/prove_open_signaling.sh
# Env:   FORK_RPC_URL (default https://mainnet.base.org)
#        ANVIL_PORT   (default 8547)
#        KEEP_FORK=1  leave anvil running
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FORK_RPC_URL="${FORK_RPC_URL:-https://mainnet.base.org}"
ANVIL_PORT="${ANVIL_PORT:-8547}"
RPC="http://127.0.0.1:${ANVIL_PORT}"
export FOUNDRY_DISABLE_NIGHTLY_WARNING=1

USDC=0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913
ESCROW=0x777777779d229cdF3110e9de47943791c26300Ef
ORCHESTRATOR=0x014025fDE093f8701d86e9f38e2C3a9b779cb5c7
VENMO=$(cast keccak venmo)
USD=$(cast keccak USD)

KEEPER_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
USER=0x70997970C51812dc3A010C7d01b50e0d17dc79C8
# A taker the deposit has never heard of.
TAKER_KEY=0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba
TAKER=$(cast wallet address --private-key "$TAKER_KEY")

AMOUNT=25000000 # 25 USDC
cleanup() { [ "${KEEP_FORK:-0}" != "1" ] && [ -n "${ANVIL_PID:-}" ] && kill "$ANVIL_PID" 2>/dev/null || true; }
trap cleanup EXIT
log() { printf '\n== %s\n' "$*"; }

if cast block-number --rpc-url "$RPC" >/dev/null 2>&1; then
  log "using anvil already listening on $RPC"
else
  log "starting anvil fork of $FORK_RPC_URL on port $ANVIL_PORT"
  anvil --fork-url "$FORK_RPC_URL" --port "$ANVIL_PORT" --silent &
  ANVIL_PID=$!
  for _ in $(seq 1 60); do sleep 1; cast block-number --rpc-url "$RPC" >/dev/null 2>&1 && break; done
fi
[ "$(cast chain-id --rpc-url "$RPC")" = "8453" ] || { echo "fork is not Base mainnet"; exit 1; }
echo "fork block: $(cast block-number --rpc-url "$RPC")"
echo "taker (generated, unknown to the deposit): $TAKER"

log "deploying OfframpGlue"
DEPLOY_OUT=$(cd "$ROOT/contracts" && PRIVATE_KEY=$KEEPER_KEY forge script script/Deploy.s.sol:DeployOfframpGlue \
  --rpc-url "$RPC" --broadcast 2>&1)
GLUE=$(echo "$DEPLOY_OUT" | sed -n 's/.*OfframpGlue deployed at: *\(0x[0-9a-fA-F]\{40\}\).*/\1/p' | head -1)
[ -n "$GLUE" ] || { echo "$DEPLOY_OUT"; exit 1; }
echo "OfframpGlue: $GLUE"

SESSION_ID=$(cast keccak "open-signaling-$(date +%s)")
PAYEE_HASH=$(cast keccak "mock-zkp2p-payee:open-signaling")
MIN_RATE=1000000000000000000

log "createSession + fund the glue (fake NEAR leg)"
cast send --rpc-url "$RPC" --private-key "$KEEPER_KEY" "$GLUE" \
  'createSession(bytes32,address,bytes32,uint256,uint256)' \
  "$SESSION_ID" "$USER" "$PAYEE_HASH" "$MIN_RATE" "$AMOUNT" >/dev/null
cast rpc --rpc-url "$RPC" anvil_impersonateAccount "$ESCROW" >/dev/null
cast rpc --rpc-url "$RPC" anvil_setBalance "$ESCROW" 0x1000000000000000000 >/dev/null
cast send --rpc-url "$RPC" --unlocked --from "$ESCROW" "$USDC" 'transfer(address,uint256)(bool)' "$GLUE" "$AMOUNT" >/dev/null
cast rpc --rpc-url "$RPC" anvil_stopImpersonatingAccount "$ESCROW" >/dev/null

log "processOfframp -> EscrowV2.createDeposit with intentGatingService = address(0)"
DEPOSIT_ID=$(cast call --rpc-url "$RPC" "$ESCROW" 'depositCounter()(uint256)')
cast send --rpc-url "$RPC" --private-key "$KEEPER_KEY" "$GLUE" \
  'processOfframp(bytes32,bytes32[],(address,bytes32,bytes)[],(bytes32,uint256,(address,bytes,int16,uint32))[][])' \
  "$SESSION_ID" "[$VENMO]" "[(0x0000000000000000000000000000000000000000,$PAYEE_HASH,0x)]" \
  "[[($USD,$MIN_RATE,(0x0000000000000000000000000000000000000000,0x,0,0))]]" >/dev/null
echo "deposit id: $DEPOSIT_ID"

# Confirm on-chain that this deposit carries no gating service.
PAYEE_TOPIC=$(cast keccak 'DepositPaymentMethodAdded(uint256,bytes32,bytes32,address)')
BLOCK=$(cast block-number --rpc-url "$RPC")
GATING=$(cast logs --rpc-url "$RPC" --from-block $((BLOCK-3)) --to-block "$BLOCK" --address "$ESCROW" "$PAYEE_TOPIC" \
  | sed -n 's/^  data: 0x0\{24\}\([0-9a-f]\{40\}\)$/\1/p' | tail -1)
echo "intentGatingService on the deposit: 0x$GATING"
[ "$GATING" = "0000000000000000000000000000000000000000" ] || { echo "FAIL: deposit is gated"; exit 1; }

log "the unknown taker stakes USDC in the zk-p2p StakeVault"
# OrchestratorV3's lifecycleHook (0x5Dd6...0031) routes signalIntent through a
# dispute-protection policy that locks taker stake equal to the intent amount.
# Without it: InsufficientFreeStake(taker, 0, amount). The stake token is USDC.
VAULT=0x47c26258222e2f96424bD2B21bf173f0DA5034C7
cast rpc --rpc-url "$RPC" anvil_setBalance "$TAKER" 0x1000000000000000000 >/dev/null
cast rpc --rpc-url "$RPC" anvil_impersonateAccount "$ESCROW" >/dev/null
cast rpc --rpc-url "$RPC" anvil_setBalance "$ESCROW" 0x1000000000000000000 >/dev/null
cast send --rpc-url "$RPC" --unlocked --from "$ESCROW" "$USDC" 'transfer(address,uint256)(bool)' "$TAKER" "$AMOUNT" >/dev/null
cast rpc --rpc-url "$RPC" anvil_stopImpersonatingAccount "$ESCROW" >/dev/null
cast send --rpc-url "$RPC" --private-key "$TAKER_KEY" "$USDC" 'approve(address,uint256)(bool)' "$VAULT" "$AMOUNT" >/dev/null
cast send --rpc-url "$RPC" --private-key "$TAKER_KEY" "$VAULT" 'depositStake(uint256)' "$AMOUNT" >/dev/null
echo "taker freeStake: $(cast call --rpc-url "$RPC" "$VAULT" 'freeStake(address)(uint256)' "$TAKER")"

log "the unknown taker calls signalIntent on OrchestratorV3"
# IntentParams struct, signature verified against production calldata
# (selector 0xf3ff8655, tx 0x6e635dfa...cdb31f on Base):
#   escrow, depositId, amount, to, paymentMethod, fiatCurrency, conversionRate,
#   (address,uint256)[] referrers, bytes gatingSignature, uint256 signatureExpiration,
#   address postIntentHook, bytes data, bytes postIntentHookData
# gatingSignature is empty because the deposit sets intentGatingService = address(0).
SIG='signalIntent((address,uint256,uint256,address,bytes32,bytes32,uint256,(address,uint256)[],bytes,uint256,address,bytes,bytes))'
ARGS="($ESCROW,$DEPOSIT_ID,$AMOUNT,$TAKER,$VENMO,$USD,$MIN_RATE,[],0x,0,0x0000000000000000000000000000000000000000,0x,0x)"
set +e
OUT=$(cast send --rpc-url "$RPC" --private-key "$TAKER_KEY" "$ORCHESTRATOR" "$SIG" "$ARGS" 2>&1)
RC=$?
set -e
echo "$OUT" | tail -20

if [ $RC -ne 0 ]; then
  echo
  echo "signalIntent did not go through with the struct shape above."
  echo "The selector is confirmed 0xf3ff8655 from production calldata; the field"
  echo "list is the part still being pinned down. See docs/taker-matching-design.md."
  exit 1
fi

log "checking IntentSignaled"
INTENT_TOPIC=$(cast keccak 'IntentSignaled(bytes32,address,uint256,bytes32,address,address,uint256,bytes32,uint256,uint256)')
BLOCK=$(cast block-number --rpc-url "$RPC")
cast logs --rpc-url "$RPC" --from-block $((BLOCK-2)) --to-block "$BLOCK" --address "$ORCHESTRATOR" "$INTENT_TOPIC" | head -20

log "PASS: a taker with no prior arrangement signaled on a glue-created deposit"

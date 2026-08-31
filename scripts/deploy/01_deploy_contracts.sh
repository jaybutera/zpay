#!/usr/bin/env bash
# Step 01: deploy OfframpGlue.
#
# Simulates by default and sends nothing. Pass --broadcast to deploy for real;
# that spends ETH from DEPLOYER_PRIVATE_KEY on chain CHAIN_ID.
#
#   scripts/deploy/01_deploy_contracts.sh              # simulate
#   scripts/deploy/01_deploy_contracts.sh --broadcast  # deploy
#
# Idempotent: if GLUE_CONTRACT_ADDRESS already names a contract whose usdc()
# and zkp2pEscrow() match the configured addresses, this reports it and exits
# without deploying a second one. Pass --force to deploy a fresh glue anyway.
#
# Env (from .env; see .env.example):
#   DEPLOYER_PRIVATE_KEY  required with --broadcast. Becomes owner and keeper.
#   BASE_RPC_URL, CHAIN_ID
#   USDC_ADDRESS, ZKP2P_ESCROW_ADDRESS
#   BASESCAN_API_KEY      if set, verifies the source on Basescan after deploy
#
# Writes GLUE_CONTRACT_ADDRESS into scripts/deploy/state/deployed.<chain>.env.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "$ROOT/scripts/deploy/lib.sh"
load_deployed

FORCE=""
for a in "$@"; do [ "$a" = "--force" ] && FORCE=1; done
parse_broadcast "$@" || { sed -n '2,25p' "$0"; exit 0; }

echo "deploy OfframpGlue"
echo "chain : $CHAIN_ID"
echo "rpc   : $BASE_RPC_URL"
require_chain
require_code USDC_ADDRESS
require_code ZKP2P_ESCROW_ADDRESS

# ---------------------------------------------------------------- idempotence
if [ -n "${GLUE_CONTRACT_ADDRESS:-}" ] && is_address "$GLUE_CONTRACT_ADDRESS" && [ -z "$FORCE" ]; then
  CODE_SIZE=$(( ($(cast code --rpc-url "$BASE_RPC_URL" "$GLUE_CONTRACT_ADDRESS" 2>/dev/null | wc -c) - 3) / 2 ))
  if [ "$CODE_SIZE" -gt 0 ]; then
    HAVE_USDC="$(cast call --rpc-url "$BASE_RPC_URL" "$GLUE_CONTRACT_ADDRESS" 'usdc()(address)' 2>/dev/null)"
    HAVE_ESCROW="$(cast call --rpc-url "$BASE_RPC_URL" "$GLUE_CONTRACT_ADDRESS" 'zkp2pEscrow()(address)' 2>/dev/null)"
    lc() { printf '%s' "$1" | tr 'A-Z' 'a-z'; }
    if [ "$(lc "$HAVE_USDC")" = "$(lc "$USDC_ADDRESS")" ] && \
       [ "$(lc "$HAVE_ESCROW")" = "$(lc "$ZKP2P_ESCROW_ADDRESS")" ]; then
      log "already deployed"
      ok "OfframpGlue $GLUE_CONTRACT_ADDRESS ($CODE_SIZE bytes)"
      note "usdc   $HAVE_USDC"
      note "escrow $HAVE_ESCROW"
      note "owner  $(cast call --rpc-url "$BASE_RPC_URL" "$GLUE_CONTRACT_ADDRESS" 'owner()(address)' 2>/dev/null)"
      note "keeper $(cast call --rpc-url "$BASE_RPC_URL" "$GLUE_CONTRACT_ADDRESS" 'keeper()(address)' 2>/dev/null)"
      echo
      echo "Nothing to do. Pass --force to deploy a second glue anyway."
      echo "Next: scripts/deploy/02_configure_keeper.sh"
      exit 0
    fi
    die "GLUE_CONTRACT_ADDRESS $GLUE_CONTRACT_ADDRESS points at a contract built against
       usdc=$HAVE_USDC escrow=$HAVE_ESCROW, which is not the configured
       usdc=$USDC_ADDRESS escrow=$ZKP2P_ESCROW_ADDRESS.
       Clear GLUE_CONTRACT_ADDRESS or fix the config; refusing to guess."
  fi
  note "GLUE_CONTRACT_ADDRESS is set but holds no code on this chain; deploying fresh"
fi

# ---------------------------------------------------------------- cost estimate
require_var DEPLOYER_PRIVATE_KEY
DEPLOYER="$(deployer_address)"
GAS_WEI="$(cast gas-price --rpc-url "$BASE_RPC_URL" 2>/dev/null || echo 0)"
echo
echo "deployer : $DEPLOYER"
echo "balance  : $(cast from-wei "$(eth_balance_wei "$DEPLOYER")") ETH"
echo "gas price: $(python3 -c "print(int('$GAS_WEI')/1e9)") gwei"

# Measured against Base mainnet bytecode on an anvil fork: eth_estimateGas for
# the CREATE is 1,497,322 and the mined receipt is 1,517,222 including the
# intrinsic cost. Budget the receipt figure.
DEPLOY_GAS=1520000
COST_WEI="$(python3 -c "print($DEPLOY_GAS * int('$GAS_WEI'))")"
echo "estimate : $DEPLOY_GAS gas ~ $(cast from-wei "$COST_WEI") ETH at the current price"
announce_mode

# ---------------------------------------------------------------- deploy
VERIFY=""
if [ -n "$BROADCAST" ] && [ -n "${BASESCAN_API_KEY:-}" ]; then
  VERIFY="--verify --etherscan-api-key $BASESCAN_API_KEY"
  note "will verify sources on Basescan"
fi

log "forge script DeployOfframpGlue"
set +e
OUT="$(cd "$ROOT/contracts" && \
  DEPLOYER_PRIVATE_KEY="$DEPLOYER_PRIVATE_KEY" \
  USDC_ADDRESS="$USDC_ADDRESS" \
  ZKP2P_ESCROW_ADDRESS="$ZKP2P_ESCROW_ADDRESS" \
  EXPECTED_CHAIN_ID="$CHAIN_ID" \
  forge script script/Deploy.s.sol:DeployOfframpGlue \
    --rpc-url "$BASE_RPC_URL" $BROADCAST $VERIFY 2>&1)"
RC=$?
set -e
echo "$OUT" | grep -E "Chain id:|USDC:|ZKP2P Escrow:|deployed at:|Owner:|Keeper:|Total Paid|Estimated|Error|revert" || true
[ $RC -eq 0 ] || { echo "$OUT" | tail -30; die "forge script failed"; }

GLUE="$(echo "$OUT" | sed -n 's/.*OfframpGlue deployed at: *\(0x[0-9a-fA-F]\{40\}\).*/\1/p' | head -1)"
[ -n "$GLUE" ] || { echo "$OUT" | tail -20; die "could not parse the deployed address"; }

if [ -z "$BROADCAST" ]; then
  echo
  echo "simulation ok. The address above is the simulated one, not a real deployment."
  echo "Re-run with --broadcast to deploy."
  exit 0
fi

# ---------------------------------------------------------------- verify + record
log "reading the deployment back off chain"
CODE_SIZE=$(( ($(cast code --rpc-url "$BASE_RPC_URL" "$GLUE" | wc -c) - 3) / 2 ))
[ "$CODE_SIZE" -gt 0 ] || die "no code at $GLUE after broadcast"
ok "OfframpGlue $GLUE ($CODE_SIZE bytes)"
lc() { printf '%s' "$1" | tr 'A-Z' 'a-z'; }
[ "$(lc "$(cast call --rpc-url "$BASE_RPC_URL" "$GLUE" 'usdc()(address)')")" = "$(lc "$USDC_ADDRESS")" ] \
  || die "deployed glue points at the wrong USDC"
[ "$(lc "$(cast call --rpc-url "$BASE_RPC_URL" "$GLUE" 'zkp2pEscrow()(address)')")" = "$(lc "$ZKP2P_ESCROW_ADDRESS")" ] \
  || die "deployed glue points at the wrong escrow"
ok "usdc and escrow match the configuration"
ok "owner  $(cast call --rpc-url "$BASE_RPC_URL" "$GLUE" 'owner()(address)')"
ok "keeper $(cast call --rpc-url "$BASE_RPC_URL" "$GLUE" 'keeper()(address)')"

record GLUE_CONTRACT_ADDRESS "$GLUE"
record DEPLOYER_ADDRESS "$DEPLOYER"
record DEPLOYED_AT "$(date -Iseconds)"
echo
echo "recorded in $DEPLOYED_ENV"
echo "Put GLUE_CONTRACT_ADDRESS=$GLUE in your .env and config.toml."
echo "Next: scripts/deploy/02_configure_keeper.sh"

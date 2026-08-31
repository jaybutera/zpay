#!/usr/bin/env bash
# Step 02: point the glue at the coordinator's keeper key, and check that key
# can actually operate.
#
# Simulates by default. Pass --broadcast to send the setKeeper transaction.
#
#   scripts/deploy/02_configure_keeper.sh
#   scripts/deploy/02_configure_keeper.sh --broadcast
#
# The deployer is the glue's keeper out of the constructor. Running the
# coordinator with the deployer key works, but it means the key that owns the
# contract is also the hot key polling an RPC every 15 seconds. Setting a
# separate keeper keeps the owner key cold: the owner can always take the
# keeper role back, and the keeper can never change the owner.
#
# Idempotent: if the keeper is already COORDINATOR_ADDRESS, this sends nothing.
#
# Env:
#   GLUE_CONTRACT_ADDRESS  from step 01 (read from the state file automatically)
#   DEPLOYER_PRIVATE_KEY   the glue owner; the only key setKeeper accepts
#   COORDINATOR_PRIVATE_KEY  the keeper key the coordinator will run with.
#                          COORDINATOR_ADDRESS may be given instead if the key
#                          lives somewhere this machine cannot read.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "$ROOT/scripts/deploy/lib.sh"
load_deployed
parse_broadcast "$@" || { sed -n '2,24p' "$0"; exit 0; }

echo "configure the keeper"
echo "chain : $CHAIN_ID"
require_chain
require_address GLUE_CONTRACT_ADDRESS
require_code GLUE_CONTRACT_ADDRESS

OWNER="$(cast call --rpc-url "$BASE_RPC_URL" "$GLUE_CONTRACT_ADDRESS" 'owner()(address)')"
KEEPER_NOW="$(cast call --rpc-url "$BASE_RPC_URL" "$GLUE_CONTRACT_ADDRESS" 'keeper()(address)')"
note "glue   $GLUE_CONTRACT_ADDRESS"
note "owner  $OWNER"
note "keeper $KEEPER_NOW (current)"

# ---------------------------------------------------------------- target keeper
if [ -n "${COORDINATOR_ADDRESS:-}" ]; then
  require_address COORDINATOR_ADDRESS
  TARGET="$COORDINATOR_ADDRESS"
  note "keeper target from COORDINATOR_ADDRESS"
elif [ -n "${COORDINATOR_PRIVATE_KEY:-}" ] && [ "${COORDINATOR_PRIVATE_KEY}" != "0x..." ]; then
  TARGET="$(cast wallet address --private-key "$COORDINATOR_PRIVATE_KEY" 2>/dev/null)" \
    || die "COORDINATOR_PRIVATE_KEY is not a valid private key"
  note "keeper target derived from COORDINATOR_PRIVATE_KEY"
else
  die "set COORDINATOR_PRIVATE_KEY (or COORDINATOR_ADDRESS) in .env to the key the coordinator will run with"
fi
echo "keeper target: $TARGET"

lc() { printf '%s' "$1" | tr 'A-Z' 'a-z'; }

# ---------------------------------------------------------------- keeper health
# The keeper sends processOfframp on every session, so it needs its own ETH.
# Measured on a Base mainnet fork: processOfframp against the real EscrowV2 uses
# 501,459 gas, createSession 121,891, withdrawFromZkp2p about 94,151.
log "can this keeper operate?"
KEEPER_ETH="$(eth_balance_wei "$TARGET")"
note "keeper ETH $(cast from-wei "$KEEPER_ETH")"
GAS_WEI="$(cast gas-price --rpc-url "$BASE_RPC_URL" 2>/dev/null || echo 1)"
PER_SESSION_GAS=720000   # createSession + processOfframp + a withdraw, rounded up
PER_SESSION_WEI="$(python3 -c "print($PER_SESSION_GAS * int('$GAS_WEI'))")"
note "one full session costs about $PER_SESSION_GAS gas = $(cast from-wei "$PER_SESSION_WEI") ETH at the current price"
if [ "$(python3 -c "print(1 if int('$KEEPER_ETH') < int('$PER_SESSION_WEI') else 0)")" = "1" ]; then
  note "the keeper cannot currently pay for even one session; fund it before starting the coordinator"
else
  note "keeper can fund about $(python3 -c "print(int(int('$KEEPER_ETH')//max(int('$PER_SESSION_WEI'),1)))") sessions at this gas price"
fi

# ---------------------------------------------------------------- act
if [ "$(lc "$KEEPER_NOW")" = "$(lc "$TARGET")" ]; then
  echo
  ok "keeper is already $TARGET; nothing to send"
  record KEEPER_ADDRESS "$TARGET"
  echo "Next: scripts/deploy/03_write_config.sh"
  exit 0
fi

require_var DEPLOYER_PRIVATE_KEY
DEPLOYER="$(deployer_address)"
[ "$(lc "$DEPLOYER")" = "$(lc "$OWNER")" ] \
  || die "DEPLOYER_PRIVATE_KEY is $DEPLOYER but the glue owner is $OWNER. Only the owner can set the keeper."

announce_mode
log "SetKeeper $KEEPER_NOW -> $TARGET"
set +e
OUT="$(cd "$ROOT/contracts" && \
  DEPLOYER_PRIVATE_KEY="$DEPLOYER_PRIVATE_KEY" \
  forge script script/Deploy.s.sol:SetKeeper \
    --sig "run(address,address)" "$GLUE_CONTRACT_ADDRESS" "$TARGET" \
    --rpc-url "$BASE_RPC_URL" $BROADCAST 2>&1)"
RC=$?
set -e
echo "$OUT" | grep -E "Keeper|Total Paid|Error|revert" || true
[ $RC -eq 0 ] || { echo "$OUT" | tail -30; die "SetKeeper failed"; }

if [ -z "$BROADCAST" ]; then
  echo
  echo "simulation ok. Re-run with --broadcast to send it."
  exit 0
fi

AFTER="$(cast call --rpc-url "$BASE_RPC_URL" "$GLUE_CONTRACT_ADDRESS" 'keeper()(address)')"
[ "$(lc "$AFTER")" = "$(lc "$TARGET")" ] || die "keeper is $AFTER after the send, expected $TARGET"
ok "keeper is now $AFTER"
record KEEPER_ADDRESS "$TARGET"
echo
echo "Next: scripts/deploy/03_write_config.sh"

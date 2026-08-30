#!/usr/bin/env bash
# End-to-end dry run on Base Sepolia with the NEAR leg faked.
#
# Flow: mock NEAR + mock curator (or the real curator) -> coordinator ->
# POST /offramp -> you send test USDC to the GlueContract (this is the fake
# "NEAR delivered USDC" step) -> mock NEAR reports SUCCESS -> keeper deposits
# into the stand-in escrow -> withdraw returns the USDC to user_address.
#
# This sends real Sepolia transactions from PRIVATE_KEY: one USDC transfer,
# createSession, processOfframp, withdrawFromZkp2p. It never touches mainnet.
#
# Usage:
#   scripts/testnet/02_dryrun_sepolia.sh
# Env (scripts/testnet/deployed.sepolia.env is sourced first if present):
#   PRIVATE_KEY             keeper key; also the user_address so the coordinator can withdraw
#   BASE_SEPOLIA_RPC_URL    default https://sepolia.base.org
#   GLUE_CONTRACT_ADDRESS   from 01_deploy_sepolia.sh
#   ESCROW_ADDRESS          stand-in escrow (also used as orchestrator)
#   USDC_ADDRESS            default Circle USDC on Base Sepolia
#   AMOUNT                  USDC units (6 decimals) to move, default 5000000 (5 USDC)
#   FUND_MODE               transfer (default; PRIVATE_KEY must hold USDC) or mint (MockUSDC only)
#   ZKP2P_API_URL           default: local mock curator. Set https://api.zkp2p.xyz and
#                           VENMO_USERNAME=<your real username> to exercise the real curator.
#   VENMO_USERNAME          default dryrun-user (mock only)
#   ZEC_REFUND_ADDRESS      any syntactically valid t-address; the mock ignores it
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ -f "$ROOT/scripts/testnet/deployed.sepolia.env" ] && set -a && . "$ROOT/scripts/testnet/deployed.sepolia.env" && set +a
RPC="${BASE_SEPOLIA_RPC_URL:-https://sepolia.base.org}"
export FOUNDRY_DISABLE_NIGHTLY_WARNING=1

: "${PRIVATE_KEY:?set PRIVATE_KEY}"
: "${GLUE_CONTRACT_ADDRESS:?set GLUE_CONTRACT_ADDRESS (run 01_deploy_sepolia.sh --broadcast first)}"
: "${ESCROW_ADDRESS:?set ESCROW_ADDRESS}"
USDC="${USDC_ADDRESS:-0x036CbD53842c5426634e7929541eC2318f3dCF7e}"
AMOUNT="${AMOUNT:-5000000}"
FUND_MODE="${FUND_MODE:-transfer}"
VENMO_USERNAME="${VENMO_USERNAME:-dryrun-user}"
ZEC_REFUND_ADDRESS="${ZEC_REFUND_ADDRESS:-t1KzZ5n2TPvvDDNhVbFcZDkhjYVBFfd1iRw}"
KEEPER=$(cast wallet address --private-key "$PRIVATE_KEY")
CHAIN=$(cast chain-id --rpc-url "$RPC")
NEAR_PORT=4101; ZKP2P_PORT=4102; COORD_PORT=3100
ZKP2P_API_URL="${ZKP2P_API_URL:-http://127.0.0.1:$ZKP2P_PORT}"
WORK=$(mktemp -d)
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
log() { printf '\n== %s\n' "$*"; }

echo "rpc:    $RPC (chain $CHAIN)"
echo "keeper: $KEEPER  ETH=$(cast balance --rpc-url "$RPC" "$KEEPER" --ether)  USDC=$(cast call --rpc-url "$RPC" "$USDC" 'balanceOf(address)(uint256)' "$KEEPER")"
echo "glue:   $GLUE_CONTRACT_ADDRESS (escrow $(cast call --rpc-url "$RPC" "$GLUE_CONTRACT_ADDRESS" 'zkp2pEscrow()(address)'))"
[ "$(cast call --rpc-url "$RPC" "$GLUE_CONTRACT_ADDRESS" 'keeper()(address)')" = "$KEEPER" ] || { echo "PRIVATE_KEY is not the glue keeper"; exit 1; }

log "starting mock NEAR (:$NEAR_PORT)"
python3 "$ROOT/scripts/dryrun/mock_near.py" --port $NEAR_PORT > "$WORK/near.log" 2>&1 & PIDS+=($!)
if [ "$ZKP2P_API_URL" = "http://127.0.0.1:$ZKP2P_PORT" ]; then
  log "starting mock curator (:$ZKP2P_PORT); set ZKP2P_API_URL=https://api.zkp2p.xyz to use the real one"
  python3 "$ROOT/scripts/dryrun/mock_zkp2p.py" --port $ZKP2P_PORT > "$WORK/zkp2p.log" 2>&1 & PIDS+=($!)
fi
sleep 1

log "starting the coordinator"
(cd "$ROOT" && cargo build -q -p zecp2p-coordinator)
cat > "$WORK/config.toml" <<EOF
[network]
base_rpc_url = "$RPC"
chain_id = $CHAIN
[contracts]
usdc = "$USDC"
zkp2p_escrow = "$ESCROW_ADDRESS"
zkp2p_orchestrator = "$ESCROW_ADDRESS"
glue_contract = "$GLUE_CONTRACT_ADDRESS"
[near]
api_url = "http://127.0.0.1:$NEAR_PORT"
default_timeout = 600
[zkp2p]
api_url = "$ZKP2P_API_URL"
[server]
host = "127.0.0.1"
port = $COORD_PORT
[database]
path = "$WORK/dryrun.db"
EOF
COORD="http://127.0.0.1:$COORD_PORT"
if curl -sf "$COORD/health" >/dev/null 2>&1; then
  echo "something already answers on $COORD (stale coordinator?); stop it first"; exit 1
fi
( cd "$WORK" && exec env ZECP2P_CONFIG="$WORK/config.toml" GLUE_CONTRACT_ADDRESS="$GLUE_CONTRACT_ADDRESS" COORDINATOR_PRIVATE_KEY="$PRIVATE_KEY" \
    RUST_LOG=zecp2p_coordinator=info "$ROOT/target/debug/zecp2p-coordinator" > "$WORK/coordinator.log" 2>&1 ) & PIDS+=($!)
for _ in $(seq 1 30); do sleep 1; curl -sf "$COORD/health" >/dev/null && break; done
curl -sf "$COORD/health" >/dev/null || { cat "$WORK/coordinator.log"; exit 1; }

log "POST /offramp (venmo=$VENMO_USERNAME, user_address=$KEEPER)"
RESP=$(curl -sf -X POST "$COORD/offramp" -H 'Content-Type: application/json' -d "{
  \"zec_amount\": \"0.5\", \"venmo_username\": \"$VENMO_USERNAME\",
  \"user_address\": \"$KEEPER\", \"taker_address\": \"$KEEPER\",
  \"zec_refund_address\": \"$ZEC_REFUND_ADDRESS\", \"min_rate\": \"1.0\" }") || { cat "$WORK/coordinator.log"; exit 1; }
echo "$RESP"
SID=$(echo "$RESP" | python3 -c 'import sys,json; print(json.load(sys.stdin)["session_id"])')

log "faking the NEAR leg: $AMOUNT USDC units -> GlueContract ($FUND_MODE)"
if [ "$FUND_MODE" = "mint" ]; then
  cast send --rpc-url "$RPC" --private-key "$PRIVATE_KEY" "$USDC" 'mint(address,uint256)' "$GLUE_CONTRACT_ADDRESS" "$AMOUNT" >/dev/null
else
  cast send --rpc-url "$RPC" --private-key "$PRIVATE_KEY" "$USDC" 'transfer(address,uint256)(bool)' "$GLUE_CONTRACT_ADDRESS" "$AMOUNT" >/dev/null
fi
echo "glue USDC balance: $(cast call --rpc-url "$RPC" "$USDC" 'balanceOf(address)(uint256)' "$GLUE_CONTRACT_ADDRESS")"
curl -sf -X POST "http://127.0.0.1:$NEAR_PORT/admin/status" -H 'Content-Type: application/json' -d '{"status":"SUCCESS"}' >/dev/null

log "waiting for the keeper (15s poll) to deposit into the stand-in escrow"
STATUS=""
for _ in $(seq 1 24); do
  sleep 5
  STATUS=$(curl -sf "$COORD/offramp/$SID" | python3 -c 'import sys,json; print(json.load(sys.stdin)["status"])')
  echo "  status: $STATUS"
  [ "$STATUS" = "zkp2p_deposited" ] && break
  [ "$STATUS" = "failed" ] && { cat "$WORK/coordinator.log"; exit 1; }
done
[ "$STATUS" = "zkp2p_deposited" ] || { cat "$WORK/coordinator.log"; exit 1; }
curl -sf "$COORD/offramp/$SID"; echo

log "POST /offramp/$SID/withdraw (no taker on the stand-in)"
curl -sf -X POST "$COORD/offramp/$SID/withdraw"; echo
echo "keeper USDC balance: $(cast call --rpc-url "$RPC" "$USDC" 'balanceOf(address)(uint256)' "$KEEPER")"
log "PASS on chain $CHAIN. Logs: $WORK"

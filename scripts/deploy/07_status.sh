#!/usr/bin/env bash
# Step 07: what is the state of this deployment right now?
#
# Read-only. Sends nothing. Safe to run against a live deployment at any time.
#
#   scripts/deploy/07_status.sh
#
# Reports the glue's on-chain state, both operating keys' balances against what
# they need, the coordinator's health if it is running, and how much runway the
# keeper has at the current gas price.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "$ROOT/scripts/deploy/lib.sh"
load_deployed

require_tools cast python3
require_chain

usd() { python3 -c "print(f'{float(${1:-0}):.2f}')" 2>/dev/null || echo "?"; }

echo "zecp2p deployment status"
echo "chain : $CHAIN_ID"
echo "state : $DEPLOYED_ENV"

# ---------------------------------------------------------------- contract
if [ -n "${GLUE_CONTRACT_ADDRESS:-}" ] && is_address "$GLUE_CONTRACT_ADDRESS"; then
  log "OfframpGlue $GLUE_CONTRACT_ADDRESS"
  SIZE=$(( ($(cast code --rpc-url "$BASE_RPC_URL" "$GLUE_CONTRACT_ADDRESS" 2>/dev/null | wc -c) - 3) / 2 ))
  if [ "$SIZE" -gt 0 ]; then
    ok "$SIZE bytes of code"
    note "owner   $(cast call --rpc-url "$BASE_RPC_URL" "$GLUE_CONTRACT_ADDRESS" 'owner()(address)' 2>/dev/null)"
    note "keeper  $(cast call --rpc-url "$BASE_RPC_URL" "$GLUE_CONTRACT_ADDRESS" 'keeper()(address)' 2>/dev/null)"
    note "usdc    $(cast call --rpc-url "$BASE_RPC_URL" "$GLUE_CONTRACT_ADDRESS" 'usdc()(address)' 2>/dev/null)"
    note "escrow  $(cast call --rpc-url "$BASE_RPC_URL" "$GLUE_CONTRACT_ADDRESS" 'zkp2pEscrow()(address)' 2>/dev/null)"
    HELD="$(cast call --rpc-url "$BASE_RPC_URL" "$GLUE_CONTRACT_ADDRESS" 'getContractUsdcBalance()(uint256)' 2>/dev/null | awk '{print $1}' || true)"
    [ -n "${HELD:-}" ] || { HELD=0; bad "getContractUsdcBalance() did not answer; is this really an OfframpGlue?"; }
    # USDC sitting on the glue between the NEAR delivery and processOfframp is
    # normal. Sitting there for long is not: it means the keeper is not running.
    note "USDC held right now: $(usd "${HELD:-0}/1e6")"
  else
    bad "no code at GLUE_CONTRACT_ADDRESS on chain $CHAIN_ID"
  fi
else
  note "GLUE_CONTRACT_ADDRESS not set; nothing deployed yet"
fi

# ---------------------------------------------------------------- keys
GAS_WEI="$(cast gas-price --rpc-url "$BASE_RPC_URL" 2>/dev/null || echo 1)"
log "gas price $(python3 -c "print(int('$GAS_WEI')/1e9)") gwei"

report_key() { # label, address
  local label="$1" addr="$2"
  is_address "$addr" || return 0
  local eth usdc
  eth="$(eth_balance_wei "$addr")"
  usdc="$(usdc_balance "$addr" || true)"
  printf '  %-11s %s\n' "$label" "$addr"
  printf '              ETH  %s\n' "$(cast from-wei "$eth")"
  printf '              USDC %s\n' "$(usd "${usdc:-0}/1e6")"
}

log "operating keys"
if [ -n "${DEPLOYER_PRIVATE_KEY:-}" ] && [ "$DEPLOYER_PRIVATE_KEY" != "0x..." ]; then
  report_key "deployer" "$(deployer_address)"
fi
KEEPER_ADDR="${KEEPER_ADDRESS:-}"
if [ -z "$KEEPER_ADDR" ] && [ -n "${COORDINATOR_PRIVATE_KEY:-}" ] && [ "$COORDINATOR_PRIVATE_KEY" != "0x..." ]; then
  KEEPER_ADDR="$(cast wallet address --private-key "$COORDINATOR_PRIVATE_KEY" 2>/dev/null || true)"
fi
if is_address "${KEEPER_ADDR:-}"; then
  report_key "keeper" "$KEEPER_ADDR"
  # 720k gas covers createSession + processOfframp + a withdraw, measured on a
  # Base mainnet fork.
  PER_SESSION_WEI="$(python3 -c "print(720000 * int('$GAS_WEI'))")"
  HAVE="$(eth_balance_wei "$KEEPER_ADDR")"
  RUNWAY="$(python3 -c "print(int(int('$HAVE') // max(int('$PER_SESSION_WEI'), 1)))")"
  note "runway: about $RUNWAY sessions at the current gas price"
  [ "$RUNWAY" -lt 10 ] && bad "keeper is low on gas; top it up before it runs dry"
fi
if [ -n "${TAKER_PRIVATE_KEY:-}" ] && [ "$TAKER_PRIVATE_KEY" != "0x..." ]; then
  TAKER_ADDR="$(cast wallet address --private-key "$TAKER_PRIVATE_KEY" 2>/dev/null || true)"
  if is_address "${TAKER_ADDR:-}"; then
    report_key "taker" "$TAKER_ADDR"
    if is_address "${STAKE_VAULT_ADDRESS:-}"; then
          FREE="$(cast call --rpc-url "$BASE_RPC_URL" "$STAKE_VAULT_ADDRESS" 'freeStake(address)(uint256)' "$TAKER_ADDR" 2>/dev/null | awk '{print $1}' || true)"
      note "free stake in the vault: $(usd "${FREE:-0}/1e6") USDC"
      note "a taker needs stake equal to the intent it signals, plus the same amount"
      note "again in real dollars on Venmo"
    fi
  fi
fi

# ---------------------------------------------------------------- coordinator
COORD_URL="${COORDINATOR_URL:-http://${COORDINATOR_HOST:-127.0.0.1}:${COORDINATOR_PORT:-3000}}"
log "coordinator $COORD_URL"
if curl -sf -m 5 "$COORD_URL/health" >/dev/null 2>&1; then
  ok "answering /health"
  OPEN="$(curl -sf -m 10 "$COORD_URL/deposits/open" 2>/dev/null || true)"
  if [ -n "$OPEN" ]; then
    printf '%s' "$OPEN" | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
except Exception:
    raise SystemExit
rows = d if isinstance(d, list) else d.get("deposits", [])
print(f"  {len(rows)} open deposit(s) advertised to takers")
for r in rows[:10]:
    print("   ", json.dumps(r)[:160])
' 2>/dev/null || true
  fi
else
  note "not running (or not reachable at $COORD_URL)"
fi

# ---------------------------------------------------------------- externals
log "external services"
curl -sf -m 15 "$ATTESTATION_URL/health" >/dev/null 2>&1 \
  && ok "attestation enclave $ATTESTATION_URL" || bad "attestation enclave unreachable"
curl -sf -m 15 "$NEAR_API_URL/v0/tokens" >/dev/null 2>&1 \
  && ok "1Click $NEAR_API_URL" || bad "1Click unreachable"
curl -sf -m 15 -X POST "$ZKP2P_API_URL/v2/makers/validate" -H 'Content-Type: application/json' \
  -d '{"processorName":"venmo","offchainId":"zecp2p-status-probe"}' >/dev/null 2>&1 \
  && ok "zk-p2p curator $ZKP2P_API_URL" || bad "zk-p2p curator unreachable"

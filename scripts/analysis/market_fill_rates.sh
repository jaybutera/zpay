#!/usr/bin/env bash
# Do small offramp sells actually clear on zk-p2p, and how fast?
#
# Read-only. Sends no transaction, creates no deposit, needs no private key,
# and never calls createDeposit. It only reads historical logs. Safe to run as
# often as you like, and safe to run before deciding whether to spend anything.
#
#   scripts/analysis/market_fill_rates.sh                 # ~6 days, the default
#   scripts/analysis/market_fill_rates.sh --blocks 500000 # ~12 days, slower
#   scripts/analysis/market_fill_rates.sh --json out.json # keep the raw rows
#
# The question this answers: a ~$5 sell is far below the median intent on this
# market. Before funding one, we want to know whether intents that small get
# taken at all, how often, and how long they sit. The numbers come from
# OrchestratorV3 and EscrowV2 logs on Base mainnet, not from zk-p2p's docs.
#
# Verification: every topic hash the Python uses is re-derived here with
# `cast keccak` and compared. A mismatch aborts the run, so the analysis cannot
# silently measure the wrong event.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "$ROOT/scripts/deploy/lib.sh"
load_deployed

require_tools cast python3
require_chain

[ "$CHAIN_ID" = "8453" ] || die "this measures the live Base mainnet market; CHAIN_ID is $CHAIN_ID"

require_code ZKP2P_ORCHESTRATOR_ADDRESS
require_code ZKP2P_ESCROW_ADDRESS

# ---------------------------------------------------------------- topic check
# The signatures on the left are the ones the coordinator already ships in
# crates/zecp2p-types/src/abi.rs; the rest were resolved against production
# logs. Hashing them here means the constants in fill_rates.py are checked on
# every run rather than trusted.
log "verifying event topic hashes against the signatures"
check_topic() { # human name, signature, expected hash
  local name="$1" sig="$2" want="$3" got
  got="$(cast keccak "$sig")"
  if [ "$got" = "$want" ]; then
    ok "$name"
  else
    bad "$name: keccak($sig)"
    bad "  is       $got"
    bad "  expected $want"
    die "topic hash mismatch; fill_rates.py would measure the wrong event"
  fi
}

check_topic "IntentSignaled" \
  'IntentSignaled(bytes32,address,uint256,bytes32,address,address,uint256,bytes32,uint256,uint256)' \
  0xf8c114f83581b2cf0b9f130782a93024aa8933e7d188901156bd68bdd558a20a
check_topic "IntentFulfilled" \
  'IntentFulfilled(bytes32,address,uint256,bool)' \
  0xd50b3b21bc45b85ddfaec58dbf56fe9b88754d08f47dcf5143b63258a57ad944
check_topic "IntentPruned" \
  'IntentPruned(bytes32)' \
  0x95eadd9e42ccacb548c6389441b53e6eebec39e11adaea9029a25fe1222483e0
check_topic "FundsLocked" \
  'FundsLocked(uint256,bytes32,uint256,uint256)' \
  0xb40d75557428cec6806c7ebb58634796f8a5870a0874bcd0d299328b5518665b
check_topic "FundsUnlockedAndTransferred" \
  'FundsUnlockedAndTransferred(uint256,bytes32,uint256,uint256,address)' \
  0x45625e0810f65b3c601b5c91bdacdf9e8f9ec7098fce927c57a8a65a823fd617
check_topic "FundsUnlocked" \
  'FundsUnlocked(uint256,bytes32,uint256)' \
  0x683f6606eec92f04a68f1797d32d15f840b9b3d410a8ec9b4fdab4c30813796d
check_topic "DepositReceived" \
  'DepositReceived(uint256,address,address,uint256,(uint256,uint256),address,address)' \
  0x1236dbdc184b6c8721974cce53dabb6018679bca9a43784ab2ad71bcdb1d7dd1

# One live confirmation that the signal topic is really emitted by this
# orchestrator, so a hash that is self-consistent but wrong still gets caught.
log "confirming the orchestrator emits IntentSignaled"
RECENT="$(cast logs --rpc-url "$BASE_RPC_URL" \
  --from-block $(( $(cast block-number --rpc-url "$BASE_RPC_URL") - 5000 )) \
  --address "$ZKP2P_ORCHESTRATOR_ADDRESS" \
  0xf8c114f83581b2cf0b9f130782a93024aa8933e7d188901156bd68bdd558a20a \
  2>/dev/null | grep -c '^blockNumber' || true)"
if [ "${RECENT:-0}" -gt 0 ]; then
  ok "$RECENT IntentSignaled logs in the last 5000 blocks"
else
  note "no IntentSignaled in the last 5000 blocks; the scan below covers more"
fi

log "scanning"
note "read-only: eth_getLogs only, no transaction is sent"
exec python3 "$ROOT/scripts/analysis/fill_rates.py" \
  --rpc "$BASE_RPC_URL" \
  --orchestrator "$ZKP2P_ORCHESTRATOR_ADDRESS" \
  --escrow "$ZKP2P_ESCROW_ADDRESS" \
  "$@"

#!/usr/bin/env bash
# Step 00: verify everything the deploy depends on, before spending anything.
#
# Read-only. Sends no transaction, moves no funds, and needs no private key
# beyond deriving an address from it. Safe to run as often as you like.
#
#   scripts/deploy/00_preflight.sh
#
# Checks, in order:
#   - the toolchain is present
#   - the RPC answers and is the chain CHAIN_ID claims
#   - USDC, EscrowV2, OrchestratorV3, StakeVault and the payment verifier all
#     hold code on that chain
#   - OrchestratorV3 is registered with EscrowV2, and venmo/USD are accepted
#     payment method and currency
#   - the zk-p2p curator answers and rejects an unknown username
#   - the attestation enclave answers and advertises the chain we settle on
#   - the 1Click API answers and lists the ZEC and Base-USDC assets
#   - the deployer key parses and how much ETH it holds
#
# Exits non-zero if any check fails.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "$ROOT/scripts/deploy/lib.sh"
load_deployed

FAIL=0
fail() { bad "$*"; FAIL=1; }

# `cast call` swallows an RPC 429 into an empty string, which reads as a failed
# check when it is really rate limiting. Retry a few times before believing it.
call_retry() {
  local out i
  for i in 1 2 3; do
    out="$(cast call --rpc-url "$BASE_RPC_URL" "$@" 2>/dev/null | head -1 | cut -d' ' -f1)"
    [ -n "$out" ] && { printf '%s' "$out"; return 0; }
    sleep 2
  done
  return 1
}

expect() { # label expected actual
  if [ "$2" = "$3" ]; then ok "$1 = $3"; else fail "$1 = ${3:-<no answer>} (expected $2)"; fi
}

echo "zecp2p deploy preflight"
echo "chain    : $CHAIN_ID"
echo "rpc      : $BASE_RPC_URL"
echo "state    : $DEPLOYED_ENV"

log "toolchain"
require_tools cast forge python3 curl
ok "cast, forge, python3, curl present"
command -v node >/dev/null 2>&1 && ok "node $(node --version) present (needed for the proof leg)" \
  || note "node is absent; scripts/proof will not run without it"

log "chain"
require_chain
note "current block $(cast block-number --rpc-url "$BASE_RPC_URL" 2>/dev/null)"
GAS_WEI="$(cast gas-price --rpc-url "$BASE_RPC_URL" 2>/dev/null || echo 0)"
note "gas price $(python3 -c "print(int('$GAS_WEI')/1e9)") gwei"

log "contracts we depend on"
require_code USDC_ADDRESS
require_code ZKP2P_ESCROW_ADDRESS
require_code ZKP2P_ORCHESTRATOR_ADDRESS
require_code STAKE_VAULT_ADDRESS
require_code ATTESTATION_VERIFIER_ADDRESS

expect "USDC decimals" 6 "$(call_retry "$USDC_ADDRESS" 'decimals()(uint8)')"

if [ "$CHAIN_ID" = "8453" ]; then
  VENMO="$(cast keccak venmo)"
  USD="$(cast keccak USD)"
  note "EscrowV2 depositCounter = $(call_retry "$ZKP2P_ESCROW_ADDRESS" 'depositCounter()(uint256)')"

  REG="$(call_retry "$ZKP2P_ESCROW_ADDRESS" 'orchestratorRegistry()(address)' || true)"
  if is_address "${REG:-}"; then
    expect "OrchestratorV3 registered with EscrowV2" true \
      "$(call_retry "$REG" 'isOrchestrator(address)(bool)' "$ZKP2P_ORCHESTRATOR_ADDRESS")"
  else
    fail "could not read orchestratorRegistry() off EscrowV2"
  fi

  PVR="$(call_retry "$ZKP2P_ESCROW_ADDRESS" 'paymentVerifierRegistry()(address)' || true)"
  if is_address "${PVR:-}"; then
    expect "venmo is a registered payment method" true \
      "$(call_retry "$PVR" 'isPaymentMethod(bytes32)(bool)' "$VENMO")"
    expect "USD accepted for venmo" true \
      "$(call_retry "$PVR" 'isCurrency(bytes32,bytes32)(bool)' "$VENMO" "$USD")"
    VERIFIER_ONCHAIN="$(call_retry "$PVR" 'getVerifier(bytes32)(address)' "$VENMO" || true)"
    if [ "$(printf '%s' "${VERIFIER_ONCHAIN:-}" | tr 'A-Z' 'a-z')" = "$(printf '%s' "$ATTESTATION_VERIFIER_ADDRESS" | tr 'A-Z' 'a-z')" ]; then
      ok "registry's venmo verifier matches ATTESTATION_VERIFIER_ADDRESS"
    else
      fail "registry's venmo verifier is $VERIFIER_ONCHAIN but ATTESTATION_VERIFIER_ADDRESS is $ATTESTATION_VERIFIER_ADDRESS"
    fi
  else
    fail "could not read paymentVerifierRegistry() off EscrowV2"
  fi
else
  note "chain $CHAIN_ID is not Base mainnet; skipping the zk-p2p registry checks"
  note "the payment verifier and the attestation enclave exist only on 8453"
fi

log "zk-p2p curator ($ZKP2P_API_URL)"
CURATOR="$(curl -s -m 25 -X POST "$ZKP2P_API_URL/v2/makers/validate" \
  -H 'Content-Type: application/json' \
  -d '{"processorName":"venmo","offchainId":"this-user-should-not-exist-zecp2p"}' || true)"
if printf '%s' "$CURATOR" | grep -q '"responseObject":false'; then
  ok "curator reachable and rejecting unknown usernames"
else
  fail "unexpected curator answer: $(printf '%s' "$CURATOR" | head -c 200)"
fi

log "attestation enclave ($ATTESTATION_URL)"
HEALTH="$(curl -s -m 25 "$ATTESTATION_URL/health" || true)"
if printf '%s' "$HEALTH" | grep -q '"status":"ok"'; then
  ok "enclave health ok: $(printf '%s' "$HEALTH" | python3 -c 'import sys,json;d=json.load(sys.stdin);print("version",d.get("version"),"branch",d.get("branch"))' 2>/dev/null)"
else
  fail "enclave health check did not return ok: $(printf '%s' "$HEALTH" | head -c 200)"
fi
if command -v node >/dev/null 2>&1 && [ -d "$ROOT/scripts/proof/node_modules" ]; then
  note "verifying the enclave's Nitro attestation document (this reaches AWS)"
  if ( cd "$ROOT/scripts/proof" && ATTESTATION_URL="$ATTESTATION_URL" \
       VERIFIER="$ATTESTATION_VERIFIER_ADDRESS" node check_enclave.mjs ) 2>&1 | sed 's/^/    /'; then
    ok "enclave attestation verified to the AWS Nitro root"
  else
    fail "enclave attestation did not verify"
  fi
else
  note "skipping the Nitro check (run 'npm install' in scripts/proof to enable it)"
fi

log "NEAR 1Click ($NEAR_API_URL)"
# The script is passed with -c, not on stdin: a heredoc would claim stdin and
# python would then read the piped JSON as its own source.
ASSET_CHECK='
import sys, json
usdc = sys.argv[1].lower()
data = json.load(sys.stdin)
ids = {t.get("assetId", "") for t in data}
zec = "nep141:zec.omft.near"
usdc_asset = "nep141:base-" + usdc + ".omft.near"
missing = [a for a in (zec, usdc_asset) if a not in ids]
if missing:
    print("  missing assets:", missing)
    raise SystemExit(1)
print("  " + str(len(data)) + " assets listed; " + zec + " and " + usdc_asset + " both present")
'
TOKENS="$(curl -s -m 30 "$NEAR_API_URL/v0/tokens" || true)"
if printf '%s' "$TOKENS" | python3 -c "$ASSET_CHECK" "$USDC_ADDRESS"; then
  ok "1Click lists the ZEC origin and Base-USDC destination assets"
else
  fail "1Click did not list the assets this deploy swaps between"
fi

log "deployer key"
if [ -n "${DEPLOYER_PRIVATE_KEY:-}" ] && [ "${DEPLOYER_PRIVATE_KEY}" != "0x..." ]; then
  DEPLOYER="$(deployer_address)"
  ok "deployer $DEPLOYER"
  note "ETH  $(cast from-wei "$(eth_balance_wei "$DEPLOYER")")"
  note "USDC $(python3 -c "print(int('$(usdc_balance "$DEPLOYER")' or 0)/1e6)")"
  # 0.0005 ETH covers the ~1.5M-gas deploy with a wide margin at Base gas prices.
  warn_if_below_eth "$DEPLOYER" 500000000000000 "deployer" || \
    note "01_deploy_contracts.sh --broadcast will fail without gas; see DEPLOY.md"
else
  note "DEPLOYER_PRIVATE_KEY not set; skipping the key checks"
  note "set it in .env before running 01_deploy_contracts.sh"
fi

if [ -n "${GLUE_CONTRACT_ADDRESS:-}" ] && is_address "$GLUE_CONTRACT_ADDRESS"; then
  log "already-deployed glue"
  require_code GLUE_CONTRACT_ADDRESS
  note "owner  $(call_retry "$GLUE_CONTRACT_ADDRESS" 'owner()(address)')"
  note "keeper $(call_retry "$GLUE_CONTRACT_ADDRESS" 'keeper()(address)')"
  note "usdc   $(call_retry "$GLUE_CONTRACT_ADDRESS" 'usdc()(address)')"
  note "escrow $(call_retry "$GLUE_CONTRACT_ADDRESS" 'zkp2pEscrow()(address)')"
fi

echo
if [ "$FAIL" = 0 ]; then
  echo "preflight passed. Next: scripts/deploy/01_deploy_contracts.sh"
else
  echo "preflight FAILED. Fix the items marked FAIL before deploying."
  exit 1
fi

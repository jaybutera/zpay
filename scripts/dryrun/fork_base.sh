#!/usr/bin/env bash
# Dry run of GlueContract against the real zk-p2p EscrowV2 on an anvil fork of
# Base mainnet. Costs nothing and touches no live chain.
#
# What it proves: our createDeposit / withdrawDeposit encoding matches the
# deployed EscrowV2, the deposit id bookkeeping is right, and the payee hash we
# pass ends up on the deposit. The NEAR leg is faked by transferring USDC to
# the GlueContract from an impersonated holder (EscrowV2 itself).
#
# Modes:
#   contract     (default) drive GlueContract directly with cast
#   coordinator  run mock NEAR + mock curator + the coordinator binary and go
#                through POST /offramp -> keeper -> zkp2p_deposited -> withdraw
#   claim        drive the REAL EscrowV2 + OrchestratorV3 + UnifiedPaymentVerifierV3
#                through signalIntent -> fulfillIntent with a real enclave
#                attestation. Proves the claim leg executes against deployed
#                mainnet bytecode, on a local fork, spending nothing.
#
# Usage:
#   scripts/dryrun/fork_base.sh [contract|coordinator]
# Env:
#   FORK_RPC_URL   upstream RPC to fork from   (default https://mainnet.base.org)
#   ANVIL_PORT     local fork port             (default 8546)
#   KEEP_FORK=1    do not kill anvil at the end
set -euo pipefail

MODE="${1:-contract}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FORK_RPC_URL="${FORK_RPC_URL:-https://mainnet.base.org}"
ANVIL_PORT="${ANVIL_PORT:-8546}"
RPC="http://127.0.0.1:${ANVIL_PORT}"
export FOUNDRY_DISABLE_NIGHTLY_WARNING=1

# Base mainnet
USDC=0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913
ESCROW=0x777777779d229cdF3110e9de47943791c26300Ef      # zk-p2p EscrowV2
ORCHESTRATOR=0x014025fDE093f8701d86e9f38e2C3a9b779cb5c7 # zk-p2p OrchestratorV3
VENMO=$(cast keccak venmo)
USD=$(cast keccak USD)

# anvil default accounts
KEEPER_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
KEEPER=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
USER_KEY=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
USER=0x70997970C51812dc3A010C7d01b50e0d17dc79C8

AMOUNT=25000000 # 25 USDC
WORKDIR="${WORKDIR:-$(mktemp -d)}"
PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
  if [ "${KEEP_FORK:-0}" != "1" ] && [ -n "${ANVIL_PID:-}" ]; then kill "$ANVIL_PID" 2>/dev/null || true; fi
}
trap cleanup EXIT

log() { printf '\n== %s\n' "$*"; }

# ---------------------------------------------------------------- fork
if cast block-number --rpc-url "$RPC" >/dev/null 2>&1; then
  log "using anvil already listening on $RPC"
else
  log "starting anvil fork of $FORK_RPC_URL on port $ANVIL_PORT"
  anvil --fork-url "$FORK_RPC_URL" --port "$ANVIL_PORT" --silent &
  ANVIL_PID=$!
  for _ in $(seq 1 60); do
    sleep 1
    cast block-number --rpc-url "$RPC" >/dev/null 2>&1 && break
  done
fi
[ "$(cast chain-id --rpc-url "$RPC")" = "8453" ] || { echo "fork is not Base mainnet (chain id 8453)"; exit 1; }
echo "fork block: $(cast block-number --rpc-url "$RPC")"
echo "EscrowV2 depositCounter: $(cast call --rpc-url "$RPC" "$ESCROW" 'depositCounter()(uint256)')"

# ---------------------------------------------------------------- deploy glue
log "deploying OfframpGlue against USDC $USDC and EscrowV2 $ESCROW"
DEPLOY_OUT=$(cd "$ROOT/contracts" && PRIVATE_KEY=$KEEPER_KEY forge script script/Deploy.s.sol:DeployOfframpGlue \
  --rpc-url "$RPC" --broadcast 2>&1)
GLUE=$(echo "$DEPLOY_OUT" | sed -n 's/.*OfframpGlue deployed at: *\(0x[0-9a-fA-F]\{40\}\).*/\1/p' | head -1)
[ -n "$GLUE" ] || { echo "$DEPLOY_OUT"; echo "could not find deployed address"; exit 1; }
echo "OfframpGlue: $GLUE"
[ "$(cast call --rpc-url "$RPC" "$GLUE" 'zkp2pEscrow()(address)')" = "$ESCROW" ] || { echo "glue points at wrong escrow"; exit 1; }

# ---------------------------------------------------------------- fake NEAR leg
fund_glue() {
  log "faking the NEAR leg: moving $AMOUNT USDC units to the GlueContract from an impersonated holder"
  cast rpc --rpc-url "$RPC" anvil_impersonateAccount "$ESCROW" >/dev/null
  cast rpc --rpc-url "$RPC" anvil_setBalance "$ESCROW" 0x1000000000000000000 >/dev/null
  cast send --rpc-url "$RPC" --unlocked --from "$ESCROW" "$USDC" 'transfer(address,uint256)(bool)' "$GLUE" "$AMOUNT" >/dev/null
  cast rpc --rpc-url "$RPC" anvil_stopImpersonatingAccount "$ESCROW" >/dev/null
  echo "glue USDC balance: $(cast call --rpc-url "$RPC" "$USDC" 'balanceOf(address)(uint256)' "$GLUE")"
}

if [ "$MODE" = "contract" ]; then
  SESSION_ID=$(cast keccak "dryrun-session-$(date +%s)")
  # Stand-in for a curator-issued hashedOnchainId (opaque bytes32)
  PAYEE_HASH=$(cast keccak "mock-zkp2p-payee:dryrun")
  MIN_RATE=1000000000000000000 # 1 USD per USDC

  log "createSession"
  cast send --rpc-url "$RPC" --private-key "$KEEPER_KEY" "$GLUE" \
    'createSession(bytes32,address,bytes32,uint256,uint256)' \
    "$SESSION_ID" "$USER" "$PAYEE_HASH" "$MIN_RATE" "$AMOUNT" >/dev/null
  echo "session created for user $USER"

  fund_glue

  log "processOfframp -> EscrowV2.createDeposit"
  EXPECTED_ID=$(cast call --rpc-url "$RPC" "$ESCROW" 'depositCounter()(uint256)')
  cast send --rpc-url "$RPC" --private-key "$KEEPER_KEY" "$GLUE" \
    'processOfframp(bytes32,bytes32[],(address,bytes32,bytes)[],(bytes32,uint256,(address,bytes,int16,uint32))[][])' \
    "$SESSION_ID" "[$VENMO]" "[(0x0000000000000000000000000000000000000000,$PAYEE_HASH,0x)]" \
    "[[($USD,$MIN_RATE,(0x0000000000000000000000000000000000000000,0x,0,0))]]" >/dev/null

  SESSION=$(cast call --rpc-url "$RPC" "$GLUE" 'getSession(bytes32)((address,bytes32,uint256,uint256,uint256,bool,bool,bool))' "$SESSION_ID")
  echo "session: $SESSION"
  DEPOSIT_ID=$(echo "$SESSION" | tr -d '()' | cut -d, -f5 | tr -d ' ')
  [ "$DEPOSIT_ID" = "$EXPECTED_ID" ] || { echo "deposit id $DEPOSIT_ID != expected $EXPECTED_ID"; exit 1; }
  echo "zk-p2p deposit id: $DEPOSIT_ID"

  log "verifying the deposit on EscrowV2"
  DEPOSIT=$(cast call --rpc-url "$RPC" "$ESCROW" \
    'getDeposit(uint256)((address,address,address,(uint256,uint256),bool,uint256,uint256,address,bool))' "$DEPOSIT_ID")
  echo "deposit: $DEPOSIT"
  echo "$DEPOSIT" | grep -qi "$GLUE" || { echo "depositor is not the glue contract"; exit 1; }
  echo "$DEPOSIT" | grep -q "$AMOUNT" || { echo "remainingDeposits != $AMOUNT"; exit 1; }
  PAYEE_TOPIC=$(cast keccak 'DepositPaymentMethodAdded(uint256,bytes32,bytes32,address)')
  BLOCK=$(cast block-number --rpc-url "$RPC")
  LOGS=$(cast logs --rpc-url "$RPC" --from-block $((BLOCK-3)) --to-block "$BLOCK" --address "$ESCROW" "$PAYEE_TOPIC")
  echo "$LOGS" | grep -qi "$PAYEE_HASH" || { echo "DepositPaymentMethodAdded does not carry our payee hash"; echo "$LOGS"; exit 1; }
  echo "DepositPaymentMethodAdded carries payeeDetails $PAYEE_HASH"

  log "withdrawFromZkp2p as the user (no taker scenario)"
  cast send --rpc-url "$RPC" --private-key "$USER_KEY" "$GLUE" 'withdrawFromZkp2p(bytes32)' "$SESSION_ID" >/dev/null
  USER_BAL=$(cast call --rpc-url "$RPC" "$USDC" 'balanceOf(address)(uint256)' "$USER" | cut -d' ' -f1)
  echo "user USDC balance after withdraw: $USER_BAL"
  [ "$USER_BAL" = "$AMOUNT" ] || { echo "user did not receive $AMOUNT"; exit 1; }
  echo "escrow remainingDeposits: $(cast call --rpc-url "$RPC" "$ESCROW" 'getDeposit(uint256)((address,address,address,(uint256,uint256),bool,uint256,uint256,address,bool))' "$DEPOSIT_ID")"

  log "PASS: createSession -> processOfframp -> EscrowV2 deposit $DEPOSIT_ID -> withdraw, against the real EscrowV2 bytecode"

elif [ "$MODE" = "coordinator" ]; then
  command -v python3 >/dev/null || { echo "python3 required"; exit 1; }
  NEAR_PORT=4101; ZKP2P_PORT=4102; COORD_PORT=3100
  WORK=$(mktemp -d)
  log "starting mock NEAR (:$NEAR_PORT) and mock curator (:$ZKP2P_PORT)"
  python3 "$ROOT/scripts/dryrun/mock_near.py" --port $NEAR_PORT > "$WORK/near.log" 2>&1 & PIDS+=($!)
  python3 "$ROOT/scripts/dryrun/mock_zkp2p.py" --port $ZKP2P_PORT > "$WORK/zkp2p.log" 2>&1 & PIDS+=($!)
  sleep 1

  log "building and starting the coordinator against the fork"
  (cd "$ROOT" && cargo build -q -p zecp2p-coordinator)
  cat > "$WORK/config.toml" <<EOF
[network]
base_rpc_url = "$RPC"
chain_id = 8453
[contracts]
usdc = "$USDC"
zkp2p_escrow = "$ESCROW"
zkp2p_orchestrator = "$ORCHESTRATOR"
glue_contract = "$GLUE"
[near]
api_url = "http://127.0.0.1:$NEAR_PORT"
default_timeout = 600
[zkp2p]
api_url = "http://127.0.0.1:$ZKP2P_PORT"
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
  # Run from $WORK so the repo's .env (with placeholder addresses) is not loaded
  ( cd "$WORK" && exec env ZECP2P_CONFIG="$WORK/config.toml" GLUE_CONTRACT_ADDRESS="$GLUE" COORDINATOR_PRIVATE_KEY=$KEEPER_KEY \
      RUST_LOG=zecp2p_coordinator=info "$ROOT/target/debug/zecp2p-coordinator" > "$WORK/coordinator.log" 2>&1 ) & PIDS+=($!)
  for _ in $(seq 1 30); do sleep 1; curl -sf "$COORD/health" >/dev/null && break; done
  curl -sf "$COORD/health" >/dev/null || { cat "$WORK/coordinator.log"; exit 1; }

  log "POST /offramp (user_address = keeper so the coordinator can call withdraw)"
  RESP=$(curl -sf -X POST "$COORD/offramp" -H 'Content-Type: application/json' -d "{
    \"zec_amount\": \"0.8\", \"venmo_username\": \"dryrun-user\",
    \"user_address\": \"$KEEPER\", \"taker_address\": \"$USER\",
    \"zec_refund_address\": \"t1KzZ5n2TPvvDDNhVbFcZDkhjYVBFfd1iRw\", \"min_rate\": \"1.0\" }")
  echo "$RESP"
  SID=$(echo "$RESP" | python3 -c 'import sys,json; print(json.load(sys.stdin)["session_id"])')
  echo "curator registered: $(curl -s http://127.0.0.1:$ZKP2P_PORT/admin/state)"

  fund_glue
  log "telling mock NEAR the swap succeeded"
  curl -sf -X POST "http://127.0.0.1:$NEAR_PORT/admin/status" -H 'Content-Type: application/json' -d '{"status":"SUCCESS"}' >/dev/null

  log "waiting for the keeper (15s poll) to reach zkp2p_deposited"
  STATUS=""
  for _ in $(seq 1 12); do
    sleep 5
    STATUS=$(curl -sf "$COORD/offramp/$SID" | python3 -c 'import sys,json; print(json.load(sys.stdin)["status"])')
    echo "  status: $STATUS"
    [ "$STATUS" = "zkp2p_deposited" ] && break
    [ "$STATUS" = "failed" ] && { cat "$WORK/coordinator.log"; exit 1; }
  done
  [ "$STATUS" = "zkp2p_deposited" ] || { cat "$WORK/coordinator.log"; exit 1; }
  curl -sf "$COORD/offramp/$SID"; echo

  log "POST /offramp/$SID/withdraw"
  curl -sf -X POST "$COORD/offramp/$SID/withdraw"; echo
  echo "keeper USDC balance: $(cast call --rpc-url "$RPC" "$USDC" 'balanceOf(address)(uint256)' "$KEEPER")"
  log "PASS: coordinator drove POST /offramp -> keeper -> EscrowV2 deposit -> withdraw on the fork (logs in $WORK)"
elif [ "$MODE" = "claim" ]; then
  # ---------------------------------------------------------------- claim
  # The full taker leg against real deployed bytecode: stake, signalIntent,
  # then fulfillIntent with an enclave attestation re-bound to the intent hash
  # this fork actually produces.
  #
  # Needs an attestation.json from scripts/proof (any intent hash; it gets
  # re-bound below) and, to re-bind, the same Venmo cookie the prover uses.
  ATT="${ATTESTATION_JSON:-$ROOT/scripts/proof/attestation.json}"
  [ -f "$ATT" ] || { echo "no attestation at $ATT; run scripts/proof first"; exit 1; }
  command -v python3 >/dev/null || { echo "python3 required"; exit 1; }
  python3 -c 'import eth_abi, eth_utils' 2>/dev/null || { echo "pip install eth-abi eth-utils"; exit 1; }

  CLAIM_AMOUNT="${CLAIM_AMOUNT:-1000000}"                       # $1, matches the payment
  REAL_PAYEE="${PAYEE_HASH:-0x853410f0416f12611961e72ee5397ec6839a3f6475467f8a557bbdb3fc8555db}"
  STAKE_VAULT=0x47c26258222e2f96424bD2B21bf173f0DA5034C7
  VERIFIER=0xC6F4a193576C60892a47e111Bb5706c30162502B
  MIN_RATE=1000000000000000000

  log "claim rehearsal: \$$(python3 -c "print($CLAIM_AMOUNT/1e6)") deposit, payee $REAL_PAYEE"
  echo "verifier code on fork: $(( ($(cast code --rpc-url "$RPC" $VERIFIER | wc -c) - 3) / 2 )) bytes"

  # A maker deposit carrying the REAL curator payee hash. The verifier checks
  # the attested payeeDetails against the intent's payeeId, so a mock hash here
  # would fail for the right reason but prove nothing.
  SESSION_ID=$(cast keccak "claim-session-$(date +%s)")
  cast send --rpc-url "$RPC" --private-key "$KEEPER_KEY" "$GLUE" \
    'createSession(bytes32,address,bytes32,uint256,uint256)' \
    "$SESSION_ID" "$USER" "$REAL_PAYEE" "$MIN_RATE" "$CLAIM_AMOUNT" >/dev/null

  log "funding the glue with exactly $CLAIM_AMOUNT USDC units"
  cast rpc --rpc-url "$RPC" anvil_impersonateAccount "$ESCROW" >/dev/null
  cast rpc --rpc-url "$RPC" anvil_setBalance "$ESCROW" 0x1000000000000000000 >/dev/null
  cast send --rpc-url "$RPC" --unlocked --from "$ESCROW" "$USDC" \
    'transfer(address,uint256)(bool)' "$GLUE" "$CLAIM_AMOUNT" >/dev/null
  cast rpc --rpc-url "$RPC" anvil_stopImpersonatingAccount "$ESCROW" >/dev/null

  log "processOfframp -> real EscrowV2.createDeposit"
  DEPOSIT_ID=$(cast call --rpc-url "$RPC" "$ESCROW" 'depositCounter()(uint256)')
  cast send --rpc-url "$RPC" --private-key "$KEEPER_KEY" "$GLUE" \
    'processOfframp(bytes32,bytes32[],(address,bytes32,bytes)[],(bytes32,uint256,(address,bytes,int16,uint32))[][])' \
    "$SESSION_ID" "[$VENMO]" "[(0x0000000000000000000000000000000000000000,$REAL_PAYEE,0x)]" \
    "[[($USD,$MIN_RATE,(0x0000000000000000000000000000000000000000,0x,0,0))]]" >/dev/null
  echo "deposit id: $DEPOSIT_ID"

  # The taker is a fresh anvil account; give it USDC for the stake by
  # impersonating a holder. On mainnet this is real money the taker must own.
  log "funding + staking the taker (OrchestratorV3 lifecycle hook locks stake == intent amount)"
  cast rpc --rpc-url "$RPC" anvil_impersonateAccount "$ESCROW" >/dev/null
  cast rpc --rpc-url "$RPC" anvil_setBalance "$ESCROW" 0x1000000000000000000 >/dev/null
  cast send --rpc-url "$RPC" --unlocked --from "$ESCROW" "$USDC" \
    'transfer(address,uint256)(bool)' "$USER" "$CLAIM_AMOUNT" >/dev/null
  cast rpc --rpc-url "$RPC" anvil_stopImpersonatingAccount "$ESCROW" >/dev/null
  cast send --rpc-url "$RPC" --private-key "$USER_KEY" "$USDC" \
    'approve(address,uint256)(bool)' "$STAKE_VAULT" "$CLAIM_AMOUNT" >/dev/null
  cast send --rpc-url "$RPC" --private-key "$USER_KEY" "$STAKE_VAULT" \
    'depositStake(uint256)' "$CLAIM_AMOUNT" >/dev/null
  echo "taker freeStake: $(cast call --rpc-url "$RPC" $STAKE_VAULT 'freeStake(address)(uint256)' "$USER")"

  log "signalIntent on the real OrchestratorV3"
  SIGNAL_ARGS="($ESCROW,$DEPOSIT_ID,$CLAIM_AMOUNT,$USER,$VENMO,$USD,$MIN_RATE,[],0x,0,0x0000000000000000000000000000000000000000,0x,0x)"
  SIGNAL_SIG='signalIntent((address,uint256,uint256,address,bytes32,bytes32,uint256,(address,uint256)[],bytes,uint256,address,bytes,bytes))'
  # Simulate first so a revert prints its custom error instead of vanishing.
  if ! SIM=$(cast call --rpc-url "$RPC" --from "$USER" "$ORCHESTRATOR" "$SIGNAL_SIG" "$SIGNAL_ARGS" 2>&1); then
    echo "$SIM" | head -5
    log "FAIL: signalIntent reverted (reason above)"; exit 1
  fi
  cast send --rpc-url "$RPC" --private-key "$USER_KEY" "$ORCHESTRATOR" "$SIGNAL_SIG" "$SIGNAL_ARGS" >/dev/null

  # IntentSignaled's first indexed topic is the intent hash. The signature has
  # ten parameters; taking it from the shipped ABI rather than retyping it.
  SIGNALED=$(cast keccak 'IntentSignaled(bytes32,address,uint256,bytes32,address,address,uint256,bytes32,uint256,uint256)')
  BN=$(cast block-number --rpc-url "$RPC")
  INTENT_HASH=$(cast logs --rpc-url "$RPC" --from-block $((BN-5)) --to-block "$BN" \
    --address "$ORCHESTRATOR" "$SIGNALED" --json 2>/dev/null \
    | python3 -c 'import sys,json; l=json.load(sys.stdin); print(l[-1]["topics"][1] if l else "")')
  [ -n "$INTENT_HASH" ] || { echo "could not read intent hash from IntentSignaled logs"; exit 1; }
  echo "intent hash on fork: $INTENT_HASH"

  # UnifiedPaymentVerifierV3 cross-checks the attested snapshot's intent
  # timestamp against the intent actually stored on chain and reverts with
  # "UPV: Snapshot timestamp mismatch" if they differ. So the attestation must
  # be built with the intent's real signal time, not Date.now().
  INTENT_TS=$(cast call --rpc-url "$RPC" "$ORCHESTRATOR" \
    'getIntent(bytes32)((address,address,address,uint256,uint256,uint256,bytes32,bytes32,uint256,address,bytes))' \
    "$INTENT_HASH" 2>/dev/null | tr -d '()' | cut -d, -f6 | tr -d ' ' | cut -d'[' -f1)
  [ -n "$INTENT_TS" ] || { echo "could not read intent timestamp"; exit 1; }
  INTENT_TS_MS=$((INTENT_TS * 1000))
  echo "intent timestamp: ${INTENT_TS}s -> ${INTENT_TS_MS}ms"

  # ---- re-bind the attestation to THIS intent hash ----
  # The enclave re-signs the same Venmo payment for any intent hash, which is
  # what makes a mainnet claim of this payment possible at all.
  if [ -n "${VENMO_COOKIE:-}" ] && [ -n "${VENMO_SENDER_ID:-}" ]; then
    log "re-binding the attestation to $INTENT_HASH via the live enclave"
    ( cd "$ROOT/scripts/proof" && INTENT_HASH="$INTENT_HASH" PAYEE_HASH="$REAL_PAYEE" \
        INTENT_AMOUNT="$CLAIM_AMOUNT" PAYMENT_INDEX="${PAYMENT_INDEX:-0}" \
        INTENT_TIMESTAMP_MS="$INTENT_TS_MS" \
        OUT="$WORKDIR/attestation.rebound.json" node prove_payment.mjs >"$WORKDIR/rebind.log" 2>&1 ) \
      || { echo "re-binding failed:"; tail -20 "$WORKDIR/rebind.log"; exit 1; }
    ATT="$WORKDIR/attestation.rebound.json"
    echo "re-bound attestation written"
  else
    echo "VENMO_COOKIE/VENMO_SENDER_ID unset: using $ATT as-is."
    echo "fulfillIntent will revert unless its intentHash already equals $INTENT_HASH."
  fi

  log "building fulfillIntent calldata from the attestation"
  PROOF=$(python3 "$ROOT/scripts/dryrun/build_proof.py" "$ATT")
  echo "paymentProof: ${#PROOF} hex chars"

  log "fulfillIntent on the real OrchestratorV3 -> UnifiedPaymentVerifierV3"
  BAL_BEFORE=$(cast call --rpc-url "$RPC" "$USDC" 'balanceOf(address)(uint256)' "$USER" | cut -d' ' -f1)
  set +e
  FULFILL_OUT=$(cast send --rpc-url "$RPC" --private-key "$USER_KEY" "$ORCHESTRATOR" \
    'fulfillIntent((bytes,bytes32,bytes,bytes))' "($PROOF,$INTENT_HASH,0x,0x)" 2>&1)
  FULFILL_RC=$?
  set -e
  if [ $FULFILL_RC -ne 0 ]; then
    echo "$FULFILL_OUT" | tail -20
    log "FAIL: fulfillIntent reverted (reason above)"
    exit 1
  fi
  BAL_AFTER=$(cast call --rpc-url "$RPC" "$USDC" 'balanceOf(address)(uint256)' "$USER" | cut -d' ' -f1)
  echo "taker USDC before=$BAL_BEFORE after=$BAL_AFTER"
  VERIFIED=$(cast keccak 'PaymentVerified(bytes32,bytes32,bytes32,uint256,uint256,bytes32,bytes32)')
  BN2=$(cast block-number --rpc-url "$RPC")
  cast logs --rpc-url "$RPC" --from-block $((BN2-2)) --to-block "$BN2" --address "$VERIFIER" "$VERIFIED" 2>/dev/null | head -20

  log "PASS: signalIntent + fulfillIntent executed against the real deployed EscrowV2/OrchestratorV3/UnifiedPaymentVerifierV3"

else
  echo "unknown mode $MODE"; exit 1
fi

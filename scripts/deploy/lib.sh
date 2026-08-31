#!/usr/bin/env bash
# Shared helpers for the scripts/deploy/* steps.
#
# Sourced, not executed. Loads .env, resolves every setting from the
# environment, and provides the preflight checks the steps share. Nothing here
# sends a transaction.
#
# Every value the deploy needs comes from the environment, normally through the
# repo-root .env (gitignored). .env.example documents each one.

set -euo pipefail
export FOUNDRY_DISABLE_NIGHTLY_WARNING=1

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STATE_DIR="$ROOT/scripts/deploy/state"

# ---------------------------------------------------------------- output
if [ -t 1 ]; then
  C_OK=$'\033[32m'; C_BAD=$'\033[31m'; C_DIM=$'\033[2m'; C_OFF=$'\033[0m'
else
  C_OK=""; C_BAD=""; C_DIM=""; C_OFF=""
fi
log()  { printf '\n== %s\n' "$*"; }
ok()   { printf '  %sok%s   %s\n' "$C_OK" "$C_OFF" "$*"; }
bad()  { printf '  %sFAIL%s %s\n' "$C_BAD" "$C_OFF" "$*"; }
note() { printf '  %s%s%s\n' "$C_DIM" "$*" "$C_OFF"; }
die()  { printf '\n%serror:%s %s\n' "$C_BAD" "$C_OFF" "$*" >&2; exit 1; }

# ---------------------------------------------------------------- env loading
# Load .env without letting it clobber anything already exported, so a
# one-off `AMOUNT=... script.sh` on the command line still wins.
load_env() {
  local file="${ZECP2P_ENV_FILE:-$ROOT/.env}"
  [ -f "$file" ] || return 0
  local line key
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ''|'#'*) continue;; esac
    key="${line%%=*}"
    key="${key#export }"
    key="$(printf '%s' "$key" | tr -d '[:space:]')"
    [ -n "$key" ] || continue
    # Only set what the caller has not already set.
    if [ -z "${!key:-}" ]; then
      eval "export $line" 2>/dev/null || true
    fi
  done < "$file"
}
load_env

# ---------------------------------------------------------------- settings
CHAIN_ID="${CHAIN_ID:-8453}"
BASE_RPC_URL="${BASE_RPC_URL:-https://mainnet.base.org}"
USDC_ADDRESS="${USDC_ADDRESS:-0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913}"
ZKP2P_ESCROW_ADDRESS="${ZKP2P_ESCROW_ADDRESS:-0x777777779d229cdF3110e9de47943791c26300Ef}"
ZKP2P_ORCHESTRATOR_ADDRESS="${ZKP2P_ORCHESTRATOR_ADDRESS:-0x014025fDE093f8701d86e9f38e2C3a9b779cb5c7}"
STAKE_VAULT_ADDRESS="${STAKE_VAULT_ADDRESS:-0x47c26258222e2f96424bD2B21bf173f0DA5034C7}"
ATTESTATION_VERIFIER_ADDRESS="${ATTESTATION_VERIFIER_ADDRESS:-0xC6F4a193576C60892a47e111Bb5706c30162502B}"
ATTESTATION_URL="${ATTESTATION_URL:-https://attestation-service.zkp2p.xyz}"
ZKP2P_API_URL="${ZKP2P_API_URL:-https://api.zkp2p.xyz}"
NEAR_API_URL="${NEAR_API_URL:-https://1click.chaindefuser.com}"

# The file each step reads its predecessor's output from, and appends to.
DEPLOYED_ENV="${DEPLOYED_ENV:-$STATE_DIR/deployed.$CHAIN_ID.env}"

# Pull in a previous step's recorded addresses, again without clobbering
# anything the caller set explicitly.
load_deployed() {
  [ -f "$DEPLOYED_ENV" ] || return 0
  local line key
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ''|'#'*) continue;; esac
    key="${line%%=*}"
    [ -n "$key" ] || continue
    if [ -z "${!key:-}" ]; then eval "export $line" 2>/dev/null || true; fi
  done < "$DEPLOYED_ENV"
}

# Record a key=value into the deployed-state file, replacing any previous entry
# so re-running a step does not leave two conflicting lines behind.
record() {
  local key="$1" value="$2"
  mkdir -p "$STATE_DIR"
  [ -f "$DEPLOYED_ENV" ] || {
    printf '# zecp2p deploy state, chain %s. Written by scripts/deploy/*.\n' "$CHAIN_ID" > "$DEPLOYED_ENV"
    printf '# Addresses only; no keys. Safe to read, do not hand-edit while a step runs.\n' >> "$DEPLOYED_ENV"
  }
  local tmp
  tmp="$(mktemp)"
  grep -v "^${key}=" "$DEPLOYED_ENV" > "$tmp" 2>/dev/null || true
  printf '%s=%s\n' "$key" "$value" >> "$tmp"
  mv "$tmp" "$DEPLOYED_ENV"
  export "$key=$value"
}

# ---------------------------------------------------------------- checks
require_tools() {
  local t
  for t in "$@"; do
    command -v "$t" >/dev/null 2>&1 || die "'$t' is not on PATH. See DEPLOY.md for prerequisites."
  done
}

is_address() { [[ "${1:-}" =~ ^0x[0-9a-fA-F]{40}$ ]]; }

require_address() {
  local name="$1" value="${!1:-}"
  [ -n "$value" ] || die "$name is not set. Put it in .env (see .env.example)."
  is_address "$value" || die "$name is not a 0x address: $value"
}

require_var() {
  local name="$1" value="${!1:-}"
  [ -n "$value" ] || die "$name is not set. Put it in .env (see .env.example)."
  [ "$value" != "0x..." ] || die "$name is still the .env.example placeholder."
}

# The RPC answers, and it answers for the chain we think we are on. Every step
# runs this before anything else, so a misconfigured RPC cannot spend on the
# wrong chain.
require_chain() {
  local actual
  actual="$(cast chain-id --rpc-url "$BASE_RPC_URL" 2>/dev/null)" \
    || die "no answer from BASE_RPC_URL=$BASE_RPC_URL"
  [ "$actual" = "$CHAIN_ID" ] \
    || die "BASE_RPC_URL is chain $actual but CHAIN_ID is $CHAIN_ID. Refusing to continue."
  ok "rpc $BASE_RPC_URL is chain $actual"
}

# A contract address that must actually hold code. Catches a config pointing at
# an EOA, a wrong chain, or a typo, before a transaction encodes against it.
require_code() {
  local name="$1" addr="${!1:-}" size
  require_address "$name"
  size="$(cast code --rpc-url "$BASE_RPC_URL" "$addr" 2>/dev/null | wc -c)"
  size=$(( (size - 3) / 2 ))
  [ "$size" -gt 0 ] || die "$name ($addr) has no code on chain $CHAIN_ID"
  ok "$name $addr ($size bytes of code)"
}

deployer_address() {
  require_var DEPLOYER_PRIVATE_KEY
  cast wallet address --private-key "$DEPLOYER_PRIVATE_KEY" 2>/dev/null \
    || die "DEPLOYER_PRIVATE_KEY is not a valid private key"
}

eth_balance_wei() { cast balance --rpc-url "$BASE_RPC_URL" "$1" 2>/dev/null || echo 0; }
usdc_balance()    { cast call --rpc-url "$BASE_RPC_URL" "$USDC_ADDRESS" 'balanceOf(address)(uint256)' "$1" 2>/dev/null | awk '{print $1}'; }

# Warn, do not block, when a balance is thin: the caller may be doing a
# simulation that spends nothing.
warn_if_below_eth() {
  local addr="$1" min_wei="$2" label="$3" have
  have="$(eth_balance_wei "$addr")"
  if [ "$(python3 -c "print(1 if int('$have') < int('$min_wei') else 0)")" = "1" ]; then
    note "$label has $(cast from-wei "$have") ETH, below the $(cast from-wei "$min_wei") ETH this step expects"
    return 1
  fi
  ok "$label has $(cast from-wei "$have") ETH"
  return 0
}

# Whether this invocation is allowed to send transactions. Every step simulates
# unless --broadcast is passed, so a bare run can never spend.
BROADCAST=""
parse_broadcast() {
  local a
  for a in "$@"; do
    case "$a" in
      --broadcast) BROADCAST="--broadcast";;
      --help|-h) return 1;;
    esac
  done
  return 0
}

announce_mode() {
  if [ -n "$BROADCAST" ]; then
    printf '\n  %sBROADCAST%s: this run sends real transactions on chain %s.\n' "$C_BAD" "$C_OFF" "$CHAIN_ID"
  else
    printf '\n  SIMULATION: nothing is sent. Pass --broadcast to execute.\n'
  fi
}

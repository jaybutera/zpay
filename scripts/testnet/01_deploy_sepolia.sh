#!/usr/bin/env bash
# Deploy OfframpGlue (plus a stand-in zk-p2p escrow) to Base Sepolia.
#
# Simulates by default. Pass --broadcast to actually send transactions; that
# spends Sepolia ETH from PRIVATE_KEY.
#
# Usage:
#   scripts/testnet/01_deploy_sepolia.sh            # simulation only, nothing sent
#   scripts/testnet/01_deploy_sepolia.sh --broadcast
#
# Env:
#   PRIVATE_KEY            deployer key with Base Sepolia ETH (required)
#   BASE_SEPOLIA_RPC_URL   default https://sepolia.base.org
#   USDC_ADDRESS           default Circle USDC 0x036CbD53842c5426634e7929541eC2318f3dCF7e
#   MOCK_USDC=true         deploy a mintable MockUSDC instead (local anvil only)
#   ESCROW_ADDRESS         reuse an existing stand-in escrow instead of deploying one
#   BASESCAN_API_KEY       if set together with --broadcast, verifies sources on Basescan
#
# On success prints the three addresses and writes them to
# scripts/testnet/deployed.sepolia.env for 02_dryrun_sepolia.sh.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RPC="${BASE_SEPOLIA_RPC_URL:-https://sepolia.base.org}"
export FOUNDRY_DISABLE_NIGHTLY_WARNING=1
BROADCAST=""
[ "${1:-}" = "--broadcast" ] && BROADCAST="--broadcast"

: "${PRIVATE_KEY:?set PRIVATE_KEY to the deployer key (needs Base Sepolia ETH)}"
DEPLOYER=$(cast wallet address --private-key "$PRIVATE_KEY")
CHAIN=$(cast chain-id --rpc-url "$RPC")
echo "rpc:      $RPC (chain $CHAIN)"
echo "deployer: $DEPLOYER"
echo "balance:  $(cast balance --rpc-url "$RPC" "$DEPLOYER" --ether) ETH"
[ -n "$BROADCAST" ] || echo "mode:     SIMULATION (pass --broadcast to send)"

VERIFY=""
if [ -n "$BROADCAST" ] && [ -n "${BASESCAN_API_KEY:-}" ] && [ "$CHAIN" = "84532" ]; then
  VERIFY="--verify --etherscan-api-key $BASESCAN_API_KEY"
fi

OUT=$(cd "$ROOT/contracts" && forge script script/DeploySepolia.s.sol:DeploySepolia \
  --rpc-url "$RPC" $BROADCAST $VERIFY 2>&1) || { echo "$OUT"; exit 1; }
echo "$OUT" | grep -E "deployed at:|Using|Owner:|Keeper:|ONCHAIN EXECUTION|Total Paid|Error" || true

USDC=$(echo "$OUT" | sed -n 's/.*\(MockUSDC deployed at\|Using USDC at\): *\(0x[0-9a-fA-F]\{40\}\).*/\2/p' | head -1)
ESCROW=$(echo "$OUT" | sed -n 's/.*\(MockEscrowWithOrchestrator deployed at\|Using stand-in escrow at\): *\(0x[0-9a-fA-F]\{40\}\).*/\2/p' | head -1)
GLUE=$(echo "$OUT" | sed -n 's/.*OfframpGlue deployed at: *\(0x[0-9a-fA-F]\{40\}\).*/\1/p' | head -1)
[ -n "$GLUE" ] || { echo "$OUT"; echo "could not parse deployed addresses"; exit 1; }

if [ -n "$BROADCAST" ]; then
  cat > "$ROOT/scripts/testnet/deployed.sepolia.env" <<EOF
# written by 01_deploy_sepolia.sh on $(date -Iseconds), chain $CHAIN
USDC_ADDRESS=$USDC
ESCROW_ADDRESS=$ESCROW
GLUE_CONTRACT_ADDRESS=$GLUE
DEPLOYER=$DEPLOYER
EOF
  echo
  echo "wrote scripts/testnet/deployed.sepolia.env"
  echo "next: put these into config.testnet.toml ([contracts] usdc / zkp2p_escrow / zkp2p_orchestrator / glue_contract)"
  echo "      zkp2p_orchestrator = $ESCROW (the stand-in escrow also plays orchestrator)"
else
  echo
  echo "simulation ok: would deploy escrow stand-in and glue for USDC $USDC"
fi

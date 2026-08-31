#!/usr/bin/env bash
# Step 05: rehearse the whole on-chain path against real mainnet bytecode,
# on a local fork, before spending anything.
#
# Costs nothing and touches no live chain. It forks Base mainnet into anvil,
# deploys a throwaway glue there, and drives the real EscrowV2 and
# OrchestratorV3 with it.
#
#   scripts/deploy/05_rehearse_on_fork.sh              # contract + coordinator
#   scripts/deploy/05_rehearse_on_fork.sh contract     # just the glue path
#   scripts/deploy/05_rehearse_on_fork.sh coordinator  # through the HTTP API
#   scripts/deploy/05_rehearse_on_fork.sh claim        # + signalIntent/fulfillIntent
#
# The `claim` mode is the only one that needs anything from you: an attestation
# from scripts/proof, and the Venmo cookie to re-bind it to the fork's own
# intent hash. Without those it stops before fulfillIntent rather than pretend.
#
# This wraps scripts/dryrun/fork_base.sh, which holds the actual rehearsal, and
# adds the deployment's own configuration to it.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "$ROOT/scripts/deploy/lib.sh"
load_deployed

MODE="${1:-}"
case "$MODE" in
  --help|-h) sed -n '2,20p' "$0"; exit 0;;
esac

require_tools anvil cast forge

[ "$CHAIN_ID" = "8453" ] || die "the fork rehearsal forks Base mainnet; CHAIN_ID is $CHAIN_ID"

echo "fork rehearsal against real Base mainnet bytecode"
echo "forking : ${FORK_RPC_URL:-$BASE_RPC_URL}"
note "nothing here touches a live chain and nothing is spent"

export FORK_RPC_URL="${FORK_RPC_URL:-$BASE_RPC_URL}"

run_mode() {
  log "mode: $1"
  "$ROOT/scripts/dryrun/fork_base.sh" "$1"
}

if [ -n "$MODE" ]; then
  run_mode "$MODE"
else
  run_mode contract
  run_mode coordinator
  echo
  note "the claim leg (signalIntent + fulfillIntent) was not rehearsed."
  note "run 'scripts/deploy/05_rehearse_on_fork.sh claim' with an attestation"
  note "from scripts/proof to exercise it end to end."
fi

echo
echo "Next: scripts/deploy/06_prove_payment.sh (the Venmo attestation leg)"

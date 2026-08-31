# zecp2p

Trustless ZEC to Venmo offramp. Converts shielded Zcash to Venmo payments without centralized exchanges by combining NEAR Intents (ZEC → USDC) with zk-p2p (USDC → Venmo).

**[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** explains the whole system end to
end: both legs, the coordinator and taker, the trust boundaries, and why
`OfframpGlue` is deployed immutable rather than behind a proxy.

## Prerequisites

- Rust 1.75+
- Foundry (for smart contracts)
- Node >= 20 (for the Venmo attestation client)
- Python 3 (for the deploy scripts)

## Setup

**[DEPLOY.md](DEPLOY.md) is the deployment guide**: the ordered script sequence
to stand this up on Base mainnet from scratch, and an itemized funding list with
measured gas costs. Start there for a real deployment. The short version:

```bash
cargo build --release
(cd contracts && forge build)
(cd scripts/proof && npm install)

cp .env.example .env      # every address, key, RPC and URL lives here
$EDITOR .env

scripts/deploy/00_preflight.sh                    # read-only; spends nothing
scripts/deploy/01_deploy_contracts.sh --broadcast  # deploys OfframpGlue
scripts/deploy/02_configure_keeper.sh --broadcast  # hands the keeper role over
scripts/deploy/03_write_config.sh                  # generates the config files
scripts/deploy/04_verify_near_leg.sh               # dry quotes only
scripts/deploy/05_rehearse_on_fork.sh              # local fork; spends nothing
scripts/deploy/07_status.sh                        # read-only; run any time
```

Every step that can spend simulates by default and needs an explicit
`--broadcast`. Every step is idempotent.

Base mainnet (8453) is the only chain the whole flow runs on: zk-p2p's Venmo
verifier exists only there, and the attestation enclave signs an EIP-712 domain
bound to that chain, so a proof cannot be replayed elsewhere.

## Running the Coordinator

The coordinator is the REST API server that manages offramp sessions.

**Mainnet (Base):**
```bash
COORDINATOR_PRIVATE_KEY=0x... cargo run --bin zecp2p-coordinator
```

**Testnet (Base Sepolia):**
```bash
ZECP2P_CONFIG=config.testnet.toml \
COORDINATOR_PRIVATE_KEY=0x... \
cargo run --bin zecp2p-coordinator
```

The server runs on `http://127.0.0.1:3000` by default.

## Using the CLI

```bash
# Get a quote for ZEC amount
cargo run --bin zecp2p -- quote 0.5

# Start an offramp. No taker needed: the zk-p2p deposit is open to any taker.
cargo run --bin zecp2p -- offramp 0.5 \
  --venmo myusername \
  --user-address 0xYourBaseAddress \
  --zec-address t1YourZcashAddress \
  --min-rate 1.0

# --taker 0xAddress still works, but is advisory; zk-p2p does not enforce it.

# Check status
cargo run --bin zecp2p -- status <session-id>

# Watch until complete
cargo run --bin zecp2p -- watch <session-id>

# Rescue funds (if stuck after USDC received)
cargo run --bin zecp2p -- rescue <session-id>

# Withdraw from zk-p2p (if no taker)
cargo run --bin zecp2p -- withdraw <session-id>
```

Point CLI to a different coordinator:
```bash
cargo run --bin zecp2p -- --coordinator http://other-server:3000 quote 0.5
```

## Dry runs and testnet

`docs/testnet-deploy-plan.md` describes the two-stage plan. The scripts:

```bash
scripts/dryrun/fork_base.sh contract        # GlueContract against the real EscrowV2 on an anvil fork of Base; free
scripts/dryrun/fork_base.sh coordinator     # same, driven through the coordinator with mock NEAR and mock curator
scripts/dryrun/fork_base.sh claim           # + signalIntent/fulfillIntent with a real enclave attestation
scripts/testnet/00_verify_zkp2p_addresses.sh   # read-only checks of the zk-p2p addresses in the configs
scripts/testnet/01_deploy_sepolia.sh [--broadcast]   # deploy glue + stand-in escrow to Base Sepolia
scripts/testnet/02_dryrun_sepolia.sh        # POST /offramp -> fake NEAR delivery -> keeper -> withdraw on Sepolia
```

`scripts/dryrun/mock_near.py` and `scripts/dryrun/mock_zkp2p.py` stand in for
the 1Click API and the zk-p2p curator; point the coordinator at them with
`NEAR_API_URL` and `ZKP2P_API_URL`.

## Running a taker

The other side of the market. `zecp2p-taker` watches Base for claimable
deposits, claims one, and pays the Venmo through a browser you have already
logged in.

```bash
cp config.taker.example.toml config.taker.toml   # then set glue_contract

# See what it would do without spending anything
TAKER_PRIVATE_KEY=0x... cargo run --bin zecp2p-taker -- run --dry-run
```

`docs/taker-agent.md` covers the stake requirement, the commands, and the one
step that stays manual. Proving a payment is a plain HTTPS call to zk-p2p's TEE;
`scripts/deploy/06_prove_payment.sh` drives it against a live intent. `docs/taker-matching-design.md` covers why deposits are
open to any taker, verified against production bytecode by
`scripts/taker/prove_open_signaling.sh`.

## Testing

**Run all Rust tests:**
```bash
cargo test --workspace
```

**Run smart contract tests:**
```bash
cd contracts
forge test
```

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/quote?zec_amount=0.5` | GET | Get conversion quote |
| `/offramp` | POST | Create new offramp session |
| `/offramp/{id}` | GET | Get session status |
| `/offramp/{id}/rescue` | POST | Rescue stuck funds |
| `/offramp/{id}/withdraw` | POST | Withdraw from zk-p2p |
| `/deposits/open` | GET | Deposits takers can claim, with the Venmo username to pay |

**Create offramp request:**
```json
{
  "zec_amount": "500000000",
  "venmo_username": "alice",
  "user_address": "0x...",
  "zec_refund_address": "t1...",
  "min_rate": "1.0",
  "timeout_seconds": 600
}
```

## Venmo payee registration

zk-p2p identifies the payout account on-chain by `payeeDetails`, a bytes32 that
its curator service issues when a maker registers a payout identifier. The
coordinator performs that registration when an offramp is created:

1. `POST {zkp2p.api_url}/v2/makers/validate` with `{"processorName": "venmo", "offchainId": "<username>"}`.
   The curator checks the exact username casing; a `false` answer fails the request with HTTP 400.
2. `POST {zkp2p.api_url}/v2/makers/create` with the same body. The returned
   `hashedOnchainId` is stored as the session's `payee_details_hash`, written to
   the GlueContract session, and used as `payeeDetails` for the zk-p2p deposit.

The hash is opaque and server-side; `keccak256(username)` would create a deposit
that no Venmo proof can ever fulfill. `GlueContract.processOfframp` rejects any
deposit whose `payeeDetails` differs from the hash recorded at session creation.

Usernames are sent without the leading `@`.

## Configuration

Configuration comes from `.env` (gitignored; `.env.example` documents every
variable) and is turned into config files by
`scripts/deploy/03_write_config.sh`. Two checked-in files remain for reference
and for the testnet path:

- `config.toml` - Base mainnet defaults
- `config.testnet.toml` - Base Sepolia testnet

Key settings:
```toml
[network]
base_rpc_url = "https://mainnet.base.org"
chain_id = 8453

[contracts]
glue_contract = "0x..."  # Your deployed contract

[server]
host = "127.0.0.1"
port = 3000

[database]
path = "zecp2p.db"

[zkp2p]
api_url = "https://api.zkp2p.xyz"   # curator API used for payee registration

[attestation]
service_url = "https://attestation-service.zkp2p.xyz"  # the TEE that signs payment proofs
verifier = "0xC6F4a193576C60892a47e111Bb5706c30162502B"

[keeper]
poll_interval_seconds = 15
```

Environment overrides: `BASE_RPC_URL`, `GLUE_CONTRACT_ADDRESS`, `NEAR_API_URL`,
`ZKP2P_API_URL`, `ATTESTATION_URL`, `ATTESTATION_VERIFIER_ADDRESS`,
`STAKE_VAULT_ADDRESS`, `KEEPER_POLL_INTERVAL_SECONDS`.

Keys are never read from a config file. The coordinator takes
`COORDINATOR_PRIVATE_KEY` and the taker takes `TAKER_PRIVATE_KEY` from the
environment.

## Session Flow

1. **Created** - Session initialized
2. **NearIntentPending** - Waiting for ZEC deposit to NEAR address
3. **UsdcReceived** - USDC arrived at GlueContract
4. **Zkp2pDeposited** - USDC deposited to zk-p2p escrow
5. **IntentSignaled** - A taker claimed the order
6. **Fulfilled** - Venmo payment verified, complete

If something goes wrong:
- Use `rescue` after USDC is received but before zk-p2p deposit
- Use `withdraw` after zk-p2p deposit if no taker claims it

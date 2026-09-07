# The Base rail

The first route this project shipped: shielded ZEC is swapped to USDC on Base
through NEAR Intents 1Click, the USDC is parked in zk-p2p's EscrowV2 through
our `OfframpGlue` contract, and a taker claims it, pays the user's Venmo from
their own account, and proves the payment to release the USDC.

The site's app does not use this route today; it uses the native Zcash escrow
in `zecp2p-v2coordinator`. The rail still builds, its contract is deployed at
`0x617544CC688F7f742cA68B5d9106890500b6C689` on Base mainnet, and the page for
it is served at `/app/advanced/`.

[docs/ARCHITECTURE.md](../../docs/ARCHITECTURE.md) explains both legs, the
trust boundaries, and why the glue is deployed immutable rather than behind a
proxy.

## Why only Base mainnet

zk-p2p's Venmo verifier is deployed on Base mainnet (chain 8453) and nowhere
else, and the attestation enclave signs an EIP-712 domain bound to that chain
plus `UnifiedPaymentVerifierV3 0xC6F4a193576C60892a47e111Bb5706c30162502B`.
A proof of a real Venmo payment cannot be replayed onto Sepolia. Base Sepolia
gets as far as `signalIntent` and stops.

## Deploying

[DEPLOY.md](../../DEPLOY.md) is the deployment guide: the ordered scripts to
stand this up on Base mainnet from scratch, and a funding list with measured
gas costs. The short version:

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

## Running the coordinator

The coordinator is the REST server that manages offramp sessions and runs the
keeper that moves USDC from the glue into zk-p2p.

```bash
COORDINATOR_PRIVATE_KEY=0x... cargo run --bin zecp2p-coordinator

# Base Sepolia
ZECP2P_CONFIG=config.testnet.toml COORDINATOR_PRIVATE_KEY=0x... cargo run --bin zecp2p-coordinator
```

It listens on `http://127.0.0.1:3000` by default. Configuration comes from
`.env` (gitignored; `.env.example` documents every variable), turned into
config files by `scripts/deploy/03_write_config.sh`. `config.toml` and
`config.testnet.toml` are checked in for reference. Keys are never read from a
config file: the coordinator takes `COORDINATOR_PRIVATE_KEY` and the taker
takes `TAKER_PRIVATE_KEY` from the environment.

## Using the CLI

```bash
cargo run --bin zecp2p -- quote 0.5

cargo run --bin zecp2p -- offramp 0.5 \
  --venmo myusername \
  --user-address 0xYourBaseAddress \
  --zec-address t1YourZcashAddress \
  --min-rate 1.0

cargo run --bin zecp2p -- status <session-id>
cargo run --bin zecp2p -- watch <session-id>
cargo run --bin zecp2p -- rescue <session-id>     # USDC received, not yet deposited
cargo run --bin zecp2p -- withdraw <session-id>   # deposited, no taker claimed it

cargo run --bin zecp2p -- --coordinator http://other-server:3000 quote 0.5
```

No taker is named: the zk-p2p deposit is open to any taker. `--taker` is
accepted but advisory, since zk-p2p does not enforce it.

A session moves through `Created`, `NearIntentPending` (waiting for ZEC at
the 1Click deposit address), `UsdcReceived`, `Zkp2pDeposited`,
`IntentSignaled` (a taker claimed it) and `Fulfilled`. `rescue` applies after
`UsdcReceived` and before the deposit; `withdraw` applies after the deposit if
nobody claims it.

## Running a taker

`zecp2p-taker` watches Base for claimable deposits, claims one, pays the Venmo
through a browser you have signed in, and proves the payment.

```bash
cp config.taker.example.toml config.taker.toml   # then set glue_contract
TAKER_PRIVATE_KEY=0x... cargo run --bin zecp2p-taker -- run --dry-run
```

[docs/taker-agent.md](../../docs/taker-agent.md) covers the stake requirement,
each command, which one may send money, and what a dry run prints.
[docs/taker-matching-design.md](../../docs/taker-matching-design.md) covers why
deposits are open to any taker, verified against production bytecode by
`scripts/taker/prove_open_signaling.sh`.

The unattended installation the live host uses is in `deploy/hub/`:
`install-hub.sh` installs the Chrome unit and the taker unit under
`systemd --user`, and the taker runs in a supervised dry-run until
`TAKER_PRIVATE_KEY`, a filled-in `venmo.local.toml` with a TOTP seed, and an
`only_user` file are all present. `preflight.sh` chooses the mode and always
exits 0, so a missing credential never becomes a restart loop.

## Dry runs and testnet

```bash
scripts/dryrun/fork_base.sh contract        # the glue against the real EscrowV2 on an anvil fork of Base
scripts/dryrun/fork_base.sh coordinator     # same, through the coordinator with mock NEAR and mock curator
scripts/dryrun/fork_base.sh claim           # plus signalIntent/fulfillIntent with a real enclave attestation
scripts/testnet/00_verify_zkp2p_addresses.sh
scripts/testnet/01_deploy_sepolia.sh [--broadcast]
scripts/testnet/02_dryrun_sepolia.sh
```

`scripts/dryrun/mock_near.py` and `scripts/dryrun/mock_zkp2p.py` stand in for
the 1Click API and the zk-p2p curator; point the coordinator at them with
`NEAR_API_URL` and `ZKP2P_API_URL`.

## API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | liveness |
| `/stats` | GET | fills, USDC settled, open orders, last fill, contract address |
| `/quote?zec_amount=0.5` | GET | conversion quote |
| `/offramp` | POST | create a session |
| `/offramp/{id}` | GET | session status |
| `/offramp/{id}/rescue` | POST | rescue stuck funds |
| `/offramp/{id}/withdraw` | POST | withdraw from zk-p2p |
| `/deposits/open` | GET | deposits takers can claim, with the Venmo username to pay |

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

zk-p2p identifies the payout account on chain by `payeeDetails`, a bytes32
its curator service issues. The coordinator registers it when a session is
created: `POST {zkp2p.api_url}/v2/makers/validate` with
`{"processorName": "venmo", "offchainId": "<username>"}`, where a `false`
answer fails the request with HTTP 400, then `POST /v2/makers/create` with the
same body. The returned `hashedOnchainId` is stored as the session's
`payee_details_hash` and used as `payeeDetails` for the deposit.

The hash is opaque and server-side. `keccak256(username)` would create a
deposit no Venmo proof can ever fulfil, and `GlueContract.processOfframp`
rejects any deposit whose `payeeDetails` differs from the hash recorded at
creation. Usernames are sent without the leading `@`.

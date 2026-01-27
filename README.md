# zecp2p

Trustless ZEC to Venmo offramp. Converts shielded Zcash to Venmo payments without centralized exchanges by combining NEAR Intents (ZEC → USDC) with zk-p2p (USDC → Venmo).

## Prerequisites

- Rust 1.75+
- Foundry (for smart contracts)

## Setup

1. **Build the project:**
   ```bash
   cargo build --release
   ```

2. **Deploy the GlueContract** (if not already deployed):
   ```bash
   cd contracts
   forge build
   forge script script/Deploy.s.sol:DeployOfframpGlue \
     --rpc-url https://sepolia.base.org \
     --broadcast \
     --private-key $PRIVATE_KEY
   ```

3. **Configure environment:**
   ```bash
   cp .env.example .env
   ```

   Set your deployed contract address in `config.toml`:
   ```toml
   [contracts]
   glue_contract = "0xYourDeployedContractAddress"
   ```

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

# Start an offramp
cargo run --bin zecp2p -- offramp 0.5 \
  --venmo myusername \
  --user-address 0xYourBaseAddress \
  --taker 0xTakerAddress \
  --zec-address t1YourZcashAddress \
  --min-rate 30

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

**Create offramp request:**
```json
{
  "zec_amount": "500000000",
  "venmo_username": "alice",
  "user_address": "0x...",
  "taker_address": "0x...",
  "zec_refund_address": "t1...",
  "min_rate": "30000000000000000000",
  "timeout_seconds": 600
}
```

## Configuration

Two config files are provided:
- `config.toml` - Base mainnet
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
```

## Session Flow

1. **Created** - Session initialized
2. **NearIntentPending** - Waiting for ZEC deposit to NEAR address
3. **UsdcReceived** - USDC arrived at GlueContract
4. **Zkp2pDeposited** - USDC deposited to zk-p2p escrow
5. **IntentSignaled** - Taker claimed the order
6. **Fulfilled** - Venmo payment verified, complete

If something goes wrong:
- Use `rescue` after USDC is received but before zk-p2p deposit
- Use `withdraw` after zk-p2p deposit if no taker claims it

# ZEC → Venmo Offramp (V0)

Trustless offramp from shielded ZEC to Venmo by gluing NEAR Intents (ZEC → USDC) with zk-p2p (USDC → Venmo).

## Problem

User holds shielded ZEC and wants fiat on Venmo. No trustless path exists today without a centralized exchange. Two decentralized systems solve pieces of this:

- **NEAR Intents**: Swaps shielded ZEC → USDC across chains via competing solvers. Live, $5B+ volume.
- **zk-p2p**: Settles USDC → Venmo via ZK proofs of payment. Live on Base.

This spec connects them.

## High-Level Flow

```
Shielded ZEC
    │
    ▼ [1] NEAR Intent: ZEC → USDC
USDC on Base (in GlueContract)
    │
    ▼ [2] GlueContract routes to zk-p2p
zk-p2p escrow (user's USDC held)
    │
    ▼ [3] Taker signals intent
    ▼ [4] Taker sends Venmo to user
    ▼ [5] Taker proves payment via ZK
    │
    ▼ [6] zk-p2p releases USDC to taker
User has fiat on Venmo. Done.
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      CLI / UI                            │
│  $ zecp2p offramp 0.5 ZEC to venmo @myusername          │
├─────────────────────────────────────────────────────────┤
│                   Coordinator (Rust)                     │
│  • Registers session with GlueContract                   │
│  • Initiates NEAR Intent with GlueContract as recipient  │
│  • Polls for USDC arrival                                │
│  • Triggers GlueContract to route to zk-p2p              │
│  • Monitors zk-p2p for fulfillment                       │
├──────────────────────┬──────────────────────────────────┤
│   NEAR Intents       │         zk-p2p (Base)            │
│   ZEC → USDC         │   USDC → Venmo                   │
│                      │                                   │
│   Shielded input     │   Escrow.createDeposit()         │
│   Solver network     │   Orchestrator (intent lifecycle) │
│   Bridge to Base     │   ZK proof verification           │
└──────────────────────┴──────────────────────────────────┘

           GlueContract (single deployment on Base)
           ─────────────────────────────────────────
           • Deployed once by developer, used by all users
           • Receives USDC from NEAR Intents
           • Routes to zk-p2p per session configuration
           • Tracks offramp state per session
```

## Why Two Steps?

ERC20 tokens do not trigger code on receipt. When NEAR Intents delivers USDC to a contract via `transfer()`, no callback fires. Therefore:

1. USDC arrives at GlueContract (balance updated, no code runs)
2. Keeper/coordinator must call GlueContract to route funds to zk-p2p

## Components

### 1. GlueContract (Solidity)

A single contract deployed once on Base. Receives USDC from NEAR Intents and routes it to zk-p2p. Shared by all users.

**Key Functions:**

| Function | Description |
|----------|-------------|
| `createSession(sessionId, user, payeeDetailsHash, minRate, expectedAmount)` | Register an offramp before NEAR Intent executes |
| `processOfframp(sessionId, zkp2pParams)` | Route received USDC to zk-p2p (called by keeper) |
| `rescue(sessionId)` | Return USDC to user if something fails (user only) |
| `withdrawFromZkp2p(sessionId)` | Withdraw from zk-p2p if no taker (user only) |

**Session State:**
- `user`: User's Base address (for rescue/withdraw)
- `payeeDetailsHash`: zk-p2p payee details hash for the Venmo account. Issued by the zk-p2p curator API (`POST /v2/makers/create`, `{processorName: "venmo", offchainId: <username>}`) as `hashedOnchainId`; the attestation witness matches it against the taker's Venmo proof, so it cannot be derived locally
- `minConversionRate`: Minimum acceptable rate
- `expectedAmount`: Expected USDC from NEAR Intent
- `depositId`: zk-p2p deposit ID (0 until processed)
- `fulfilled`: Whether session is complete

**Events:**
- `SessionCreated(sessionId, user, payeeDetailsHash)`
- `OfframpProcessed(sessionId, depositId, amount)`
- `SessionRescued(sessionId, user, amount)`

### 2. Coordinator Service (Rust)

Backend REST API that orchestrates the offramp flow.

**Responsibilities:**
- Register session with GlueContract
- Initiate NEAR Intent (ZEC → USDC to GlueContract)
- Poll for USDC arrival on Base
- Call `processOfframp()` when USDC arrives
- Monitor zk-p2p for intent fulfillment
- Report status to CLI/user

**State Machine:**
```
Created → NearIntentPending → UsdcReceived → Zkp2pDeposited → IntentSignaled → Fulfilled
                                    ↓                              ↓
                                 Failed                         Failed
```

**API Endpoints:**
- `POST /offramp` - Initiate new offramp
- `GET /offramp/:id` - Get offramp status
- `GET /quote` - Get quote for ZEC → USDC → Venmo

### 3. CLI

```
$ zecp2p offramp <amount> ZEC to venmo @<username>

Options:
  --taker <address>     Pre-arranged taker address (required for V0)
  --min-rate <rate>     Minimum USDC/ZEC rate to accept
  --timeout <seconds>   Timeout for NEAR settlement (default: 600)

$ zecp2p status <offramp-id>
```

## Detailed Flow

### Step 1: Initiate Offramp

1. User runs: `zecp2p offramp 0.5 ZEC to venmo @alice --taker 0xBob`
2. CLI calls coordinator `POST /offramp`
3. Coordinator:
   - Queries NEAR Intents for quote
   - Generates unique sessionId
   - Calls `GlueContract.createSession()` on Base
   - Returns sessionId and quote to user

### Step 2: Execute NEAR Intent

4. User approves quote
5. CLI initiates NEAR Intent:
   - Source: Shielded ZEC
   - Destination: USDC on Base
   - Recipient: GlueContract address
6. NEAR solver network executes swap
7. Coordinator polls for USDC arrival at GlueContract

### Step 3: Route to zk-p2p

8. When USDC arrives, coordinator calls `GlueContract.processOfframp()`
9. GlueContract approves USDC to zk-p2p Escrow
10. GlueContract calls `Escrow.createDeposit()` with session parameters
11. Returns depositId, status → Zkp2pDeposited

### Step 4: Taker Fulfills

12. Pre-arranged taker sees deposit on zk-p2p
13. Taker calls `Orchestrator.signalIntent()`
14. Taker sends Venmo payment to user (off-chain)
15. Taker generates ZK proof via PeerAuth (~30 seconds)
16. Taker calls `Orchestrator.fulfillIntent()` with proof
17. zk-p2p verifies proof and releases USDC to taker

### Step 5: Complete

18. Coordinator detects fulfillment event
19. CLI reports success with amounts and transaction hashes

## Failure Modes

| Failure | User ends up with | Recovery |
|---------|-------------------|----------|
| NEAR Intent times out | Original ZEC (refunded) | Automatic via NEAR |
| USDC arrives but processOfframp fails | USDC in GlueContract | Call `rescue()` |
| No taker signals intent | USDC in zk-p2p deposit | Call `withdrawFromZkp2p()` |
| Taker signals but doesn't pay | USDC (intent expires) | Automatic via zk-p2p |
| Taker pays but proof fails | USDC (intent expires) | Automatic via zk-p2p |

In all cases, user either gets their ZEC back, USDC, or Venmo payment. Never nothing.

## Contract Addresses (Base Mainnet)

| Contract | Address | Source |
|----------|---------|--------|
| USDC | `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913` | Circle |
| zk-p2p Escrow | TBD - fetch from [@zkp2p/contracts-v2](https://www.npmjs.com/package/@zkp2p/contracts-v2) | zk-p2p |
| zk-p2p Orchestrator | TBD - fetch from [@zkp2p/contracts-v2](https://www.npmjs.com/package/@zkp2p/contracts-v2) | zk-p2p |
| GlueContract | TBD - deployed by developer | zecp2p |

## Technical References

### zk-p2p

| Resource | URL |
|----------|-----|
| Contracts repo | https://github.com/zkp2p/zkp2p-contracts |
| npm package | https://www.npmjs.com/package/@zkp2p/contracts-v2 |
| IEscrow interface | https://github.com/zkp2p/zkp2p-contracts/blob/main/contracts/interfaces/IEscrow.sol |
| IOrchestrator interface | https://github.com/zkp2p/zkp2p-contracts/blob/main/contracts/interfaces/IOrchestrator.sol |

**Key zk-p2p Types:**

`CreateDepositParams`:
- `token`: ERC20 token (USDC)
- `amount`: Deposit amount
- `intentAmountRange`: Min/max per intent
- `delegate`: Optional manager address
- `intentGuardian`: Can extend intent expiry
- `retainOnEmpty`: Keep deposit open when drained
- `paymentMethods`: e.g., `[keccak256("venmo")]`
- `paymentMethodData`: Verifier-specific data including payeeId
- `currencies`: Accepted currencies with min conversion rates

`SignalIntentParams`:
- `escrow`, `depositId`, `amount`, `to`
- `paymentMethod`, `fiatCurrency`, `conversionRate`
- `gatingServiceSignature`, `signatureExpiration`
- `postIntentHook`, `data`

### NEAR Intents

| Resource | URL |
|----------|-----|
| Documentation | https://docs.near.org/chain-abstraction/intents/overview |
| 1Click API docs | https://docs.near-intents.org/near-intents/integration/distribution-channels/1click-api |
| API base URL | https://1click.chaindefuser.com/ |

**1Click API:**
- `POST /v0/quote` - Get quote with depositAddress for ZEC
- `GET /v0/status?depositAddress=<addr>` - Poll status (PENDING_DEPOSIT → KNOWN_DEPOSIT_TX → PROCESSING → SUCCESS)

### PeerAuth (ZK Proof Generation)

| Resource | URL |
|----------|-----|
| Extension | Chrome Web Store (search "PeerAuth") |
| Reclaim Protocol | https://www.reclaimprotocol.org/ |

## Gas Considerations

| Operation | Estimated Gas | Who Pays |
|-----------|---------------|----------|
| createSession() | ~100k | User or coordinator |
| processOfframp() | ~200k | Keeper/coordinator |
| signalIntent() | ~150k | Taker |
| fulfillIntent() | ~300k | Taker |

For V0, user needs Base ETH for gas. Future versions could use paymasters or deduct from USDC.

## V0 Scope

### In Scope

- [ ] GlueContract (Solidity, single deployment on Base)
- [ ] Coordinator service (Rust REST API)
- [ ] NEAR Intents integration (1Click API - full flow)
- [ ] zk-p2p Escrow.createDeposit() integration
- [ ] Status tracking (SQLite)
- [ ] CLI: `zecp2p offramp` and `zecp2p status`
- [ ] Keeper functionality (poll and trigger processOfframp)

### Out of Scope (V1+)

- Automatic taker matching (V0 requires pre-arranged taker)
- Gasless transactions
- On-ramp (Venmo → ZEC)
- Other fiat rails (Revolut, PayPal, etc.)
- Other source tokens (BTC, ETH, etc.)
- Privacy enhancements (time delays, amount splitting)
- Web UI

## V1 Vision: Offramp Marketplace

V1 introduces a marketplace for off-ramping, similar to how zk-p2p has on-ramping. Community participants can act as liquidity providers for faster off-ramps.

**Concept:**
- Makers (liquidity providers) maintain standing USDC positions ready to receive offramp requests
- Users send ZEC, which converts to USDC and immediately matches with available maker liquidity
- Eliminates waiting for a pre-arranged taker
- Competitive rates driven by market

**Open for exploration:**
- Should this be a new contract or integrate deeper with zk-p2p?
- How to incentivize makers to provide liquidity?
- Could takers become makers in a pooled system?
- Is there a better architecture than mirroring zk-p2p's model?

## Open Questions

1. **Gating service signature**: Does zk-p2p require a gating signature for signalIntent? If so, how does the taker obtain it?

2. **Payment method data format**: What exact format does `DepositPaymentMethodData` need for Venmo? Need to inspect existing deposits or ask zk-p2p team.

3. **Taker coordination**: For V0, how do user and taker coordinate? Out-of-band messaging? The taker needs to know the depositId and timing.

4. **Base ETH for gas**: User needs ETH on Base. Should we add a faucet, or require user to bridge ETH separately?

5. **Conversion rate validation**: How to ensure the taker uses a fair rate when signaling intent? The maker deposit specifies minConversionRate, but need to verify this is enforced.

6. **Maker deposit vs existing maker**: Is it faster to create a new zk-p2p maker deposit, or send USDC to an existing maker who can fulfill immediately? A second contract path could match incoming USDC with existing maker liquidity for faster settlement. This tradeoff (new deposit vs instant match) should be explored.

## FAQ / Implementation Decisions

### Project Structure

**Q: Should this be a Cargo workspace with separate crates or a single crate?**

A: Workspace is best. Separate crates for CLI, coordinator, and shared types.

**Q: Should Foundry (forge) be set up alongside Rust for the Solidity contracts?**

A: Yes. A `contracts/` directory with Foundry alongside the Rust workspace.

### Rust Dependencies

**Q: Which Ethereum library for interacting with Base?**

A: `alloy` (newer, recommended over ethers-rs).

**Q: Which SQLite crate for status tracking?**

A: `sqlx` (async, compile-time checked queries).

**Q: Which async runtime?**

A: No strong preference - use `tokio` as it's most popular and has best ecosystem support.

### Architecture

**Q: Should the coordinator be a REST API server or embedded library?**

A: Standalone REST API server. Treat the project like it's real - no placeholder logic, no "fix this later". It should be structured like a production project with all components ready to be deployed and trusted.

**Q: How to handle contract ABIs from @zkp2p/contracts-v2?**

A: Whatever is most robust. Fetch from GitHub sources and generate bindings, ensuring they stay in sync with deployed contracts.

**Q: What about the keeper daemon mentioned in the flow?**

A: The keeper daemon will be a 3rd party service monitoring the contract for events and forwarding them. The coordinator should expose the necessary endpoints/hooks for this.

**Q: Is GlueContract deployed per-offramp or once for the network?**

A: Single deployment. The developer deploys GlueContract once on Base, and all users share it. Sessions track per-user state.

### Configuration

**Q: How should RPC endpoints, contract addresses, and API keys be configured?**

A: TOML config file for public things (RPC endpoints, contract addresses), `.env` file for API keys and secrets.

### Scope

**Q: For NEAR Intents integration, full flow or just status polling?**

A: Full flow - quote, deposit address generation, and status polling. User should be able to complete the entire offramp from the CLI.

### Testing

**Q: Should tests use mocks or real services?**

A: Prefer real services when possible over mocks. Include a mix of unit tests (for business logic) and integration tests (against testnets/real APIs). Mocks only where absolutely necessary (e.g., rate limiting, cost constraints).

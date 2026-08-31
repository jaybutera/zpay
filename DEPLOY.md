# Deploying zecp2p to Base mainnet

How to stand this up from scratch, and exactly what it costs to fund.

zecp2p moves ZEC to a Venmo payout in two legs. The inbound leg swaps ZEC to
USDC on Base through NEAR Intents 1Click. The outbound leg parks that USDC in
zk-p2p's EscrowV2 and releases it to whoever proves they sent the matching
Venmo payment. `OfframpGlue` is the contract in the middle, and it is the only
contract this project deploys.

**Base mainnet (chain 8453) is the only chain the whole flow runs on.** Not a
preference. zk-p2p's Venmo payment verifier is deployed only there, and the
attestation enclave signs an EIP-712 domain bound to chain 8453 plus that
verifier's address. A proof minted for a payment cannot be replayed onto any
other chain, so no testnet can exercise the claim leg. Base Sepolia gets you as
far as `signalIntent` and no further; `scripts/testnet/` still does that.

## Prerequisites

| Tool | Why |
|---|---|
| [Foundry](https://getfoundry.sh) (`forge`, `cast`, `anvil`) | deploys, reads chain, runs the fork rehearsal |
| Rust stable | builds the coordinator, taker and CLI |
| Node >= 20 | the attestation client (`@zkp2p/zkp2p-attestation`) |
| Python 3 | the deploy scripts' JSON handling |

```bash
git clone --recurse-submodules git@github.com:jaybutera/zecp2p.git
cd zecp2p
cargo build --release
(cd contracts && forge build)
(cd scripts/proof && npm install)
```

## Configuration

Every address, key, RPC, chain id and service URL comes from `.env`, which is
gitignored along with every `.env.*` variant. Nothing is hardcoded in a deploy
script.

```bash
cp .env.example .env
$EDITOR .env
```

`.env.example` documents each variable. The three that need real values before
anything happens are `DEPLOYER_PRIVATE_KEY`, `COORDINATOR_PRIVATE_KEY` and,
on the taker's machine only, `TAKER_PRIVATE_KEY`.

The deployer and the keeper can be the same key, but splitting them is the
point: the owner key can go cold after step 02, because the owner can always
take the keeper role back and the keeper can never change the owner.

## The sequence

Each step is idempotent and re-runnable. Every step that can spend simulates by
default and needs an explicit `--broadcast` to send anything.

```bash
scripts/deploy/00_preflight.sh                    # read-only, spends nothing
scripts/deploy/01_deploy_contracts.sh             # simulate
scripts/deploy/01_deploy_contracts.sh --broadcast # deploy for real
scripts/deploy/02_configure_keeper.sh --broadcast # hand the keeper role over
scripts/deploy/03_write_config.sh                 # generate the config files
scripts/deploy/04_verify_near_leg.sh              # read-only, dry quotes only
scripts/deploy/05_rehearse_on_fork.sh             # local fork, spends nothing
scripts/deploy/07_status.sh                       # read-only, run any time
```

`scripts/deploy/06_prove_payment.sh` is the Venmo attestation leg. It runs on
demand, per payment, on the machine holding the Venmo session, not as part of
standing the system up.

### 00 — Preflight

Reads the chain and every external service and confirms all of them are what
the config says. It checks that USDC, EscrowV2, OrchestratorV3, the StakeVault
and the payment verifier all hold code; that OrchestratorV3 is registered with
EscrowV2; that venmo and USD are an accepted payment method and currency; that
the curator answers and rejects an unknown username; that the enclave's AWS
Nitro attestation document verifies to the AWS root; and that 1Click lists both
assets the swap moves between.

Run this before anything else and after any config change. It spends nothing.

One thing it papers over deliberately: `cast call` turns an RPC 429 into an
empty answer, which reads as a failed check when it is really rate limiting, so
each on-chain read retries three times before reporting a failure.

### 01 — Deploy OfframpGlue

```bash
scripts/deploy/01_deploy_contracts.sh --broadcast
```

Deploys the one contract this project owns, against the USDC and escrow named
in `.env`. The forge script refuses to run if `block.chainid` does not match
`EXPECTED_CHAIN_ID`, and refuses to deploy against an address with no code, so a
glue that would revert on every deposit never gets paid for.

If `GLUE_CONTRACT_ADDRESS` already names a contract whose `usdc()` and
`zkp2pEscrow()` match the config, the script reports it and exits without
deploying a second one. If it names a contract built against *different*
addresses, it stops rather than guess which one you meant. `--force` deploys a
fresh one regardless.

The address is written to `scripts/deploy/state/deployed.8453.env` and printed
for you to paste into `.env`.

Set `BASESCAN_API_KEY` to verify the source on Basescan in the same run.

### 02 — Configure the keeper

```bash
scripts/deploy/02_configure_keeper.sh --broadcast
```

The deployer is the keeper out of the constructor. This points the keeper role
at `COORDINATOR_PRIVATE_KEY`'s address instead, and reports whether that key
holds enough ETH to actually operate. If the keeper is already correct it sends
nothing.

### 03 — Generate the config files

```bash
scripts/deploy/03_write_config.sh
```

Writes `config.generated.toml` and `config.taker.generated.toml` from the
environment. Both hold addresses and URLs only; keys stay in `.env` and are read
from the process environment at run time. Both are gitignored, because they name
one specific deployment.

`--check` diffs what is on disk against the current environment instead of
overwriting, which is the thing to run in CI or before a restart.

### 04 — Verify the inbound NEAR leg

```bash
scripts/deploy/04_verify_near_leg.sh
```

Every call is a dry quote, which 1Click documents as simulating "without
generating a deposit address". Nothing is committed and no ZEC moves.

The check that matters is whether 1Click accepts the deployed glue as a delivery
recipient. Delivery is a plain ERC-20 transfer with no callback, and the API
denylists some destinations; a contract recipient is fine as a class, but only
the API can confirm this particular one. It also confirms the API rejects a
shielded refund address, which is what the coordinator's own validation assumes.

`--live` additionally mints one real deposit address. That still commits
nothing: the address simply expires if no ZEC arrives.

### 05 — Rehearse on a fork

```bash
scripts/deploy/05_rehearse_on_fork.sh
```

Forks Base mainnet into anvil, deploys a throwaway glue there, and drives the
*real* EscrowV2 and OrchestratorV3 bytecode with it. This is what proves the
`createDeposit` encoding matches the deployed contract, the deposit id
bookkeeping is right, and the payee hash lands on the deposit. It costs nothing
and touches no live chain.

`claim` mode additionally runs `signalIntent` and `fulfillIntent` with a real
enclave attestation, re-bound to the intent hash the fork itself produces. That
needs an attestation from `scripts/proof` and the Venmo cookie to re-bind it;
without them it stops before `fulfillIntent` rather than pretend.

### 06 — Prove a Venmo payment

```bash
scripts/deploy/06_prove_payment.sh --intent 0x<intentHash>
```

Run on the machine holding the Venmo session. It reads the intent's amount,
payee hash and on-chain signal timestamp off the orchestrator, prompts for the
cookie without echoing it, and asks the enclave to attest the payment.

The timestamp is not optional detail: `UnifiedPaymentVerifierV3` compares the
attested snapshot's timestamp against the intent stored on chain and reverts
with `UPV: Snapshot timestamp mismatch` if they differ. Building an attestation
from the wall clock produces a signature that verifies locally and then fails on
chain.

The cookie is encrypted client-side to a key whose Nitro attestation document is
verified to the AWS root before anything is sent, so the service operator cannot
read it outside the enclave. It is still as powerful as the raw cookie, and the
enclave enforces no age or replay limit on it, so it is never written to disk
and never logged.

### 07 — Status

```bash
scripts/deploy/07_status.sh
```

Read-only. Reports the glue's on-chain state, each operating key's balances
against what its role needs, the keeper's remaining runway in sessions at the
current gas price, and whether the coordinator and the three external services
are answering.

## Running it

```bash
ZECP2P_CONFIG=config.generated.toml \
  cargo run --release --bin zecp2p-coordinator

ZECP2P_TAKER_CONFIG=config.taker.generated.toml \
  cargo run --release --bin zecp2p-taker -- agent
```

Both read their keys from the environment (`COORDINATOR_PRIVATE_KEY`,
`TAKER_PRIVATE_KEY`), never from the config file.

---

# Funding requirements

What a real from-scratch mainnet deployment costs, itemized by who has to hold
what.

**Where the numbers come from.** Gas for `OfframpGlue` and its own functions was
measured on an anvil fork of Base mainnet at block 50712524, driving the real
deployed EscrowV2, by mining each transaction and reading `gasUsed` off the
receipt. Gas for `signalIntent`, `fulfillIntent` and `cancelIntent` was read off
real production transactions on Base mainnet against OrchestratorV3
`0x014025fDE093f8701d86e9f38e2C3a9b779cb5c7`, sampled over roughly 4,000 blocks
on 2026-08-31. Nothing below is extrapolated from a contract's size.

**Price assumptions**, all read live on 2026-08-31 and all of which you should
re-check before funding:

- ETH **$2,475.92**, ZEC **$851.21** (1Click's own token registry)
- Base gas price observed at **0.006 gwei**. That is unusually cheap. The dollar
  columns below use **0.05 gwei**, roughly eight times the observed price, and a
  second column at **0.2 gwei** as a headroom case. At 0.006 gwei every gas
  figure below costs about a tenth of the 0.05 gwei column.

## Measured gas

| Transaction | Gas | Source |
|---|---:|---|
| `OfframpGlue` deploy | 1,517,222 | fork receipt (`eth_estimateGas` on the CREATE: 1,497,322) |
| `setKeeper` | 28,498 | fork |
| `createSession` | 121,891 | fork |
| `processOfframp` (into real EscrowV2) | 501,459 | fork |
| `withdrawFromZkp2p` | 94,151 | fork estimate |
| `rescue` | 71,853 | fork |
| `approve` USDC to the StakeVault | 55,437 | fork |
| `depositStake` | 85,000 | fork |
| `signalIntent` | 877,070 | fork; mainnet production median 811,572, max 1,014,086 |
| `fulfillIntent` | 463,353 | mainnet production, max of 4 sampled (min 414,750) |
| `cancelIntent` | 228,482 | mainnet production, max of 5 sampled (min 196,033) |

`OfframpGlue` compiles to 6,669 bytes of runtime code and 7,051 bytes of
initcode, which is what puts the deploy at 1.5M gas.

## 1. Base ETH for the deploy — deployer key

One-time. `OfframpGlue` deploy plus one `setKeeper` is **1,545,720 gas**.

| Gas price | ETH | USD |
|---|---:|---:|
| 0.006 gwei (observed) | 0.0000093 | $0.02 |
| 0.05 gwei | 0.0000773 | $0.19 |
| 0.2 gwei | 0.0003091 | $0.77 |

**Fund the deployer with 0.005 ETH (~$12.38).** That is roughly sixteen times
the 0.2 gwei case, which buys room for a failed deploy, a re-deploy, and a gas
spike, and leaves change for `setKeeper` later. **Spent, not recoverable** —
though the overwhelming majority of it stays in the account and can be swept
back out afterwards; only the ~$0.19 of actual gas is consumed.

## 2. Base ETH for keeper operating gas — coordinator key

Per completed session the keeper sends `createSession` and `processOfframp`:
**623,350 gas**. A session that ends with the user withdrawing adds
`withdrawFromZkp2p` at 94,151 gas; one that is rescued before deposit adds
`rescue` at 71,853. Budget the withdraw case at **717,501 gas per session**.

| Gas price | Per session | 100 sessions |
|---|---:|---:|
| 0.05 gwei | 0.0000359 ETH / $0.09 | 0.00359 ETH / $8.88 |
| 0.2 gwei | 0.0001435 ETH / $0.36 | 0.01435 ETH / $35.53 |

**Fund the keeper with 0.02 ETH (~$49.52).** That covers about 140 sessions at
0.2 gwei, or 1,400 at 0.05 gwei. **Spent as it is used**, but the unspent
balance is recoverable: it is a plain EOA.

The keeper needs no USDC. The USDC it moves belongs to the glue contract, not
to the keeper key.

Watch this one. `07_status.sh` reports the remaining runway in sessions, and
warns below ten. A keeper that runs out of gas mid-session leaves USDC sitting
on the glue with nobody to deposit it.

## 3. USDC for the maker deposit — per intent, comes from the user

This is not a treasury item. The maker deposit *is* the swapped ZEC: 1Click
delivers USDC to the glue, and `processOfframp` deposits whatever the glue's
balance is. Nobody has to pre-fund it.

What matters is the size. 1Click's floor is **52,000 zatoshi** (0.00052 ZEC,
about $0.44), rejected below that with an explicit floor in the error. Fees
measured live at four sizes, ZEC to USDC on Base, `EXACT_INPUT`, 50 bps
slippage:

| ZEC in | USD in | USDC out | Loss |
|---|---:|---:|---:|
| 0.00052 | $0.44 | 0.436965 | 0.84% |
| 0.01 | $8.47 | 8.446263 | 0.33% |
| 0.05 | $42.37 | 42.283652 | 0.21% |
| 0.12 | $101.68 | 101.584043 | 0.11% |

The spread tightens with size because a fixed Base-side `withdrawFee` dominates
a small trade. Every quote also carries a 10 bps `appFee` to a NEAR account this
project does not control, attached server-side without being asked for; NEAR's
docs describe an extra surcharge for callers without an API key, so getting one
is worth doing before repeated runs.

**Recoverable.** If no taker fulfils the intent, `withdrawFromZkp2p` returns the
USDC to the user. If the swap fails before deposit, `rescue` does. If the ZEC
never arrives, 1Click refunds to `ZEC_REFUND_ADDRESS` — minus a `refundFee` of
47,000 zatoshi (~$0.40), which at the 52,000-zatoshi floor consumes nearly the
whole principal. That is the reason to test the refund path at the floor and
nowhere else.

## 4. USDC for the taker stake — taker key, per intent

OrchestratorV3 routes `signalIntent` through a lifecycle hook that locks stake
in the StakeVault **equal to the intent amount**. A taker that has not staked
gets `InsufficientFreeStake`.

So a taker claiming a $100 intent ties up **$100 of USDC as stake** and needs
**$100 of real dollars in their Venmo balance** to send the payment. Both at
once, per open intent. `TAKER_MAX_INTENT_AMOUNT` in `.env` is a real exposure
limit, not a preference.

**Fund the taker with USDC equal to the largest intent it should take, times
the number of intents it should hold open at once.** For the default
`max_intent_amount` of 100 USDC and one intent at a time: **100 USDC (~$100)**.

**Recoverable.** The stake unlocks when the intent is fulfilled or cancelled,
and `fulfillIntent` also pays the taker the escrowed USDC. The Venmo dollars are
spent and come back as that USDC — that is the whole trade. What is genuinely at
risk is the gap: a taker who sends the Venmo payment and then cannot produce an
attestation has paid real money and holds an unfulfilled intent. `cancelIntent`
releases the stake and the maker's USDC, and leaves the taker to settle the
Venmo side directly.

## 5. Base ETH for taker gas

Per full claim: `approve` + `depositStake` + `signalIntent` + `fulfillIntent` =
**1,480,860 gas**. The `approve` and `depositStake` are only needed when free
stake runs short, so a warm taker pays 1,340,423.

| Gas price | Per claim | 50 claims |
|---|---:|---:|
| 0.05 gwei | 0.0000740 ETH / $0.18 | 0.0037 ETH / $9.16 |
| 0.2 gwei | 0.0002962 ETH / $0.73 | 0.0148 ETH / $36.66 |

**Fund the taker with 0.01 ETH (~$24.76).** Covers about 33 claims at 0.2 gwei.
**Spent as used**, unspent balance recoverable.

## 6. Real ZEC for the inbound test leg

The cheapest honest end-to-end test is one minimum swap: **52,000 zatoshi
(0.00052 ZEC, ~$0.44)**, plus the Zcash network fee to send it, call it
**$0.46**.

Do this twice. The first run should deliver to a plain EOA you control, so a
failure is unambiguously a 1Click or client problem rather than a glue
integration problem. The second delivers to the glue, which is the first moment
the designed path runs end to end. Budget a retry.

**About $1.50 of ZEC** covers both runs plus one retry. **Mostly spent**: about
0.8% is lost to fees at that size and the rest arrives as USDC, but at $0.44 the
distinction is academic.

There is no way to make this leg free. NEAR publishes no testnet for 1Click and
has said it does not plan to, and there is no TAZ asset in the registry. The
Base side can run on Sepolia, but then 1Click cannot deliver to it. The two
halves cannot both be fake.

## 7. Real dollars on Venmo for the outbound test leg

Whatever the test intent is worth, in the taker's actual Venmo balance. At the
$1 scale the earlier runs used, **$1**. This is the same money as the taker
stake in item 4, seen from the other side.

## Bottom line

To stand up a working mainnet deployment and run one end-to-end test at the
$1 scale, with a 100 USDC taker limit:

| Item | Amount | Where | USD | Recoverable? |
|---|---|---|---:|---|
| Deploy gas | 0.005 ETH | deployer key | $12.38 | unspent balance yes; ~$0.19 consumed |
| Keeper operating gas | 0.02 ETH | coordinator key | $49.52 | unspent balance yes |
| Taker gas | 0.01 ETH | taker key | $24.76 | unspent balance yes |
| Taker stake | 100 USDC | taker key | $100.00 | yes, unlocks on fulfil or cancel |
| Test ZEC | 0.0018 ZEC | any Zcash wallet | $1.53 | mostly spent (fees ~0.8%) |
| Venmo test payment | $1 | taker's Venmo | $1.00 | returns as escrowed USDC |
| **Total to have on hand** | | | **$189.19** | **~$185 recoverable** |

Actual gas burned across the whole exercise, at 0.05 gwei, is under **$2**. The
rest is float: balances that sit in accounts you control and can sweep back.

Two figures to re-check before funding, because both move: the ETH price and the
Base gas price. At the 0.006 gwei observed on 2026-08-31 the gas items are
roughly a tenth of the table above; the ETH balances are sized for headroom, not
for that day's price.

### What is *not* in the table

- **A 1Click API key.** Free, and it drops a surcharge NEAR documents for
  callers without one. Worth getting before repeated testing.
- **A paid RPC endpoint.** The public Base RPC rate limits, and the keeper polls
  every 15 seconds. Not required to deploy; required to operate reliably.
- **`BASESCAN_API_KEY`.** Free, and only affects source verification.
- **Registering the payee with the zk-p2p curator.** Free. A `POST` to
  `/v2/makers/create` returns the `hashedOnchainId` that becomes `payeeDetails`
  on chain. There is no local formula for that hash, so this step is mandatory
  but costs nothing.

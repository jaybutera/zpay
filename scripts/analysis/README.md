# Does a ~$5 sell clear on zk-p2p?

`market_fill_rates.sh` answers that from Base mainnet logs. It is read-only: no
deposit, no transaction, no key, no `createDeposit`.

```
scripts/analysis/market_fill_rates.sh                  # ~6 days
scripts/analysis/market_fill_rates.sh --blocks 500000  # ~12 days
```

## Reading the events correctly

An intent's life is three orchestrator events, and one of them is a trap:

| Event | Meaning |
|---|---|
| `IntentSignaled(intentHash, escrow, depositId, ...)` | a taker claims part of a deposit; `amount` and the signal time are in data |
| `IntentFulfilled(intentHash, ...)` | the payment proved out and USDC moved: a fill |
| `IntentPruned(intentHash)` | the intent slot was released |

`IntentPruned` is not a failure marker. It fires on fulfilled intents too, in
the same transaction as the fulfilment, emitted just before it. Over two
independent windows every fulfilled intent was also pruned: 1,780 of 1,780 in
the 11.6-day scan and 820 of 820 in a separate 5.2-day one. Treating prunes as
misses would report a market that almost never works.

So the fill rate here is fulfilled over signaled. EscrowV2 confirms that split
with events that do separate the outcomes, and the script cross-checks against
them on every run:

| Escrow event | Corresponds to |
|---|---|
| `FundsLocked` | signaled |
| `FundsUnlockedAndTransferred` | fulfilled |
| `FundsUnlocked` | released without a fill |

`FundsUnlocked` had zero overlap with the fulfilled set, which is what makes
the fills/misses split trustworthy rather than assumed. Transferred slightly
exceeds fulfilled only because intents signaled before the window opened still
settle inside it; the run reports that as spillover.

Every topic hash is re-derived by the shell wrapper with `cast keccak` before
the scan starts, and a mismatch aborts the run.

## One address is half the market

`0xa4152975230b5dc505a96cb24bde2a15a3678e8e` signaled 2,174 of 4,164 intents
(52%) in the 11.6-day window. 506 of its intents were for exactly $2.00, and it
filled 21 of its 633 intents at or under $10.

That single account is what makes the blended `$2-5` bucket read 5%. It says
nothing about whether someone else's $5 sell clears, so the script reports the
market again with the dominant signaler excluded whenever one address exceeds
20% of intents. For a fresh account, the excluding-it numbers are the ones to
plan against.

## What the 11.6-day scan found

Window 50,215,850 to 50,715,850, ending 2026-09-01 00:04 UTC. Excluding the
dominant signaler:

| Bucket | n | fill rate | median | p90 |
|---|---|---|---|---|
| $0-2 | 149 | 40.3% | 3.1m | 27.6m |
| $2-5 | 84 | 34.5% | 2.8m | 23.8m |
| $5-10 | 123 | 56.1% | 2.8m | 18.9m |
| $25-100 | 453 | 63.4% | 2.1m | 7.5m |
| $100-500 | 596 | 68.8% | 2.3m | 8.0m |

Narrowed to the band that actually matters, $4.00 to $6.00: 35 of 68 filled,
51%, median 2.5 minutes, slowest 22 minutes, spread across 53 distinct
signalers and 33 distinct deposits. Small sells clear, at roughly the market's
overall rate, in minutes.

An unfilled intent is not a loss. It releases its slot and the deposit stays;
the cost of a miss is the wait and the gas, not the principal.

## Window and RPC

The public Base RPC caps `eth_getLogs` at 10,000 blocks per call and
rate-limits, so the scan pages the range. It also answers Python's default
`urllib` User-Agent with a flat HTTP 403, which is why the client sends a plain
one; that is not rate limiting and no amount of retrying clears it.

11.6 days cost 360 calls. An archive RPC (Alchemy, QuickNode, Ankr) lifts the
range cap and would let this scan months, which matters most for the small
buckets: they are the thinnest here and the least certain. The measured window
is also recent, so it reflects current taker appetite rather than a long-run
average.

These are onramp intents against existing deposits. Our offramp is the mirror
side, so this measures taker appetite for claiming a deposit, which is the
quantity that decides whether our deposit gets taken, though not an identical
market.

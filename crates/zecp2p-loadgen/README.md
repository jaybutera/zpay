# zecp2p-loadgen

A traffic and soak harness for the v2 escrow coordinator. It drives many orders
through the whole protocol at once so the rail gets stressed, throughput is
measurable, and the paths that only break under volume have somewhere to break.

**Testnet only.** Everything it talks to is a loopback listener the process owns,
the network is pinned to `test`, and `Harness::build` refuses anything else. No
flag points it at a real node, a real attestor, the production hub, or a stored
Venmo session.

## Run it

```sh
# One order, end to end. Start here.
cargo run -p zecp2p-loadgen -- --count 1

# Volume, with the payment slot contending.
cargo run -p zecp2p-loadgen -- --count 200 --concurrency 8 --sweep-timeout 300

# A soak run over every path.
cargo run -p zecp2p-loadgen -- --duration 3600 --concurrency 8 \
  --mix release=8,refund=1,never_sign=1 --jsonl run.jsonl

# The failure injections.
cargo run -p zecp2p-loadgen -- --count 20 --false-paid-in 5      # the 2026-09-05 shape
cargo run -p zecp2p-loadgen -- --count 20 --attest-failure-in 4  # a prover-config gap
cargo run -p zecp2p-loadgen -- --count 20 --pay-failure-in 4     # an ambiguous pay failure
```

`cargo test -p zecp2p-loadgen` holds the harness itself to what it claims.

## What is real

The coordinator, all of it: the HTTP surface every step goes through, the order
store and journal, the limits, the funding decision, `verify_pre_signature`, the
attestor's nonce and outcome scalar, the release assembly, and the transaction
that gets broadcast. A release this harness produces is one the escrow crate
parses and whose signatures check out.

What is modelled is the money on both sides. The chain confirms an output as
soon as it is told about one, and the fiat leg is `ModelRail`, which reports
payments nobody made. That is the only way to run this at volume; the
alternative is real ZEC into real escrows and real dollars out of one Venmo
account.

## The address question

Nothing needs pre-generating. The escrow address is derived from the user's key
(`escrow_address(u_pub, l_pub, refund_height, amount_zat, network)`), so a fresh
keypair per order gives a fresh address for free. `every_order_derives_its_own_escrow_address`
holds it, and the report prints distinct addresses against order count on every
run.

## What concurrency measures

Not the payment rate. The coordinator holds **one global payment slot** on
purpose: two payments in flight are two feed entries of the same amount to the
same handle, and the feed search refuses to guess between them, after both have
left. Raising `--concurrency` does not raise payments in flight, and a run
reporting that it did would be reporting a bug.

What it raises is pressure on everything around the slot: the store's locks, the
funding scan, the announcement path, and the queue. At concurrency 8 with a
100 ms modelled payment, 40 orders took 135 s wall, p50 23.6 s, p99 87.9 s; the
latency is almost entirely queueing for the slot.

## Amounts and handles vary on purpose

Two open orders for one handle at the same cents are refused by
`put_unless_in_flight`, for the same feed-ambiguity reason. A generator sending
identical orders would measure that refusal and nothing else, so each iteration
draws its own amount from `--amount-min`/`--amount-max` and the handle pool
rotates.

## The chain-tip lease

There is one chain. The `refund` and `never_sign` paths reach `T` by moving its
tip, which every other open order also sees. So the tip is leased: ordinary
orders share a read guard, time-travelling ones take the write guard, and the
tip is put back before that guard is released. Without it a mixed run reports
failures against a coordinator that is behaving correctly, which is what the
first mixed run here did.

## What the report says

Throughput and latency percentiles, the outcome split, node calls per order, and
four invariants checked outright:

- at most one payment in flight
- every order got its own escrow address
- every release was backed by dollars that really left
- no escrow released more than once

The third is the one to watch. A release hands the user's ZEC to the LP, and the
only thing justifying it is dollars having reached the payee; the coordinator
cannot verify that, so the harness keeps the ledger it has no access to.

## Findings from the first runs

**A lying rail drains escrows, and nothing downstream notices.** With
`--false-paid-in 4`, 12 orders released against 9 payments that really left:
three escrows released with no money behind them. The coordinator is working as
designed here, which is the point. Nothing between the rail's return value and
the broadcast re-checks that the dollars arrived.

**One ambiguous pay failure stops all trading.** With `--pay-failure-in 3`, a
single error after the journal claim left that line open, and the global slot
was never released; the remaining five orders sat at `locked` until the run gave
up. Refusing to pay when money may have left is correct. The costs are that
throughput goes to zero until an operator resolves the line, and that the
futile polling cost 7,984 `getblockchaininfo` calls, about 1,000 node calls per
order, against a slot that was never going to free.

**An attestation failure recovers on its own.** With `--attest-failure-in 3`,
all 8 orders still released: the coordinator retried on the next sweep, 11
attest calls for 8 orders. The prover-config gap is survivable where the
ambiguous pay failure is not.

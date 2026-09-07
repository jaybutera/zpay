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

# And the faults that come from outside the process, as windows in the run.
cargo run -p zecp2p-loadgen -- --count 300 --node-outage-at 30 --node-outage-for 25
cargo run -p zecp2p-loadgen -- --count 300 --node-stall-ms 200
cargo run -p zecp2p-loadgen -- --count 20 --reject-broadcasts-at 5 --reject-broadcasts-for 10
cargo run -p zecp2p-loadgen -- --count 20 --attestor-refuses-at 5 --attestor-refuses-for 10
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

The sequence's period is every ten-thousandth of a ZEC the range holds, forced
odd so the handle rotation cannot divide it: 8,004 orders for the default range
and four handles. That is not unlimited. Orders collide on the *cents* the
coordinator quotes, and a span of `s` ZEC at rate `r` can only express
`s * r * 100` distinct cents - 805 for 0.05-0.25 at $40.25. Orders stay open for
the refund window on the `never_fund` path and indefinitely on a
`NeedsOperator` line, so a soak meaning to hold more open orders than
`handles * 805` should widen the range or name more `--handles`; otherwise it
will report refusals that are the harness's own.

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

The fourth is counted at the chain, not in the order records. An order carries
one `release_txid` however many times its escrow was really spent, so
deduplicating those cannot fail for the reason the invariant names. The fake
node instead keeps a spent set the way a real one does: it refuses a second
transaction spending an output it has already seen spent, and the report
compares the spends it accepted against the orders that released or refunded.

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

**A node that will not relay strands the escrow; an attestor that will not sign
does not.** Two runs of 6 orders, each with a 3 second window of the fault.
With `--reject-broadcasts-at 1 --reject-broadcasts-for 3`, all 6 payments left
and 5 escrows released: the one whose release fell in the window ended `failed`
with the dollars gone, and nothing re-attempted it after the node came back -
the same dead end the node-outage run found below. With
`--attestor-refuses-at 1 --attestor-refuses-for 3` all 6 released, at the cost
of 33 attest calls for 6 orders: the coordinator kept asking, and got an answer
once the enclave came back. The difference is where the failure falls. Before
the release is assembled it is a retry; after the dollars have gone and the
transaction exists, it needs a human.

## The stuck slot is invisible to monitoring

Following the ambiguous pay failure through the coordinator: on a `pay` error
after the journal claim, `driver.rs` writes the line as `NeedsOperator` with a
note saying the payment may or may not have left, and fails the order. That is
the right call, and `slot.rs` counts `NeedsOperator` as holding the slot, so
nothing else pays until a human reads the Venmo feed and clears it.

The gap is not the behaviour, it is the visibility. `GET /health` returns a
static `{"ok": true}`, and nothing else exports the journal's state, so a
coordinator with a stuck slot reports healthy while trading is completely
halted. The only signal is an `info`-level "waiting for the payment slot" line
repeating once per sweep per open order.

What a run with `--pay-failure-in 3` measured: one stuck line, five orders
queued behind it until the run's own timeout, zero throughput for the rest of
the run, and 7,984 `getblockchaininfo` calls spent asking a question whose
answer could not change.

A `/health` that reported the journal's open lines, or an operator alert on the
first `NeedsOperator` write, would turn a silent halt into a page. That is a
coordinator change and is deliberately not made here; the harness's job was to
find it.

## What grows, and what does not

Orders are never evicted, and that is deliberate: an order the coordinator
forgets is an escrow whose release nobody can assemble, leaving the user only
the refund at `T`. So a long-lived deployment accumulates them, and two things
grow with the total rather than with what is open.

**The state directory.** One JSON file per order, ~2.9 KB measured, written
under the store lock on every stage change. 2,000 orders is about 5.8 MB in
2,000 files, and the whole directory is read back at startup to rebuild the
store.

**The store scans.** `awaiting_count`, `awaiting_for_handle`,
`put_unless_in_flight` and `open_orders` each walk every order ever created,
under one mutex. Opening an order does three of those walks.

Neither is urgent. Across 2,000 orders the `open` step's p50 moved from 0 ms to
1 ms and its p99 from 8 ms to 11 ms, and the driver's sweep already filters to
`open_orders()` before spawning, so per-sweep work is bounded by what is open
rather than by the total. The measured latency growth over that run - p50 2,506
to 3,219 ms, p99 4,808 to 8,040 ms - is queueing for the payment slot, not the
scans.

What this does mean is that the cost is linear in lifetime order count, so it is
worth re-measuring before a deployment expects to hold tens of thousands.

## The open-order cap refuses cleanly

4,000 orders that never fund, against `max_open_orders = 512`: exactly 512
opened and 3,488 were refused with a 503 and a message naming the reason.
Unfunded orders stay open, so they accumulate against the cap; the refusal is
the intended behaviour under overload and it is exact.

## A node outage mid-trade

`--node-outage-at 30 --node-outage-for 25` over 300 orders, with the provider
failing every RPC for 25 seconds in the middle. 917 calls were refused. What the
run showed:

**Nothing unsafe happened.** 90 payments left, 89 escrows released, and both
money invariants held: no release without dollars behind it, and no escrow
released twice. Orders that could not be quoted were refused with a 503 and
never opened, so no key was drawn and no escrow existed to strand - 99 orders
opened and got 99 distinct addresses.

**One order landed in the state that needs a human.** The dollars went, and the
node disappeared before the release could broadcast:

> the dollars were sent and the release did not broadcast: chain error: the node
> is unreachable: getblockchaininfo: rate limit exceeded (code -32005). The
> release is still valid and is now racing the refund at block 3471852.

The message is exactly right, and `driver.rs` says so at the site: this is the
one state that always needs a human. Worth being explicit about what follows
from it, though, because the soak makes it concrete.

`order.fail` writes `Failed`, which is not open, so `advance` returns early on
every later sweep. `still_owes_a_refund_check` is false because a payment was
recorded. So **the release is never re-attempted, even once the node comes
back.** The escrow holds a valid release the LP has already paid for, and
nothing in the coordinator will broadcast it; the LP's exposure ends only when
an operator sends it by hand, or at `T` when the user refunds and the LP eats
the loss (spec 4.5).

A single retry of `broadcast_release` for an order that is `Failed` with a
recorded payment and no `release_txid` would close most of this window, since
the failure it recovers from is usually a provider blip of seconds. That is a
coordinator change and is not made here.

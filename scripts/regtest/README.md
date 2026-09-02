# A local regtest node, and why the e2e run uses one

The acceptance criteria need a funded escrow. Getting one on testnet needs TAZ,
and there is none to be had: `faucet.zecpages.com`, `zecfaucet.com`,
`faucet.zcash.garden`, `testnet.zcashfaucet.info` and `faucet.zec.rocks` were
all tried on 2026-09-02. Two do not resolve, two time out, and `zecfaucet.com`
serves its UI over 443 while its API backend on port 2653 refuses connections -
so the faucet is down, not blocked by anything here.

CPU-mining testnet was the next option and is worse than it looks: this box is
at 92% disk with 80 GB free, a testnet sync is tens of gigabytes, coinbase needs
100 confirmations, and other agents share the machine.

Regtest solves it in a minute. Blocks are mined on demand through the `generate`
RPC - no proof-of-work grinding, no sync, no peers, no faucet.

**The activation heights are the whole configuration.** A default Regtest node
runs Canopy, where ZIP 225 v5 transactions do not exist: zebrad rejects every
transaction this repo builds at parse, with `v5 transaction must have NU5 or
later consensus branch ID`. An earlier version of this file claimed regtest
shares ZIP 244 sighashes with mainnet; under Canopy it does not, and that claim
was wrong (round 6 finding R6-1).

With `[network.testnet_parameters.activation_heights]` setting NU5 through NU6.3
to height 1, the node reports `chaintip: 37a5165b` - the same consensus branch
id as mainnet - and the same v5 transaction parses, failing only on its missing
input. That is the configuration in `zebrad.toml.example`.

Two quirks worth recording, because both cost time:

- `extend_funding_stream_addresses_as_required = true` is needed. Without it any
  custom activation height panics zebrad at startup: the funding-stream check
  wants 52 addresses for the height range and the defaults supply 51.
- The parameters live under `testnet_parameters` even when `network = "Regtest"`.
  Setting `network = "Testnet"` instead gets the activation heights but no
  genesis block, and `generate` then answers "Zebra's state is empty".

## Running it

```sh
zebrad -c zebrad.toml start                     # RPC on 127.0.0.1:18232
curl -s -X POST http://127.0.0.1:18232 \
  -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"1.0","id":"x","method":"generate","params":[110]}'
```

110 blocks puts the block-1 coinbase past its 100-confirmation maturity, so
there is spendable coin. The miner address in `zebrad.toml.example` is
`tmVHejhMFq979Z7oRwseWMW7snYoQsj22yn`, whose key is `[0x5e; 32]` - printed by
`cargo run -p zecp2p-escrow --example miner_addr`. It is in the repo on purpose:
it holds regtest coin, which is worth nothing anywhere.

## What regtest does and does not establish

It establishes everything about *spending* the escrow: the funded lock, the
2-of-2 release, the CLTV refund at `T`, and criterion 12's mempool rejection of
a fabricated `s` against a real funded outpoint.

It does not establish behaviour under a live network's timing - reorgs,
propagation, fee pressure - and it is not the acceptance run. Spec section 10
asks for mainnet, and the testnet run stays the step before it. Both need coin
this host does not have.

One difference to keep in mind: regtest activates Canopy at height 1 and
reports branch id `e9ff75a6`, where mainnet is on NU6.3 (`37a5165b`). Nothing in
this repo hard-codes a branch - it is read from the node per spec 4.3 - and the
regtest run exercises that path rather than bypassing it.

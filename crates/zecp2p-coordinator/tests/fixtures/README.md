# 1Click response fixtures

Responses recorded from a real mainnet ZEC to USDC swap through 1Click on
2026-08-31, kept so the deserializer and `scripts/dryrun/mock_near.py` are
pinned to the shape the live service actually sends rather than to the shape we
assumed it sends.

**The identifiers in these files are stand-ins, and new recordings must be
scrubbed the same way before they are committed.** The originals tied a real ZEC
deposit address and its refund address to a real Base EOA, along with amounts,
timings and correlation ids. That is a linkage between a Zcash address and an
Ethereum address, in a repository about moving value between the two, and it is
worth nothing to keep. It was NEW-6 in the 2026-08-31 re-audit.

Replaced in every file here:

| Field | Replaced with |
|---|---|
| `depositAddress` | a synthetic t-addr with a valid base58check |
| `refundTo` | a second synthetic t-addr |
| `recipient` (the Base EOA) | `0x0000…f1c7` |
| `originChainTxHashes[].hash` | all-ones |
| `destinationChainTxHashes[].hash` | all-twos |
| `nearTxHashes[]`, `intentHashes[]` | repeated-digit stand-ins |
| `signature` (1Click's quote signature) | a repeated-digit stand-in |
| `correlationId` | fixed UUIDs, one per response |
| `appFees[].recipient` | zeroes |

What the tests actually assert on is structural: field names, the nesting under
`swapDetails`, chain hashes being arrays of `{hash, explorerUrl}` objects rather
than bare strings, nulls where a stage has no value yet, and the amounts. None of
that depends on the identifiers being anyone's.

Amounts and timestamps are the real ones. They carry no linkage on their own and
the tests compare against them.

# ZEC-native escrow: 2-of-2 + CLTV with adaptor-signature release

Status: approved design, 2026-09-02. Nothing here is built. This document is
the build spec; an implementer should not need the design conversation.

## 1. What this replaces and why

Today's offramp is: shielded ZEC -> 1Click swap to Base USDC -> zk-p2p
EscrowV2 deposit -> our taker pays Venmo -> zk-p2p's Nitro enclave attests the
payment -> `fulfillIntent` releases the USDC. The user pays 1Click's fee, waits
for the swap, and is subject to zk-p2p's $30 de facto floor on outside fills.

The native design removes the USDC leg. The user locks ZEC on Zcash in a
transparent P2SH escrow whose two signers are the user and the LP. The LP pays
Venmo. The LP obtains the same zk-p2p enclave attestation it obtains today and
presents it to an attestor service, which signs an outcome. That signature is
the scalar that completes a signature the user handed over at lock time. The LP
broadcasts the release. If the LP never proves payment, the user reclaims the
ZEC after an absolute block height with no one's cooperation.

Properties the design must keep, in priority order:

1. **Timeout refund to the user needs nobody.** After height `T` the user's
   key alone spends the escrow.
2. **The user signs nothing after funding.** A user who has received dollars
   cannot grief the LP by withholding a signature.
3. **The attestor holds no escrow-specific secret and no key over the funds.**
   It signs statements. Its refusal or outage means the LP cannot claim; the
   user still refunds.
4. **The on-chain release is an ordinary 2-of-2 spend.** No hashlock or oracle
   key is visible.

What the design does not achieve, stated plainly: an attestor that signs a
false "paid" outcome, in collusion with the LP, takes the user's ZEC. With two
signers and no post-hoc user veto this cannot be removed; it is the same power
zk-p2p's enclave has over an EscrowV2 depositor today. Section 8 says how it is
constrained.

## 2. Parties and roles

| Party | Holds | Does |
|---|---|---|
| User | ephemeral secp256k1 key `u` per escrow; ZEC | Funds escrow, hands LP an adaptor pre-signature, refunds after `T` if unpaid |
| LP | secp256k1 key `l`; Venmo balance; zebrad | Watches escrow, pays Venmo, obtains enclave attestation, completes and broadcasts release |
| Attestor | long-lived secp256k1 key `d` (pubkey `P`), per-event nonce `k` | Announces `R` per escrow, verifies the zk-p2p attestation, signs the outcome |
| zk-p2p enclave | signer `0xe078d93bfdd87a8c5c5cca5905dcba0dd7a1f0bd` | Replays Venmo feed, signs `PaymentAttestation(intentHash, releaseAmount, dataHash)` |

The LP and the attestor may be operated by the same organisation in Phase 1.
That collapses property 3 into "trust the operator" until Phase 7 (Nitro).

## 3. Parameters

| Name | Value | Notes |
|---|---|---|
| Block time | 75 s mainnet | NU7 proposes 25 s; all heights below are derived from `BLOCK_SECONDS`, not hard-coded |
| `REFUND_DELAY` | 1152 blocks (24 h) | `T = lock_height + REFUND_DELAY` |
| `PAY_DEADLINE` | `T - 60` blocks | LP must not send Venmo at or after this height |
| `BROADCAST_DEADLINE` | `T - 40` blocks | Release must be broadcast by here |
| Confirmation depth | see section 7 | Before LP pays |
| Reorg finality | 100 blocks | zcashd and zebrad refuse deeper reorgs |
| Fee | ZIP 317, 5000 zat per logical action, 2 grace actions | A 1-in 1-out or 1-in 2-out transparent spend is 10000 zat |
| Release tx `nExpiryHeight` | 0 | No expiry; see section 4.5 |
| Refund tx `nExpiryHeight` | 0 | |
| Attestation service | `https://attestation-service.zkp2p.xyz` | PCR8 pin `41a4ae0b9b96752cab5addb7d22689b3070e564e29f90a54316fa33fa38ea51387a6e887ea4f5a4b0cc34f69cea3f40e` |
| Enclave signer | `0xe078d93bfdd87a8c5c5cca5905dcba0dd7a1f0bd` | Also read from the attestation document's `expectedSigner`; both must match |
| Enclave EIP-712 domain | chainId 8453, verifyingContract `0xC6F4a193576C60892a47e111Bb5706c30162502B` | Domain constants only; nothing is submitted to Base |
| Minimum escrow | 0.001 ZEC above fees | Dust and fee floor |

## 4. Transactions

### 4.1 Redeem script

```
OP_IF
    OP_2 <u_pub> <l_pub> OP_2 OP_CHECKMULTISIG
OP_ELSE
    <T> OP_CHECKLOCKTIMEVERIFY OP_DROP
    <u_pub> OP_CHECKSIG
OP_ENDIF
```

- Both pubkeys compressed (33 bytes).
- `<T>` is a minimally encoded script number (CLTV requires it; use 3 or 4
  bytes for mainnet heights).
- Order in CHECKMULTISIG is `u_pub` then `l_pub`; signatures in the scriptSig
  must be in the same order.
- Zcash script is Bitcoin script circa 2015: P2SH and CLTV are enforced
  unconditionally, CSV does not exist, OP_CAT is disabled, no SegWit or
  Taproot. `nLockTime` compares against block height, not median time past.

scriptPubKey: `OP_HASH160 <hash160(redeemScript)> OP_EQUAL`, address prefix
`t3`.

### 4.2 Funding transaction

Built and broadcast by the user's client. A v5 transaction spending from the
user's shielded pool (Orchard or Ironwood; librustzcash support for Ironwood
outputs must be confirmed in Phase 0) with one transparent output to the P2SH
address for `amount_zat`. Any change stays shielded.

Because ZIP 244 txids do not commit to signatures, the client computes the
funding txid before broadcast. The escrow outpoint is therefore known when the
pre-signature is produced.

### 4.3 Release transaction

Built by the LP, signed by both parties, broadcast by the LP.

- Version 5, `consensusBranchId` = current mainnet branch (read from zebrad
  `getblockchaininfo`, never hard-coded; NU6.3 Ironwood is current).
- One input: escrow outpoint, `nSequence = 0xffffffff`.
- Outputs: `amount_zat - fee` to the LP's address (t1 or shielded).
- `nLockTime = 0`, `nExpiryHeight = 0`.
- scriptSig: `OP_0 <sig_u> <sig_l> OP_1 <redeemScript>`; the `OP_1` selects the
  IF branch. `OP_0` is the CHECKMULTISIG dummy.

### 4.4 Refund transaction

Built and broadcast by the user's client at or after height `T`.

- One input: escrow outpoint, `nSequence = 0xfffffffe` (CLTV fails if the
  input is final).
- `nLockTime = T`.
- Output to a user address; a shielded output is preferred and is possible in a
  v5 transaction.
- scriptSig: `<sig_u> OP_0 <redeemScript>`.

### 4.5 Expiry choice

The release carries no `nExpiryHeight` so that a release delayed by mempool
congestion is still minable. After `T` both refund and release are valid and
the miner picks. That race is the LP's loss and is why `PAY_DEADLINE` and
`BROADCAST_DEADLINE` exist.

### 4.6 ZIP 244 sighash

Both parties must produce the identical 32-byte digest for the release input.
Use librustzcash:

```
zcash_primitives::transaction::sighash::signature_hash(
    &unsigned_tx_data,
    &SignableInput::Transparent {
        hash_type: SIGHASH_ALL,     // 0x01
        index: 0,
        script_code: &redeem_script,
        script_pubkey: &p2sh_script_pubkey,
        value: amount_zat,
    },
    &txid_parts_cache,
)
```

Facts the implementer must not get wrong:

- The digest is BLAKE2b-256 with personalization `ZcashSigHash` followed by the
  4-byte consensus branch id, over the ZIP 244 tree. The transparent input
  digest commits to the prevout, value, spent scriptPubKey and nSequence.
- Signatures are DER-encoded ECDSA plus the sighash-type byte `0x01`.
- Zcash enforces `SCRIPT_VERIFY_LOW_S` as a standardness rule. A signature
  produced by adaptor decryption may be high-S; normalise `s` to `s' = n - s`
  before encoding. This does not change validity.
- Phase 1 must produce a test vector (unsigned tx, digest, both signatures) and
  confirm it by mempool acceptance on testnet via zebrad `sendrawtransaction`.
  A digest disagreement between the user client and the LP is a silent
  funds-lock for the LP, so the vector is a hard gate.

## 5. Adaptor / DLC protocol

### 5.1 Attestor announcement

Before the user funds, the LP requests an announcement for the escrow it is
about to serve:

```
POST /announce
{
  "event_id":   sha256("zecp2p-escrow-v1" || funding_txid || vout),
  "terms":      { ... canonical terms from 5.2 ... }
}
->
{
  "P":          33-byte attestor pubkey,
  "R":          33-byte nonce point R = k*G, fresh per event_id,
  "outcome":    "paid",
  "event_id":   ...,
  "terms_hash": sha256(canonical terms),
  "announce_sig": BIP340 Schnorr signature by d over
                  sha256("zecp2p-announce-v1" || event_id || terms_hash || R)
}
```

The attestor stores `(event_id, k, terms_hash)` and refuses a second
announcement for the same `event_id`. There is exactly one outcome, `paid`.
A `not paid` outcome is never signed because the refund path is CLTV; this
removes any possibility of the attestor equivocating between outcomes.

Outcome point, computed by everyone from public data:

```
e = tagged_hash("zecp2p-outcome-v1", R || P || event_id || "paid")   (mod n)
Y = R + e*P
```

When the attestor later signs, it publishes `s = k + e*d (mod n)`, and
`s*G == Y` holds. `s` is the adaptor secret `y`.

### 5.2 Canonical terms and intentHash

```
terms = {
  "funding_txid":      hex,
  "vout":              integer,
  "amount_zat":        integer,
  "u_pub":             hex,
  "l_pub":             hex,
  "refund_height":     T,
  "usd_amount_6dec":   integer,      // what the LP must send, in 6-decimal USD
  "rate_18dec":        integer,      // USD per ZEC, 18 decimals, quoted by LP
  "payee_hash":        bytes32,      // zk-p2p curator hashedOnchainId of the user's Venmo
  "lock_confirmed_ms": integer       // set after confirmation depth reached
}
intentHash = sha256("zecp2p-intent-v1" || canonical_json(terms))
```

`canonical_json` is JSON with sorted keys, no whitespace, integers as decimal
strings. `intentHash` is what the LP passes to the enclave as `INTENT_HASH`;
the enclave signs for any 32-byte value the caller supplies.

### 5.3 Pre-signature handshake

1. LP quotes: `rate_18dec`, `usd_amount_6dec` for the user's `amount_zat`,
   `l_pub`, `refund_height` policy, and returns the attestor announcement for
   the event id the user's funding txid will have. Because the user does not
   know the txid until it has built the funding tx, the sequence is:
   a. user builds the funding tx and computes `funding_txid`;
   b. user sends `funding_txid`, `vout`, `u_pub`, `amount_zat` to LP;
   c. LP fetches the announcement, returns `R`, `P`, `announce_sig`, `terms`.
2. User verifies `announce_sig` against `P`, checks `P` against the attestor
   identity it has pinned (Phase 7: against the Nitro attestation document),
   recomputes `Y`.
3. User builds the release tx exactly as the LP will (deterministic
   construction from `terms` and the LP's stated output script), computes the
   ZIP 244 digest `m`, and produces the ECDSA adaptor pre-signature:

   ```
   pre_sig = EcdsaAdaptorSignature::encrypt(secp, m, u_priv, Y)
   ```

   using `secp256k1-zkp` 0.11 (crate `secp256k1-zkp`, module `ecdsa_adaptor`).
   The pre-signature carries a DLEQ proof, so the LP can verify it against
   `u_pub` and `Y` without knowing `y`.
4. User sends `pre_sig` to the LP, then broadcasts the funding tx. Sending
   the pre-signature first is safe: it is useless without `y`, and the LP
   pays nothing until the lock is confirmed.
5. LP verifies `pre_sig.verify(secp, m, u_pub, Y)`. If it fails, LP does not
   proceed and the user refunds at `T`.

The user client stores `(u_priv, redeem_script, T, funding_txid)` durably
before broadcasting. Losing `u_priv` loses the refund path.

### 5.4 Payment and attestation

1. LP's zebrad reports the escrow output at confirmation depth per section 7.
   LP records `lock_confirmed_ms` and finalises `terms`.
2. LP sends the Venmo payment for `usd_amount_6dec` to the user's Venmo
   account using the existing taker flow.
3. LP runs the existing prover (`scripts/proof/prove_payment.mjs`) with:
   - `INTENT_HASH` = `intentHash` from 5.2
   - `INTENT_AMOUNT` = `usd_amount_6dec`
   - `PAYEE_HASH` = `payee_hash`
   - `INTENT_TIMESTAMP_MS` = `lock_confirmed_ms` (the enclave only matches
     payments at or after this snapshot)
   - `INTENT_RATE` = `rate_18dec`
   The prover already pins the enclave PCR8 and signer and verifies the
   signature locally. Output is the attestation JSON.
4. LP sends `POST /attest { event_id, terms, attestation }` to the attestor.

### 5.5 Attestor outcome signing

The attestor, on `/attest`:

1. Looks up `event_id`; refuses if unknown, already signed, or
   `sha256(canonical terms) != terms_hash` from the announcement.
2. Recomputes `intentHash` from `terms` and requires
   `attestation.typedDataValue.intentHash == intentHash`.
3. Verifies the enclave signature with
   `verifyBuyerTeePaymentAttestation(attestation, { expectedPlatform: 'venmo',
   expectedActionType: 'transfer_venmo', expectedDomain: { chainId: 8453,
   verifyingContract: '0xC6F4...502B' }, expectedIntentHash: intentHash,
   trustedSigners: ['0xe078d93bfdd87a8c5c5cca5905dcba0dd7a1f0bd'] })`, or an
   equivalent ecrecover in the attestor's language against the same domain
   separator and struct hash. Phase 0 records the domain name and version and
   the exact `dataHash` derivation from a captured attestation.
4. Requires `releaseAmount >= usd_amount_6dec`.
5. Confirms on its own zebrad that `funding_txid:vout` exists, pays the
   expected P2SH scriptPubKey with `amount_zat`, and has at least the
   confirmation depth for that size.
6. Computes `e`, signs `s = k + e*d mod n`, deletes `k`, marks the event
   signed, returns `{ "s": hex }`.

The attestor never sees a Venmo cookie, never signs a Zcash sighash, and
never holds a value that alone moves funds.

### 5.6 Release

1. LP checks `s*G == Y`.
2. `sig_u = pre_sig.decrypt(s)`; normalise to low-S; DER-encode; append `0x01`.
3. `sig_l = ecdsa_sign(m, l_priv)`; low-S; DER; append `0x01`.
4. Assemble scriptSig from 4.3, broadcast via zebrad, confirm.

The LP can also run `EcdsaAdaptorSignature::recover(sig_u, pre_sig, Y)` to
re-derive `s` from the on-chain signature; this is not needed in the protocol
but is a useful test.

## 6. Attestor service

Language: Rust, sharing `zcash_primitives` and `secp256k1-zkp` with the LP.

Endpoints: `GET /identity` (returns `P`, build id, and in Phase 7 the Nitro
attestation document), `POST /announce`, `POST /attest`. Authenticated by a
shared bearer token in Phase 1; in Phase 7 the enclave attestation document
is the authentication the user relies on.

State: one table `events(event_id PRIMARY KEY, terms_hash, R, k_sealed,
announced_at, signed_at, s)`. `k` is generated from the OS RNG per event, never
derived from `d`. On sign, `k` is overwritten. The attestor key `d` is
generated at first boot and in Phase 7 sealed to the enclave.

Policy is deterministic and published: an announcement is issued for any
well-formed request; an outcome is signed if and only if steps 1 to 5 of 5.5
pass. There is no manual override endpoint.

Rate limits and abuse: announcements are cheap and unbounded requests only
cost storage; cap at one announcement per `funding_txid`.

Logging: log `event_id`, decision, and the enclave attestation signature.
Never log `k`, `d`, or anything from the attestation payload beyond
`intentHash`, `releaseAmount` and the signer.

## 7. Confirmation depth and margin policy

Confirmation depth before the LP pays Venmo, by USD size of the escrow:

| USD amount | Depth | Wall time at 75 s |
|---|---|---|
| up to 50 | 10 | 12.5 min |
| 50 to 500 | 30 | 37.5 min |
| over 500 | 100 | 125 min, protocol-final |

Margins, all in blocks before `T`:

- LP does not send Venmo at or after `PAY_DEADLINE = T - 60`. If the LP has
  not paid by then it does nothing; the user refunds.
- LP must broadcast the release by `BROADCAST_DEADLINE = T - 40`. If the
  attestor has not answered by then the LP escalates operationally; the
  release is still valid after `T` but competes with the refund.
- Release fee: ZIP 317 conventional fee. Zcash has no RBF; a stuck release
  cannot be bumped, so do not underpay.
- The attestor applies the same depth table independently in step 5 of 5.5.

If a reorg drops the funding tx below the required depth after the LP has
paid, the LP waits for re-inclusion; the funding tx is not invalidated by a
reorg unless the user double-spends the shielded input, which requires the
user to have prepared for a reorg deeper than the depth table. The 100-block
tier makes that impossible by protocol.

## 8. Failure modes

| Failure | Who loses | Why bounded |
|---|---|---|
| LP never pays | Nobody | User refunds at `T` |
| LP pays, attestor down or refuses | LP | User refunds at `T`; LP is out the Venmo amount |
| LP pays, enclave service down | LP | Same; the enclave is the only source of Venmo truth |
| LP pays too close to `T`, release loses the race | LP | `PAY_DEADLINE` exists to prevent this |
| User withholds pre-signature | Nobody | LP does not pay |
| User sends a bad pre-signature | Nobody | LP verifies DLEQ before paying |
| User loses `u_priv` | User | Refund path unusable; release still works if LP pays; client stores key before broadcast |
| Sighash mismatch between client and LP | LP | Decrypted `sig_u` invalid; caught by Phase 1 test vector |
| Attestor signs `paid` for an unpaid escrow | User | Requires a forged enclave signature or modified attestor code; see below |
| Attestor + LP collude | User | Same as above; the honest limit of the two-signer design |
| Enclave attests a payment that did not happen | User | Identical to today's zk-p2p exposure |
| Enclave signer key rotates | LP (cannot claim) | Attestor pins the signer; rotation is a config change, not a protocol change |
| Zcash retires new value into the transparent pool | Everyone (no new escrows) | Existing escrows unaffected; forum proposal only, not a ZIP |
| NU7 changes block time to 25 s | Nobody if `BLOCK_SECONDS` is a parameter | Heights must be re-derived at activation |

Constraining the "attestor lies" row: the attestor's signing path is a few
hundred lines that verify one ECDSA signature against a pinned key and one
outpoint against a local node. Phase 7 runs it in AWS Nitro with a reproducible
EIF; the user client verifies the attestation document and PCR8 when it accepts
`P` and `R`. That turns "trust the operator" into "trust the measured code and
AWS", which is the same trust class as the zk-p2p enclave the user already
relies on for Venmo truth.

## 9. Build plan

| Phase | Scope | Estimate |
|---|---|---|
| 0 Recon | Capture a real attestation JSON; record EIP-712 domain name and version, `dataHash` derivation, `releaseAmount` semantics. Confirm librustzcash builds v5 tx with Ironwood outputs and P2SH transparent inputs. Confirm current consensus branch id. | 3 days |
| 1 Transactions | Redeem script builder, P2SH address, funding tx from shielded, release and refund builders, ZIP 244 digest via `signature_hash`, low-S normalisation, DER. Testnet test vector accepted by zebrad mempool for both branches. | 1 week |
| 2 Attestor core | `/identity`, `/announce`, `/attest` with steps 1 to 5 of 5.5, event table, enclave signature verification with pinned signer and domain. Unit tests with the Phase 0 attestation. | 1 week |
| 3 Adaptor | BIP340 announcement and outcome signing, `Y` derivation, `secp256k1-zkp` encrypt, verify, decrypt, recover; property test that decrypt then normalise yields a signature zebrad accepts. | 1.5 weeks |
| 4 Client handshake | User client: build funding tx, precompute txid, receive announcement, verify, produce pre-signature, durable key storage, refund automation at `T`. LP daemon: watcher, depth policy, deadlines, Venmo send via existing taker, prover invocation, attestor call, release broadcast. | 1.5 weeks |
| 5 Testnet end to end | Paid path and refund path on Zcash testnet against the preprod attestation service; deadline and race tests by manipulating `T`. | 0.5 week |
| 6 Mainnet $1 | Section 10. | 2 days |
| 7 Nitro attestor | Reproducible EIF, key sealed to enclave, attestation document on `/identity`, client PCR8 pin. | 1 week |

Total to a live $1 mainnet test: about 6 weeks. Phase 7 adds one.

## 10. Acceptance criteria for the $1 mainnet test

Two escrows, each for the ZEC equivalent of 1 USD at the quoted rate, run on
Zcash mainnet against the production attestation service.

Paid path:

1. Funding tx is a v5 transaction from a shielded input to a `t3` address
   whose redeem script decodes to section 4.1 with the expected keys and `T`.
2. The LP daemon logs the escrow at the depth from section 7 and does not
   pay before that.
3. A Venmo payment of exactly 1.00 USD is sent to the test payee; its Venmo
   payment id is recorded.
4. The prover returns an attestation whose `typedDataValue.intentHash` equals
   the `intentHash` recomputed from the recorded `terms`, whose signer is
   `0xe078d93bfdd87a8c5c5cca5905dcba0dd7a1f0bd`, and whose `releaseAmount` is
   at least 1000000.
5. The attestor returns `s` with `s*G == Y` for the announced `R`.
6. The release tx confirms with scriptSig `OP_0 <sig_u> <sig_l> OP_1
   <redeemScript>`, both signatures low-S, and pays `amount_zat - 10000` to
   the LP output. `recover(sig_u, pre_sig, Y)` reproduces `s`.
7. The release confirms before `BROADCAST_DEADLINE`.
8. A second `/attest` for the same `event_id` is refused.

Refund path:

9. A second escrow is funded; the LP daemon is configured not to pay.
10. No Venmo payment is made and no `/attest` call occurs.
11. At height `T` the user client broadcasts the refund with `nLockTime = T`
    and `nSequence = 0xfffffffe`; it confirms and pays to a shielded output.
12. A release tx assembled with a fabricated `s` is rejected by zebrad
    mempool before `T` (invalid signature), demonstrating the pre-signature is
    inert without the attestor.

Both:

13. Every height in the run was derived from `BLOCK_SECONDS` and
    `REFUND_DELAY` config, and the same binary passes the run on testnet with
    a different `REFUND_DELAY`.
14. Nothing in any log matches the Venmo cookie, `k`, `d`, `u_priv`, or
    `l_priv`.

## 11. Open items

- Exact EIP-712 domain name and version for `PaymentAttestation`, and the
  `dataHash` derivation, are read from a live attestation in Phase 0 and then
  pinned in the attestor.
- Whether the user client should be a Zashi plugin or a standalone binary.
  The spec assumes standalone; it needs shielded spend capability and a
  secp256k1 key store.
- Refund to a shielded output requires the client to build a v5 transaction
  with a transparent input and an Ironwood or Orchard output; confirm in
  Phase 0.
- Transparent-pool retirement is a live community proposal with a
  2026-10-28 target and no ZIP. If a ZIP-211-style rule activates, new escrows
  cannot be funded; existing ones are unaffected.

## 12. Phase 0 findings

Recorded 2026-09-02 against `zcash_primitives` 0.30.1, `zcash_protocol` 0.10.5,
`orchard` 0.15.5, `zcash_script` 0.4.5 and `secp256k1-zkp` 0.11.0. Every claim
below is pinned by a test in `crates/zecp2p-escrow/tests/`, so a dependency bump
that changes one fails the suite rather than surfacing on mainnet.

### 12.1 EIP-712 domain and dataHash (closes open item 1)

Read from two live attestations already in the repo,
`scripts/proof/attestation.json` and `scripts/proof/attestation_4499.json`; no
new payment was needed.

| Field | Value |
|---|---|
| Domain name | `UnifiedPaymentVerifier` |
| Domain version | `1` |
| chainId | 8453 |
| verifyingContract | `0xC6F4a193576C60892a47e111Bb5706c30162502B` |
| domainSeparator | `0xe27fb63a4c62dd4015ccc6378579f3bb3759a7fc50a072a670cb7d0fc0f164f9` |
| typeHash | `0x3fbf9df18b1c2ca7c48d809a8d8c6bbf8d7ac33f3741ab78dac072aba0f77103` |

The domain has no `salt`; the four-field EIP-712 domain above reproduces the
recorded `domainSeparator` exactly. `typeHash` is
`keccak256("PaymentAttestation(bytes32 intentHash,uint256 releaseAmount,bytes32 dataHash)")`.

**`dataHash` = `keccak256(encodedPaymentDetails)`.** Confirmed on both
attestations. Three plausible alternatives were checked and rejected: hashing
the metadata, hashing the concatenation of details and metadata, and hashing the
ABI encoding of the two hashes. Recovering the signer from the full EIP-712
digest yields `0xe078d93bfdd87a8c5c5cca5905dcba0dd7a1f0bd`, the pinned enclave
signer, for both.

`encodedPaymentDetails` is 14 abi words. The attestor's step 2 of 5.5 should
check the intent binding inside this preimage, not only in `typedDataValue`,
since it is the preimage that the signature actually commits to:

| Word | Meaning |
|---|---|
| 0, 8 | `paymentMethod`, `keccak("venmo")` |
| 1, 10 | `payeeDetails`, the curator `hashedOnchainId` |
| 2 | payment id / index (484 in the sample) |
| 3, 9 | `fiatCurrency` |
| 4 | payment timestamp, ms |
| 5 | opaque per-payment digest |
| 6 | `intentHash` |
| 7 | `releaseAmount` |
| 11 | `conversionRate`, 18 decimals |
| 12 | intent timestamp, seconds |
| 13 | a window, 1209600 s = 14 days |

`releaseAmount` equalled `intent.amount` in both samples, so the
`releaseAmount >= usd_amount_6dec` rule of 5.5 step 4 is satisfied with
equality in the normal case rather than by a margin.

### 12.2 Ironwood is a consensus branch, not an output type (corrects 4.2, 4.4, open item 3)

The spec asks for "a v5 transaction with ... an Ironwood output". As written
that is not constructible, and the phrase conflates two things:

- **Ironwood is NU6.3**, a consensus branch, id `0x37a5165b`. It is the current
  mainnet branch, as section 4.3 says.
- Ironwood *also* names a **separate shielded value pool** (`orchard::ValuePool::Ironwood`),
  and a transaction carries an Ironwood bundle only at **transaction version 6**.
  `TxVersion::V5.has_ironwood()` is false.

So: **the shielded refund output in a v5 transaction is an Orchard output.**
`TxVersion::V5.has_orchard()` is true and V5 remains valid under the NU6.3
branch, so the spec's v5 mandate stands unchanged; only the pool name in 4.4 and
open item 3 needs to read Orchard.

A trap this creates: under NU6.3 `Builder::new` defaults to **V6**, not V5. Both
the user client and the LP must call `propose_version(TxVersion::V5)` explicitly.
If one side takes the default the two ZIP 244 digests differ, and per 4.6 that
is a silent funds-lock for the LP.

A v5 transaction with the escrow P2SH outpoint as its input and a transparent
output builds against the NU6.3 branch; the P2SH input is accepted by
`add_transparent_p2sh_input`.

### 12.3 The ZIP 317 fee is 15000 zat, not 10000 (corrects section 3 and criterion 6)

Two findings, one blocking:

`zip317::FeeRule` **cannot price a custom P2SH input.** Only the spender knows
the scriptSig length, so the rule returns `FeeError::UnknownP2shInputs` and
refuses to guess. The escrow computes its own conventional fee in
`crates/zecp2p-escrow/src/fees.rs`; that arithmetic is cross-checked against the
library's rule on inputs the library can size.

With the fee computed, the numbers are not the ones section 3 assumes:

| Transaction | Input size | Logical actions | Fee |
|---|---|---|---|
| Release, 1 transparent output | 310 bytes | 3 | **15000 zat** |
| Refund, 1 shielded output | 233 bytes | 4 | **20000 zat** |

The release input is 310 bytes because its scriptSig carries two 73-byte
signatures and a 115-byte redeem script; ZIP 317 divides by the 150-byte nominal
P2PKH input, so it is three logical actions rather than one. Section 3's "a 1-in
1-out or 1-in 2-out transparent spend is 10000 zat" is true of a P2PKH spend and
false of this escrow. Acceptance criterion 6 should read `amount_zat - 15000`.

Underpaying is not recoverable: Zcash has no RBF, and section 7 already notes a
stuck release cannot be bumped. The fee module therefore sizes signatures at
their 73-byte maximum rather than their typical length.

The redeem script is 115 bytes at present mainnet heights, where `T` encodes in
three script bytes, and 116 once heights pass 8388608. Both fall in the same fee
bracket, so no escrow written today changes price at that boundary.

### 12.4 Confirmed unchanged

- The redeem script of 4.1 spends on both branches under the consensus flags a
  node applies, including `LowS`, `NullDummy`, `MinimalData`, `CleanStack` and
  `CHECKLOCKTIMEVERIFY`; the refund is rejected at `T - 1` and accepted at `T`.
- `secp256k1-zkp` 0.11 with `ecdsa_adaptor` is available as 5.3 assumes.
- The ZIP 244 API differs in shape from the sketch in 4.6: `SignableInput` is an
  enum whose transparent variant is built with
  `zcash_transparent::sighash::SignableInput::from_parts(bundle, hash_type,
  index, script_code, script_pubkey, value)`, which validates the input index
  against the bundle. The committed fields are as 4.6 describes.

### 12.5 Open after Phase 0

- No `zebrad` or `zcashd` is installed on the build host, and no Zcash RPC
  endpoint is configured. Phase 1's mempool-acceptance gate needs one; that is
  the next blocker, not a protocol question.
- The consensus branch id must still be read from the node at runtime per 4.3.
  Mainnet was at height 3469623 when this was written, on the NU6.3 branch.

## 13. Build status

Updated 2026-09-02. Phase numbering follows section 9.

| Phase | State | Where |
|---|---|---|
| 0 Recon | Done | Section 12; `crates/zecp2p-escrow/tests/phase0_librustzcash.rs`, `attestation_vectors.rs` |
| 1 Transactions | Code done, testnet gate not met | `crates/zecp2p-escrow/src/{script,tx,fees}.rs` |
| 2 Attestor core | Decision path done, HTTP surface not built | `crates/zecp2p-attestor/src/{lib,store}.rs` |
| 3 Adaptor | Done | `crates/zecp2p-escrow/src/dlc.rs` |
| 4 Client handshake | Logic done against a node trait; no RPC adapter | `crates/zecp2p-escrow/src/{client,lp,chain,deadlines}.rs` |
| 5 Testnet end to end | Blocked, see below | |
| 6 Mainnet $1 | Blocked on 5 | |
| 7 Nitro attestor | Not started | |

What is proved, and by what:

- Both branches of the redeem script run under the same consensus interpreter
  zebrad uses, with the mempool's standardness flags. The refund is rejected at
  `T - 1` and accepted at `T`; the LP cannot spend either branch alone; a
  redeem script with a different `T` does not satisfy the committed hash.
- The ZIP 244 digest changes when any committed field changes: outpoint, input
  value, `T`, `l_pub`, branch id, payout script, output value. This is the
  property the pre-signature rests on.
- The full path runs in `tests/end_to_end.rs`: the user pre-signs the real
  release digest, a production attestation gates the outcome scalar, the
  decrypted signature goes into a scriptSig, and the interpreter accepts it.
  Three fabricated scalars each yield a release the script rejects.
- The attestor refuses a mismatched intent, an underpayment, a wrong signer,
  altered terms, a wrong escrow script, a wrong amount, and insufficient depth,
  each tested with an otherwise-valid request.

### 13.1 What blocks the acceptance criteria

The gate is a Zcash node. No `zebrad` or `zcashd` is installed on this host and
no RPC endpoint is configured, so these criteria cannot be met yet:

- Phase 1's hard gate: mempool acceptance of both branches on testnet via
  `sendrawtransaction`. Section 4.6 calls this a hard gate and it is not met.
  The script tests execute the same interpreter zebrad links, which is strong
  evidence and is not the same thing as a node accepting the transaction.
- Criterion 12's mempool rejection of a fabricated release. The rejection is
  demonstrated at the script and cryptographic layers, not at a node.
- Everything in criteria 1 to 11 and 13, all of which need a funded wallet on
  testnet and then mainnet.

Nothing about the funding transaction is built. Spec 4.2 needs a shielded spend
from the user's wallet, which needs a wallet, a node, and the Orchard proving
path; `tx.rs` covers only the two transactions that spend the escrow.

The remaining code work before a testnet run is Phase 4: the client handshake,
durable key storage, refund automation at `T`, and the LP daemon that watches
depth, honours `PAY_DEADLINE` and `BROADCAST_DEADLINE`, calls the existing
prover, and broadcasts. None of it is written.

### 13.2 Phase 4 as built

The chain sits behind a `ChainClient` trait with an in-memory implementation,
so a reorg, a confirmation depth and an unreachable node are conditions a test
causes rather than waits for. **No adapter over zebrad RPC exists.** Nothing in
either crate has spoken to a node.

The LP is a state machine rather than a sequence of calls, because the ordering
is the safety argument: `ReadyToPay` is unreachable without a confirmed escrow
at the depth for its size, a verified pre-signature, and room before
`PAY_DEADLINE`. A reorg that unwinds the funding transaction moves the state
backwards. `PaidPastMargin` is distinct from `AwaitingAttestation` because the
operational response differs.

The client stores `u_priv` and the redeem script before producing a
pre-signature, and a storage failure aborts the handshake. The refund rebuilds
from the stored record alone and is byte-identical to the one the full terms
produce, which is what "the user needs nobody at `T`" has to mean in practice.

Criterion 14 is enforced by test, and writing that test found two real
violations: the derived `Debug` on `EscrowRecord` printed `u_priv`, and
`EventStore` printed `k`. Both now redact. `k` is the worse of the two, since
two signatures under one nonce expose `d`.

### 13.3 Still not built

- Any RPC adapter. Phase 1's mempool gate and criterion 12's mempool rejection
  remain unmet, and the script-level evidence is not a substitute for a node
  accepting or refusing a transaction.
- The funding transaction of 4.2: a shielded spend needs a wallet, note
  management and the Orchard proving path. `tx.rs` builds only the two
  transactions that spend the escrow.
- The attestor's HTTP surface: `/identity`, `/announce`, `/attest`, the bearer
  token, the SQLite table behind `EventStore`, and rate limiting. The decision
  logic those endpoints would call is written and tested.
- The BIP340 `announce_sig` of 5.1. The user verifies the attestor's key
  against a pin; it does not yet verify a signature over the announcement.
- Phase 7 in full.

## 14. Hosted-API mode, and what it does not establish

The development setup points the RPC adapter at a hosted Zcash endpoint. That
is a build-and-test posture, **not the production trust model**, and the
difference is worth stating precisely rather than leaving to inference.

A hosted provider can lie about height, confirmation depth, or whether an
output exists, and the adapter cannot detect it. What the protocol still
verifies for itself, against every answer the provider gives:

- the escrow's `scriptPubKey` bytes, compared to the script derived from the
  terms, so a provider naming a different output is caught;
- the amount, against the terms;
- the consensus branch id, against what the transaction was built for;
- every signature, hash and script, none of which the provider is asked about.

So a provider that reports the wrong *escrow* is refused. A provider that
reports the wrong *chain* is believed. Under that stance the confirmation-depth
policy of section 7 is advisory, because depth is exactly the number a provider
is trusted for. Production runs against our own node, where it is not.

### 14.1 The endpoint in use

`https://api.tatum.io/v3/blockchain/node/zcash-{mainnet,testnet}`, keyless, no
signup. Testnet and mainnet both answer `getblockchaininfo`, `getblockcount`,
`getblock`, `gettxout` and `getrawtransaction`. Both report
`consensus.chaintip = 37a5165b`, confirming section 12.2's branch id against the
live chain.

Two limits, both real:

- **5 requests per minute.** Enough for a gate, not for a polling daemon.
- **`sendrawtransaction` is blocked at the provider's WAF**, returning
  Cloudflare `403 error code: 1010` for a two-character payload as readily as a
  real one. It is the method that is blocked, not the size.

The second means **Phase 1's mempool gate and criterion 12's mempool rejection
remain unmet.** `crates/zecp2p-escrow/tests/mempool_gate.rs` is written and runs
unchanged against a real node; the `dump_release` example prints the same bytes
for submitting by other means.

## 15. Review round 1: what was found and what changed

An adversarial review found eleven issues, two of them critical, with runnable
proofs of concept. All are fixed. Each fix has a test that fails without it;
the reviewer's PoCs are kept as
`crates/zecp2p-escrow/tests/review_round1_regressions.rs`.

### 15.1 The attestor never read the payment (critical)

`decide` checked that `keccak256(encodedPaymentDetails)` equalled the signed
`dataHash`. That proves the enclave signed *those bytes* and says nothing about
what they claim. The enclave signs whatever payment the caller proved, so an LP
could pay **its own Venmo account**, one cent, at a rate it chose, a month
before the escrow existed, and every check passed.

The blob is now decoded (`payment_details.rs`) and compared field by field:
payee against `terms.payee_hash`, platform against Venmo, currency against USD,
intent against the recomputed intent, amount against the terms, and the payment
timestamp against the observed lock time. The duplicated words (method,
currency, payee appear twice) must agree with each other.

The timestamp check carries a **10-minute backdating tolerance**, and that is
not slack for its own sake: on the captured 1.00 USD attestation the payment is
timestamped 155 seconds *before* its own intent timestamp, because Venmo's clock
and the prover's snapshot are different clocks. A strict comparison would reject
genuine attestations.

### 15.2 The client accepted an announcement for another escrow (critical)

The LP relays the announcement, so it can relay a *genuine* one issued for an
escrow the LP itself controls. The client encrypted its pre-signature under that
event's outcome point; when the LP then paid itself for its own escrow, the
scalar the attestor legitimately published completed the victim's release too.

The client now recomputes `event_id(funding_txid, vout)` from the outpoint it is
about to fund and refuses anything else. One comparison.

### 15.3 The outcome point now commits to the terms

`e` is `tagged_hash("zecp2p-outcome-v1", R || P || event_id || terms_hash ||
"paid")`. Previously `Y` was identical for any terms over one escrow, so a
scalar signed for a 1 USD claim would decrypt a pre-signature made expecting
100 USD. The attestor's terms-hash check made that hard to reach; one check
between an LP and someone's ZEC is thinner than the cryptography allows.

**Section 5.1 changes accordingly:** the announcement request must carry the
terms, and `Y = R + e*P` is computed with `terms_hash` in the preimage.

### 15.4 Deadlines come from the script, not from an observed lock height

Section 7's margins were computed from a lock height the caller supplied. A
funding transaction that confirmed late put the LP's pay deadline in the future
and made `ReadyToPay` reachable at the exact height the user could refund. Every
deadline is now measured from the `T` burned into the redeem script, which is
the only clock CLTV honours. The client's refund gate reads the stored `T` for
the same reason.

`EscrowPolicy::proposed_refund_height` remains, for *quoting* an escrow that
does not exist yet. Once a script exists, its `T` governs.

### 15.5 One payment releases one escrow

There was no nullifier: a single Venmo payment could be presented against
several escrows for the same user. The attestor now derives a payment nullifier
from the payment's own digest, payee, index and timestamp, and the store records
it atomically with the signature. `mark_signed` refuses a nullifier already
consumed by a different event.

### 15.6 `INTENT_RATE` semantics, unresolved and now explicit

Word 11 is `conversionRate`. The LP passes `INTENT_RATE` as USD per ZEC; the
captured $4.87 attestation carries `990881148896019200`, which is 0.99 in 18
decimals, because that fill was a **USDC** fill where the rate is dollars per
USDC-like unit. Nothing captured establishes what the value must be for a ZEC
escrow.

Rather than guess, the check is a policy: `RatePolicy::Exact` (production, once
the semantics are settled), `AtLeast`, or `Unenforced` (development). The
attestor requires the caller to state which. **This remains an open item**, and
it must be settled to `Exact` before mainnet.

### 15.7 Smaller items

- An unknown consensus branch id is `TxError::UnknownBranchId` rather than a
  panic. It is read from a node, so it is untrusted input, and the daemons call
  the builder on every poll.
- `verify_against_signer` and `decide_against_signer` are behind the
  `test-signer` feature. A production build has no path that trusts anything but
  the pinned enclave key.
- The store returns a `BoundNonce` carrying its event id, so a handler cannot
  sign event B with event A's nonce.
- Weak tests fixed: assertions that sat inside `if let Ok(...)` or
  `let ... else { continue }` passed vacuously the moment the wrapped call
  changed shape. They are now unconditional.

### 15.8 A correction to the mental model

`verify_outcome_secret(-s)` fails, but `decrypt(-s)` yields a signature that
*does* verify under `u_pub` after low-S normalisation. This is not a break: `-s`
is derivable only from `s`, so anyone who can compute it already holds the real
scalar. But it means `s*G == Y` is not the property standing between an LP and
the escrow. What gates the spend is the script's CHECKMULTISIG, and what gates
that is whether the decrypted signature verifies under `u_pub`. A test pins this
so the wrong model is not re-derived from a passing suite.

### 15.9 Stale funding txid

If the wallet rebuilds the funding transaction after `prepare_escrow` has saved
the record, the stored txid names an escrow that will never exist.
`may_broadcast_funding` takes the txid actually about to be broadcast and
refuses when no record matches it, so the mismatch is caught before the money
moves rather than discovered at `T`.

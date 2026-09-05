# Checks for the page's hand-written crypto

`frontend/app/escrow.js` implements, in the browser, the user's half of the
native Zcash escrow: SHA-256, RIPEMD-160, BLAKE2b, secp256k1, ECDSA, the
libsecp256k1-zkp adaptor signature with its DLEQ proof, the redeem script, the
t3 address, ZIP 317 fees, ZIP 225 serialization and the ZIP 244 digests. Every
one of those fails silently when it is wrong: a digest one byte off is a
pre-signature the LP verifies happily against the wrong transaction.

None of this runs under `cargo test`. Run it when you touch `escrow.js`.

## Vectors against the crate

```
cargo run -p zecp2p-escrow --example frontend_vectors -- emit > /tmp/vectors.json
node frontend/app/test/escrow-vectors.js /tmp/vectors.json /tmp/js-out.json
cargo run -p zecp2p-escrow --example frontend_vectors -- check /tmp/vectors.json /tmp/js-out.json
```

`emit` prints what the crate computes from fixed keys and a fixed outpoint.
The node script recomputes each value and compares, then writes a
pre-signature, a completed release and a signed refund. `check` runs those
through `verify_pre_signature`, adaptor decryption with the real outcome
scalar, `txid_of_signed`, and the consensus script interpreter, at `T` and at
`T - 1`.

## The mock coordinator

```
MOCK_OUT_DIR=/tmp/mock-out node frontend/app/test/mock-coordinator.mjs
# open http://127.0.0.1:8787/app/
cargo run -p zecp2p-escrow --example frontend_vectors -- check-release /tmp/mock-out/release-<id>.json
```

The mock serves `frontend/` and answers the six `/escrow/*` endpoints the page
uses. Its payer key, attestor and terms are real and computed with the same
`escrow.js`; its chain is a timer. A handle of `nobody-pays` runs the
abandoned path to a refund instead. Every release it assembles is written out,
and `check-release` recomputes the digest from the terms alone and executes
the scriptSig against it, so a browser run is promoted from "JavaScript agrees
with JavaScript" to "the crate agrees".

## The older checks

`qr-verify.js`, `crypto-vectors.js`, `session-key-vectors.js` and
`zaddr-vectors.js` cover the QR encoder, and the Base-route session key and
address checksums (SHA-256, base58check, bech32m) that `advanced/` still uses
from `zaddr.js`. They need `npm install jsqr qrcode` and the coordinator's
`verify_js_sigs` example; see their headers.

## What these caught

- **Format bits written backwards** in the QR encoder: the symbol scanned as
  nothing while looking like a QR code.
- **The dark module overwritten** by the second copy of the format bits.
- **EIP-55 where the server uses lowercase** in the Base-route session key.

## The refund's outpoint

`refund-outpoint.js` reads the precedence out of `app.js` and checks it against
the case that matters: a funding transaction that expired unmined and was
resent under a new txid. The record this page saved when it signed names the
old outpoint; the coordinator's view names the one that confirmed. Building the
refund from the record produces a transaction no node will accept, while the
page says any node will take it.

```
node frontend/app/test/refund-outpoint.js
```

## When the refund becomes possible

`refund-wait.js` checks the arithmetic behind the refund screens against the
real source. `read_order` serves `current_height` 0 when the coordinator cannot
reach its node, and read as a height rather than as "unknown" that made the page
render the wait as T blocks - roughly eighty years on mainnet - for an escrow
refundable the next day.

```
node frontend/app/test/refund-wait.js
```

## When the refund form is offered

`refund-form-visibility.js` drives `renderReturns` under a stub DOM. The form
signs the escrow's timeout branch, which is right when the trade is over and
nobody was paid and wrong when the dollars already left - there the LP holds a
valid release over the same escrow, and offering the form is this page telling
the user to race it.

```
node frontend/app/test/refund-form-visibility.js
```

# Checks for the page's hand-written crypto

Four things in `frontend/app/` are implemented by hand because the browser does
not provide them: QR encoding, secp256k1, keccak256, and the address checksums
in `zaddr.js` (SHA-256, base58check, bech32m). All of them fail silently when
they are wrong. A QR code that encodes nothing still looks like a QR code; a
signature over the wrong bytes is still a well-formed signature; and a checksum
that accepts everything accepts every real address too, which is why the round
1 audit found `t1AAAA...` passing the check this replaces.

These are not run by `cargo test`. Run them when you touch `qr.js` or the
crypto section of `app.js`.

```
npm install jsqr qrcode

node frontend/app/test/crypto-vectors.js       # keccak and secp256k1 vectors
node frontend/app/test/zaddr-vectors.js        # SHA-256, base58check, bech32m
node frontend/app/test/qr-verify.js            # encode, then decode with jsQR

node frontend/app/test/session-key-vectors.js > /tmp/js-sigs.json
cargo run -p zecp2p-coordinator --example verify_js_sigs -- /tmp/js-sigs.json
```

The last one is the one that matters most: it takes signatures the page
produced and runs them through `auth::require_owner`, the same function the
live endpoint calls, and checks that the address the coordinator derives from
the page's public key is the address the page signed as.

## What these caught

- **Format bits written backwards.** QR format information is fifteen bits,
  most significant first. Written least significant first, every module of the
  data region is still correct and the symbol scans as nothing.
- **The dark module overwritten.** The second copy of the format bits runs
  through `[size-8][8]`, which is fixed dark and is not a format bit.
- **EIP-55 where the server uses lowercase.** The page checksummed the address
  inside the message it signed; `auth.rs` builds that message with alloy's
  `{:?}`, which is lowercase. Same key, same algorithm, different bytes, and
  every order would have failed to open with an unexplained 401.

## Not independently checked

The session key's transparent Zcash address is derived twice, in
`backend/session_key.rs` with the `ripemd` crate and never in the page, which
does not need it. Its base58check is checked against a vector computed outside
that code, and the result is run through the coordinator's own refund
validator, but the RIPEMD-160 step itself has only the one implementation
behind it. Worth a second opinion from a wallet before a return is claimed
against one of these addresses on mainnet.

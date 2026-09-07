# zpay

Pay a Venmo handle with ZEC. The sender locks ZEC in a 2-of-2 escrow on
Zcash, zpay sends the dollars from its own Venmo account, proves the payment
through zk-p2p's attestation enclave, and the proof releases the escrow. If
nobody proves a payment before the deadline, the sender's key alone takes the
ZEC back. Site: <https://zpay.cash/>. Tool: <https://zpay.cash/app/>.

The fee is 0.15% of the payout, charged on top of what the recipient gets, plus
a spread over the exchange price (50 basis points in the shipped config) that
pays the liquidity provider for fronting dollars against a moving coin.

## Sending

1. Open the app, type the amount and the recipient's handle, press **Get the
   address**. The page makes a key in your browser, opens an order, and
   rebuilds the escrow address from your key, zpay's key and the refund height
   before showing it.
2. Send exactly the quoted amount to that transparent address in one
   transaction, from any Zcash wallet.
3. **Keep the link the page offers.** Its fragment holds the key that refunds
   your ZEC. zpay never sees it, and there is no other copy.
4. Leave the page open until it says **locked**: the page has signed its half
   of the release, which only completes once the payment is proven. After that
   the tab can close.
5. Once the escrow is deep enough (10 confirmations under $50, 30 up to $500,
   100 above), zpay pays, attests, and broadcasts the release.

If nobody pays, the page shows **refundable** after the refund height (24
hours in the shipped config) and signs a refund with your key alone.

## Running the service

One liquidity provider, five processes on one machine, in this order:

1. **A Zcash node** over JSON-RPC: `zcashd` or `zebrad` locally, or a hosted
   provider keyed on a request header (`rpc_api_key_header`, `rpc_api_key_env`).
2. **The attestor**: `cargo run --release -p zecp2p-attestor`, configured by
   the `ZECP2P_ATTESTOR_*` and `ZECP2P_RPC_*` variables. It holds one key and
   signs outcomes; back that key up, since losing it makes every open escrow
   unreleasable. Its network must match the coordinator's.
3. **A Chrome signed into Venmo**, driven over the DevTools protocol on port
   9223 with its own profile, headed under Xvfb (headless gets a DataDome
   interstitial instead of a login form). Write the signed-in session's
   cookies to the config's `session_path`; the enclave replays that cookie to
   read the feed. The session idles out in about three hours, so something
   must keep re-capturing it.
4. **The proof harness**: `(cd scripts/proof && npm install)`. The
   coordinator runs `prove_payment_pinned.mjs` from `attestation.repo_root`.
5. **The coordinator**: copy `config.v2coordinator.example.toml`, read the
   comments, set `[zec]`, `[lp] payout_address`, `[attestor] pubkey` (pinned;
   mainnet refuses to start without it), `[serve] handles`, and
   `[server] journal_path`. Then, with `ZECP2P_LP_PRIV` and
   `ZECP2P_ATTESTOR_TOKEN` set, run it with `--check` first, and leave
   `live_payments = false` until a dry trade reaches the send button with the
   right amount and handle.

The page is static HTML in `frontend/`; serve it anywhere and list its origin
in `[server] allowed_origins`. [frontend/README.md](frontend/README.md) covers
the page.

The coordinator will not settle without a real payment, pay one escrow twice
or two at once (the journal line is written under a file lock before the
click), pay an escrow the chain no longer holds, or exceed `max_payment_cents`.

## Developing

Rust 1.88 or later, Node 20 or later, Python 3.

```bash
cargo build --release
cargo test --workspace            # add -- --ignored for tests that need a node or a browser
```

`Cargo.lock` is not committed; if a fresh resolution breaks `alloy` on
`winnow`, copy the lock from a working checkout.

For a local chain use regtest; [scripts/regtest/README.md](scripts/regtest/README.md)
has the activation heights without which zebrad rejects every transaction
this repo builds. The `zecp2p-escrow` examples drive an escrow by hand
(`escrow_e2e`, `fund_escrow`, `paid_path`, `fabricated_release`,
`frontend_vectors`); each prints its usage. The page's crypto is checked by
the node scripts in `frontend/app/test/`, and `scripts/e2e/run_e2e.py` runs a
whole trade through the live site.

The protocol is in [specs/zec-native-escrow.md](specs/zec-native-escrow.md):
a 2-of-2 P2SH with a CLTV refund, released by an adaptor signature the
attestor's outcome completes. Read it before the code.

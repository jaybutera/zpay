# zpay

Pay a Venmo handle with ZEC. The sender locks ZEC in an escrow on Zcash, zpay
sends the dollars from its own Venmo account, proves the payment through
zk-p2p's attestation enclave, and the proof releases the escrow. If nobody
proves a payment before the deadline, the sender's key alone takes the ZEC back.
The site is <https://zpay.cash/>; the tool is <https://zpay.cash/app/>.

The fee is 0.15% of the payout, charged on top of the dollars the recipient
gets. The quote also carries a spread over the exchange price (50 basis points
in the shipped config) which is the liquidity provider's margin for fronting
dollars against a coin whose price moves while the escrow is open.

This guide covers three things: sending a payment, running the service, and
working on the code.

## Sending ZEC to a Venmo handle

You need a Zcash wallet with a balance and the recipient's Venmo username.
Nothing else: no account, no wallet connection, no browser extension.

1. Open <https://zpay.cash/app/>. Type the amount, in ZEC or in dollars, and
   the recipient's handle. The page shows what lands in their Venmo after the
   fee. Paying your own handle works the same way.
2. Press **Get the address**. The page makes a key in your browser, opens an
   order with the coordinator, and shows a Zcash address. Before it shows the
   address, the page rebuilds it from your key, zpay's key and the refund
   height, and refuses the order if what the coordinator sent differs.
3. Send exactly the quoted amount to that address in one transaction, from any
   Zcash wallet. The address is transparent; sending from a shielded pool is
   fine, the escrow only cares about its own output.
4. **Copy the link the page offers, and keep it.** The link's fragment holds
   the key that refunds your ZEC. The page also stores it in this browser's
   local storage. There is no other copy anywhere: zpay never sees it, and a
   lost key on an escrow that was never paid means the coins sit there until
   the refund height and can never be reclaimed.
5. Leave the page open until it says **locked**. When your transaction appears,
   the page signs its half of the release, a signature that only completes
   once the dollars are proven paid, and sends that to the coordinator. After
   that you can close the tab; reopening the link later shows the order's
   state.
6. The dollars go out once the escrow is deep enough for its size: 10
   confirmations under $50, 30 up to $500, 100 above that. At Zcash's 75-second
   blocks the small tier is about twelve minutes. zpay pays the handle from
   its own Venmo, gets the payment attested, and broadcasts the release. The
   page shows **done** with the release transaction id.

If the payment is never made, the page shows **refundable** once the refund
height passes. Press **Take my ZEC back**, give it a transparent Zcash address,
and it signs a refund in the browser with your key alone. The coordinator
broadcasts it as a convenience; if the coordinator is unreachable the page
shows the raw transaction bytes and any Zcash node will accept them. The
shipped refund window is 24 hours after the order opens.

Limits come from the coordinator, and the page reads them live. The shipped
config allows 0.0012 to 50 ZEC per order, caps a single Venmo payment at an
amount the operator sets, and holds at most five open orders per handle.

## Running the service

The service is one liquidity provider (LP) fronting Venmo dollars against
escrows. To run it you need a Venmo account with a balance, ZEC to receive, and
five processes on one machine. Start them in this order.

### 1. A Zcash node

The coordinator and the attestor both read the chain over JSON-RPC. Any of
these works:

- `zcashd` or `zebrad` on `127.0.0.1:8232`, with `rpc_user` and `rpc_password`
  in the coordinator's `[zec]` block.
- A hosted provider keyed on a request header. NOWNodes is what the live
  service uses; set `rpc_api_key_header = "api-key"` and
  `rpc_api_key_env = "NOWNODES_KEY"` and put the key in that environment
  variable. Do not write the key into the config file, which is world-readable
  on most installs.

The funding scanner has two modes. `block_scan` walks recent blocks and works
against every node, including zebrad. `address_index` is one `getaddressutxos`
call per sweep and needs `zcashd` started with `addressindex=1`; on zebrad it
finds nothing, and the coordinator says so at startup.

### 2. The attestor

The attestor holds one secp256k1 key and signs outcomes. It has no key over any
escrow. Its refusal or outage means the LP cannot claim, and the user still
refunds at the deadline.

```bash
ZECP2P_ATTESTOR_DB=$HOME/.zecp2p/attestor.sqlite \
ZECP2P_ATTESTOR_KEY=$HOME/.zecp2p/attestor.key \
ZECP2P_ATTESTOR_TOKEN=<a long random string> \
ZECP2P_RPC_URL=https://zec.nownodes.io \
ZECP2P_RPC_NETWORK=main \
ZECP2P_RPC_API_KEY_HEADER=api-key \
ZECP2P_RPC_API_KEY=<provider key> \
ZECP2P_BIND=127.0.0.1:8480 \
  cargo run --release -p zecp2p-attestor
```

The key file is created on the first boot at mode 0600 and never overwritten.
Back it up: losing it makes every outstanding escrow unreleasable. The attestor
refuses to start if the key or the database is readable by another account.

The two `RPC_API_KEY` variables are optional and go together; a local node sets
neither. The network and the provider **must match the coordinator's `[zec]`
block**. A mainnet coordinator beside a testnet attestor starts cleanly and
fails after the dollars are gone.

### 3. A browser signed into Venmo

The coordinator pays through a Chrome it drives over the DevTools protocol. It
never sees the password; it drives the pay form in a tab that is already
signed in, and it stops before the send button unless `live_payments` is on.

Run a dedicated Chrome with its own profile on port 9223, headed under Xvfb.
The live service runs it as a systemd user unit whose command is:

```bash
xvfb-run -a -s "-screen 0 1280x900x24" google-chrome \
  --remote-debugging-port=9223 --remote-debugging-address=127.0.0.1 \
  --user-data-dir=$HOME/.zecp2p/chrome-venmo \
  --user-agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36" \
  --no-first-run --no-default-browser-check --disable-background-networking \
  --disable-gpu --disable-dev-shm-usage --window-size=1280,900 about:blank
```

The user agent must match `user_agent` in the coordinator's `[venmo]` block:
the enclave replays the captured cookie under the agent it was captured with.
Two of the choices above are not optional:

- **A separate profile and port.** The coordinator drives the first tab whose
  URL contains `venmo.com`. Attaching it to a browser a person also uses puts
  an unattended money click inside that browser.
- **Headed, not `--headless`.** Measured on 2026-09-04: headless Chrome asking
  for `account.venmo.com` gets a DataDome interstitial with no login form.
  The same profile run headed under Xvfb gets the real page.

Sign that browser into Venmo through its DevTools port; the captcha is an
interaction proof and stays manual. Then write the signed-in session's cookies
to the `session_path` named in the config, as the JSON the coordinator
documents next to that setting; the enclave replays that cookie to read the
payment feed. `sender_id` in the `[venmo]` block is the account's numeric id,
not the handle; the coordinator refuses a session whose id differs.

The session goes idle-stale in about three hours if nothing uses it, so
something has to make one authenticated request from the signed-in browser
and re-capture the cookie before it ages out. Unattended re-login exists only
for an account enrolled in an authenticator app: with `method = "totp"` and
the seed in `config/venmo.local.toml`, the daemon computes its own codes. SMS
and email second factors stop at the code box and wait for a human.

### 4. The proof harness

Attesting a payment is a call to zk-p2p's Nitro enclave, made by
`scripts/proof/prove_payment_pinned.mjs` under Node 20 or later:

```bash
(cd scripts/proof && npm install)
node scripts/proof/check_enclave.mjs     # verifies the enclave's attestation document; sends nothing
```

The coordinator runs that script from `attestation.repo_root` in its config.
Set it to this checkout.

### 5. The coordinator

```bash
cp config.v2coordinator.example.toml config.v2coordinator.toml
$EDITOR config.v2coordinator.toml
```

Every setting in the example file has a comment saying what it does and, where
it matters, what went wrong when it was set differently. The ones you must
change:

- `[zec]` network, RPC and scanner, as above.
- `[lp] payout_address`: where your half of each release lands. The LP key
  itself comes from `ZECP2P_LP_PRIV` (64 hex characters) or from a keystore
  file named by `keystore_dir` and `key_label`.
- `[attestor] url`, and `pubkey` pinned to the attestor's key. The coordinator
  relays the attestor's announcement to the page, so an unpinned key would let
  a coordinator name an attestor whose scalar it holds and decrypt the user's
  pre-signature without paying. The coordinator refuses to start on mainnet
  without the pin, and refuses if the attestor identifies as a different key.
  The key is in the attestor's log at first boot and in the coordinator's
  `attestor reachable attestor_key=` line.
- `[serve] handles`: the Venmo handles you will pay. An empty list refuses
  every order. `allow_any_handle = true` fronts dollars for any handle a
  caller names, which is the liquidity business, entered on purpose.
- `[server] journal_path`: the fill journal, which is also the payment slot.
  If `zecp2p-taker` runs on the same machine it must point at the same file;
  both take a lock on it, and two daemons with two journals will each pay
  while the other is paying.

Then:

```bash
ZECP2P_LP_PRIV=<64 hex> ZECP2P_ATTESTOR_TOKEN=<same string as the attestor> \
  cargo run --release -p zecp2p-v2coordinator -- --check
```

`--check` loads the config, reaches the node, identifies the attestor, checks
the key and the scanner, reads the price feed once, and exits. Without
`--check` it serves on `[server] host:port` (`127.0.0.1:3000` shipped) and
sweeps open orders every 60 seconds.

The shipped config has `live_payments = false`. In that posture the coordinator
takes orders, watches funding, collects pre-signatures and drives the browser
as far as the send button, then stops; no dollars leave and no escrow releases.
Run a trade through that posture first. Set `live_payments = true` when the
dry run reached the button with the right amount and the right handle.

The ZEC/USD rate is read from Coinbase, then Kraken, and cached for 45
seconds. A price that cannot be read, or that moved more than 50% from the
last good one, means the coordinator refuses to quote rather than quoting
stale. `rate_usd_per_zec` pins a constant and turns the feed off; it exists for
regtest, and the coordinator warns on every boot it is set.

### Serving the page

The coordinator serves only `/health` and the six `/escrow/*` routes. The page
is static HTML in `frontend/`; serve it from anywhere and point it at the
coordinator, or put both behind one hostname. Local:

```bash
python3 -m http.server 8080 --directory frontend
# open http://127.0.0.1:8080/app/  ; on port 8080 the page calls http://127.0.0.1:3000
```

The coordinator must list the page's origin in `[server] allowed_origins` or
the browser blocks the calls. [frontend/README.md](frontend/README.md) covers
the page and its `?api=` override.

### What the coordinator will not do

- Settle without a real payment. The production binary has no such path.
  `--simulate-fiat` exists only in a build with `--features test-rails`, and
  that build refuses the flag on mainnet.
- Pay twice for one escrow, or pay two escrows at once. The journal line is
  written under the file lock before the click, and a second payer reads it.
- Pay an escrow the chain no longer holds. The funding output, its depth and
  the branch id are re-read immediately before the browser opens.
- Cap a payment above `max_payment_cents`. That line is the last one against
  a units confusion, and it is yours to set.

## Developing

Rust 1.88 or later (`alloy` and `zcash_primitives` both declare that floor;
the tree is built with 1.98), Node 20 or later, and Python 3.

```bash
cargo build --release
cargo test --workspace
```

`Cargo.lock` is not committed. A fresh checkout resolves dependencies itself,
and a resolution that picks a newer `winnow` breaks every `alloy` crate at
compile time; copy the lock file from a working checkout if that happens.

Tests that need a live node or a signed-in browser are
marked `#[ignore]` and run with `cargo test -- --ignored`. The escrow crate's
read the node from `ZECP2P_RPC_URL` and `ZECP2P_RPC_NETWORK`.

### A local chain

Testnet faucets were all down or unreachable when this was tried,
so the local run uses regtest, where blocks are mined on demand.
[scripts/regtest/README.md](scripts/regtest/README.md) explains the one piece
of configuration that matters: the activation heights in
`zebrad.toml.example`, without which zebrad runs Canopy and rejects every v5
transaction this repo builds.

```bash
zebrad -c scripts/regtest/zebrad.toml.example start          # RPC on 127.0.0.1:18232
curl -s -X POST http://127.0.0.1:18232 -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"1.0","id":"x","method":"generate","params":[110]}'
```

110 blocks matures the first coinbase, paid to the miner address whose key is
printed by `cargo run -p zecp2p-escrow --example miner_addr`. The key is in
the repo on purpose; it holds regtest coin.

### Driving an escrow by hand

The `zecp2p-escrow` crate's examples are the tools. Each prints its usage at
the top of its source.

| example | what it does |
| --- | --- |
| `escrow_e2e plan` / `watch` / `refund` | print the address to fund, watch it reach depth, sweep it back after the deadline with the user key alone |
| `fund_escrow` | fund an escrow on regtest from the miner key |
| `fund_from_keystore` | fund an escrow on any network from a keystore key; rebuilds the address from the terms and refuses to sign if it differs |
| `paid_path` | the paid leg: announce, pre-sign, attest, decrypt, broadcast; needs an attestor built with `--features test-signer` |
| `fabricated_release` | prove that a release with a made-up scalar is rejected by a node's mempool |
| `frontend_vectors` | vectors for the page's hand-written crypto, and the check of what the page produced |

The coordinator's own tests in `crates/zecp2p-v2coordinator/tests` drive the
`/escrow/*` contract and the JS interop with the page. The page's crypto is
checked by `node` scripts in `frontend/app/test/`; that directory's README
lists them, and none of them run under `cargo test`. Run them when you touch
`frontend/app/escrow.js`.

### A whole trade through the live site

`scripts/e2e/run_e2e.py` opens zpay.cash in a Playwright browser, asks for a
payout, reads the escrow address the page shows, funds it from a keystore key
this machine holds, and waits until the page says the money landed. Its
docstring lists every environment variable it takes. It keeps a browser
profile across runs and writes the page's key to `key.json` before it funds
anything, because a throwaway profile takes the refund key with it.
`ZPAY_DRY_RUN=1` opens the order and stops without funding; the order still
counts against the per-handle limit until its refund height.

## Where the design lives

- [specs/zec-native-escrow.md](specs/zec-native-escrow.md): the escrow
  protocol. A 2-of-2 P2SH with a CLTV refund, released by an adaptor signature
  the attestor's outcome completes. Read this before the code.

# zpay frontend

Static, no build step, no dependencies. What `scripts/deploy-site.sh` pushes
to zpay.cash is this directory, minus this file.

```
frontend/
  index.html       the front door
  site.css/js      its styling and live numbers
  takers/          running a taker
  fonts/           Inter and JetBrains Mono, self-hosted
  app/             the app: pay a Venmo handle with ZEC, native Zcash escrow
    index.html     markup and the two views
    app.css        the front door's tokens, nav and card, plus the app's parts
    app.js         quote, order, status, pre-signature, refund
    escrow.js      the user's half of the escrow protocol, in the browser
    qr.js          QR encoder for the zcash: link
    advanced/      the terminal-style route on the Base path, unchanged
    test/          vectors against the crate, and a mock coordinator
```

## The app

Type an amount and a Venmo handle. The page draws a key, derives the escrow's
t3 address from it, and shows the address with a QR and a `zcash:` link. Send
from any wallet. When the coins have confirmed, the page hands the payer an
adaptor pre-signature over the release; the payer sends the Venmo, proves it,
and the escrow releases against that proof. If nobody pays, the page signs the
refund after the timeout with the same key and nobody else.

The key lives in the status link's fragment and in the browser's localStorage.
`docs/status/ux-v2-escrow-page.md` has the protocol steps the page performs,
the API it expects, and what is missing before it can run against a live
coordinator.

## Running it locally

Against the mock, which serves this directory and fakes the chain:

```bash
node frontend/app/test/mock-coordinator.mjs
# http://127.0.0.1:8787/app/
```

Against a coordinator, with any static server:

```bash
python3 -m http.server 8080 --directory frontend
# http://127.0.0.1:8080/app/          defaults to http://127.0.0.1:3000
# http://127.0.0.1:8080/app/?api=https://coordinator.example.com
```

`?api=` persists in localStorage. Served from the coordinator's own origin the
page calls same-origin paths and needs nothing.

## Checking the crypto

`app/test/README.md`. Short version:

```
cargo run -p zecp2p-escrow --example frontend_vectors -- emit > /tmp/v.json
node frontend/app/test/escrow-vectors.js /tmp/v.json /tmp/js.json
cargo run -p zecp2p-escrow --example frontend_vectors -- check /tmp/v.json /tmp/js.json
```

## Notes

Coordinator responses are assigned to text nodes and inputs, never rendered
as markup. Amounts in zatoshi are integers; cents are integers; nothing is
parsed as a float except what the user types.

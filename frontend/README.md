# zecp2p frontend

Static terminal-style UI for the coordinator API. No build step, no dependencies:
three files, plain ES2020, served as-is.

```
frontend/
  index.html    markup and the three views
  styles.css    palette, layout, terminal styling
  app.js        API calls, validation, polling
```

## Running

Any static server works. From the repo root, with the coordinator on its default
`127.0.0.1:3000`:

```bash
python3 -m http.server 8080 --directory frontend
```

Open <http://127.0.0.1:8080>. On port 8080 (and 5173, and `file://`) the UI
defaults to `http://127.0.0.1:3000` for the API. The coordinator already sends
`CorsLayer::new().allow_origin(Any)`, so cross-origin calls work without changes.

Point it at a different coordinator with `?api=`, which persists in localStorage:

```
http://127.0.0.1:8080/?api=https://coordinator.example.com
```

Served from the coordinator's own origin, the UI calls same-origin paths and
needs no configuration.

## Views

**01 / offramp** takes a Venmo handle and a ZEC amount. `get quote` hits
`GET /quote`; `create offramp` posts to `POST /offramp` and jumps to watch.

The API also requires a Base address, a taker address and a ZEC refund address.
Those live in the *advanced* disclosure, since they change rarely, and
`remember these on this device` keeps them in localStorage. `min_rate` is
optional; left blank the coordinator applies its own default of 20 USDC/ZEC, and
after a quote the field shows a suggestion 2% under the quoted rate.

**02 / watch** polls `GET /offramp/{id}` every 5 seconds, stopping on any
terminal state (`fulfilled`, `failed`, `rescued`, `withdrawn`). It shows the
deposit address, a progress ladder over the state machine, and an activity log.
`?session=<uuid>` opens straight into this view.

**03 / manage** posts to the `/process`, `/rescue` and `/withdraw` endpoints.
Rescue and withdraw confirm first, since both end the session.

## Notes

Amounts: `expected_usdc` arrives as a raw 6-decimal integer and is divided by
1e6 for display. Quote fields are already decimal strings.

Input is validated client-side against the same rules as
`crates/zecp2p-coordinator/src/api.rs` (handle charset and length, 8-decimal ZEC
cap, address prefixes and lengths) so mistakes surface before a round trip. The
server revalidates regardless.

Coordinator responses are escaped before rendering, so a hostile or compromised
API cannot inject markup into the page.

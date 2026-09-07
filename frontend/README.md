# zpay frontend

Static, no build step, no dependencies. The front door (`index.html`), the
takers page (`takers/`) and the app (`app/`) are plain HTML, one stylesheet
and one script each, with Inter and JetBrains Mono self-hosted so no page
makes a third-party request.

## Running it locally

Any static server works. From the repo root, with the coordinator on its
default `127.0.0.1:3000`:

```bash
python3 -m http.server 8080 --directory frontend
```

Open <http://127.0.0.1:8080>. On port 8080 (and 5173, and `file://`) every
page defaults to `http://127.0.0.1:3000` for the API. The coordinator has to
list the page's origin in `[server] allowed_origins` or the browser blocks the
calls.

The app accepts `?api=` to point at a different coordinator; it is saved to
localStorage only when it is loopback. The front door does not accept `?api=`
at all. It reads only, and it reuses whatever loopback the app saved.

Served from the coordinator's own origin, everything calls same-origin paths
and needs no configuration.

## What each page reads

The front door reads three things and never posts:

- `GET /api/stats` every 30 seconds: payments completed, dollars settled,
  open orders, last payment. This is a static snapshot behind a Lambda
  (`infra/public-api/`), not the coordinator.
- `GET /escrow/capabilities` every two minutes: the rate, the limits and the
  spread on the fees table.
- `GET /escrow/quote?amount=X&unit=zec` once per pause in typing. A reply that
  arrives after a newer keystroke is dropped.

Starting a payment hands off to `app/` with `?zec=` and optionally `?venmo=`
prefilled.

The app uses the six `/escrow/*` routes: capabilities, quote, open an order,
read an order, submit a pre-signature, broadcast a refund. Everything
cryptographic happens in `app/escrow.js` in the browser: the user's key, the
redeem script and t3 address, the ZIP 244 digest, the adaptor pre-signature
with its DLEQ proof, and the signed refund. The key lives in the status link's
fragment and in this browser's localStorage, and nowhere else. The page
rebuilds the escrow address from its own key, the LP's key and the refund
height before it shows one, and refuses an order whose address differs.

## The SITE block

The top of `site.js` holds every value the copy leans on: the fee percent, the
outbound links, and the platform list. There is no GitHub link because the
repository is private; when it is public, add it to `links` and give the
markup a `data-link` for it. Every entry in `links` must resolve. Change them
there and both pages update.

## The social card

`og.png` is a screenshot of a 1200x630 HTML page with the hero headline on it.
`og:image`, `twitter:image` and `og:url` carry absolute URLs, because scrapers
do not resolve relative paths. If the domain changes, those three tags in
`index.html` change with it.

## Testing the page's crypto

`app/test/README.md` lists the node scripts that check `escrow.js` against
vectors the Rust crate emits, and the mock coordinator that serves the page
with a timer for a chain. None of it runs under `cargo test`; run it whenever
`escrow.js` changes.

## Deploying

```bash
./scripts/deploy-site.sh
```

Live at <https://zpay.cash/>, with `www.zpay.cash` serving the same
distribution. The CloudFront domain <https://d2acgjt7j1yqe8.cloudfront.net/>
still answers and is what the deploy script prints.

The site is a private S3 bucket (`zpay-site-<account-id>`) behind CloudFront
distribution `<distribution-id>`, which reads it through an origin access
control; the bucket denies everything else, so the S3 URLs are not reachable.
Both hostnames are alternate domain names on the distribution, so CloudFront
terminates TLS for them with an ACM certificate in `us-east-1` (certificates
for CloudFront must live in that region regardless of where anything else
runs). DNS is Cloudflare, and the two records are CNAMEs to the distribution
set to DNS-only: proxying them would put Cloudflare's certificate in front
and hide CloudFront's. CloudFront compresses text on the way out, routes
`/api/*` to the Lambda and `/escrow/*` to the coordinator, and a CloudFront
function appends `index.html` to directory URLs, which an S3 REST origin does
not do on its own.

The script syncs in four passes, because the `Cache-Control` differs by file
and `aws s3 sync` sets one value per invocation:

| pass | files | max-age |
| --- | --- | --- |
| 1 | css, js | 1 day |
| 2 | `fonts/`, `og.png` | 1 year, immutable |
| 3 | html | 60s, must-revalidate |
| 4 | deletes only | |

HTML goes up after the assets it references, so a page is never live pointing
at something that has not landed. The fourth pass removes keys that are gone
from `frontend/`; it exists because the earlier passes filter, and a filtered
`aws s3 sync --delete` skips excluded keys when deciding what to delete. The
invalidation covers the short-TTL paths only, since the year-long assets are
content-stable. `README.md`, `app/test/` and any `shot-*.png` stay local.

Both the bucket and the distribution can be overridden with
`ZPAY_SITE_BUCKET` and `ZPAY_SITE_DISTRIBUTION`.

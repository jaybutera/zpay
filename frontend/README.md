# zpay frontend

Static, no build step, no dependencies. Three pages share one stylesheet and
one script; the app keeps its own.

```
frontend/
  index.html        the front door: hero, live numbers, quote, how it works,
                    custody, fees, limits, taker band
  site.css          palette and layout for the front door and takers/
  site.js           live numbers, the quote widget, the platform picker,
                    and the SITE block every link and number fills from
  fonts/            Inter and JetBrains Mono, latin subsets, self-hosted so
                    the page makes no third-party request
  og.png            the 1200x630 social card the meta tags point at
  takers/index.html how to run the auto-taker daemon
  app/index.html    the offramp terminal: create, watch, manage
  app/app.js        API calls, validation, polling
  app/styles.css    the terminal's own styling
```

## Running

Any static server works. From the repo root, with the coordinator on its
default `127.0.0.1:3000`:

```bash
python3 -m http.server 8080 --directory frontend
```

Open <http://127.0.0.1:8080>. On port 8080 (and 5173, and `file://`) both the
front door and the app default to `http://127.0.0.1:3000` for the API. The
coordinator has to list the page's origin in `[server] allowed_origins` or the
browser blocks the calls.

The app accepts `?api=` to point at a different coordinator, confirmed and not
persisted unless it is loopback. The front door does not accept `?api=` at all;
it reads only, and it reuses whatever loopback the app saved.

Served from the coordinator's own origin, everything calls same-origin paths
and needs no configuration.

## What the front door reads

- `GET /api/stats` every 30 seconds: payments completed, dollars settled, open
  orders, last payment. A static snapshot behind a Lambda, not the coordinator.
- `GET /escrow/capabilities` every two minutes for the rate cell, the quote
  card's header and the spread figure on the fees table.
- `GET /escrow/quote?amount=X&unit=zec` once per pause in typing for the quote
  card itself. A reply that arrives after a newer keystroke is dropped.

Nothing on the front door posts. Starting an offramp hands off to `app/` with
`?zec=` and optionally `?venmo=` prefilled.

## The social card

`og.png` is a screenshot of a 1200x630 HTML page with the hero headline on
it. `og:image`, `twitter:image` and `og:url` carry absolute URLs on the
CloudFront domain, because scrapers do not resolve relative paths. When a real
domain replaces the CloudFront one, those three tags in `index.html` change
with it.

## The SITE block

The top of `site.js` holds every value the copy leans on: the fee percent, the
contract address, the GitHub URLs, the block explorer links, and the platform
list. The repositories do not exist yet; the URLs there are placeholders. The
fee is a placeholder too. Change them there and both pages update.

## App views

**01 / offramp** takes a Venmo handle and a ZEC amount. `get quote` hits
`GET /quote`; `create offramp` posts to `POST /offramp` and jumps to watch.

The API also requires a Base address, a taker address and a ZEC refund address.
Those live under **advanced** and persist in localStorage.

**02 / watch** polls `GET /offramp/{id}` and renders the session as it moves
through the statuses.

**03 / manage** exposes `process`, `rescue` and `withdraw`, each signed by the
session owner's key.

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
and hide CloudFront's. The default `*.cloudfront.net` certificate still
covers the distribution's own domain. CloudFront compresses text on the way
out.

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
content-stable.

`README.md` and the `shot-*.png` screenshots stay local; nothing on the site
links to them.

Both the bucket and the distribution can be overridden with
`ZPAY_SITE_BUCKET` and `ZPAY_SITE_DISTRIBUTION`.

Directory URLs (`/takers/`, `/app/`) work through a CloudFront function that
appends `index.html`; an S3 REST origin does not do that on its own, and the
S3 website endpoint that would cannot sit behind an origin access control.

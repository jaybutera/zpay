/* zpay front door: live numbers, the quote widget, the platform picker.
   Plain ES2020, no build step. Read-only: GET /api/stats for the counters,
   GET /escrow/capabilities for the rate, GET /escrow/quote for the card.
   Nothing here ever posts. */

'use strict';

// ---------- one place to edit ----------
//
// Every link and every number the copy leans on. Change it here, not in the
// markup: both index.html and takers/index.html fill from this block.
const SITE = {
  // Placeholder until the fee is fixed. Rendered everywhere as data-fee.
  feePercent: '0.15',

  // Only destinations that exist. The source repository is private, so there
  // is no GitHub link; add one here when it is public and both pages pick it
  // up. `verifier` is the Base contract whose EIP-712 domain the zk-p2p
  // enclave signs under; nothing is submitted there, the takers page links it
  // as the signing domain.
  links: {
    zkp2p: 'https://zkp2p.xyz',
    zcash: 'https://z.cash',
    verifier: 'https://basescan.org/address/0xC6F4a193576C60892a47e111Bb5706c30162502B',
  },

  // zk-p2p's buyer platform enum, as the enclave enumerates it. Venmo is the
  // one the coordinator registers payees for today.
  platforms: [
    { id: 'venmo',    name: 'Venmo',       on: true },
    { id: 'cashapp',  name: 'Cash App' },
    { id: 'paypal',   name: 'PayPal' },
    { id: 'zelle',    name: 'Zelle' },
    { id: 'wise',     name: 'Wise' },
    { id: 'revolut',  name: 'Revolut' },
    { id: 'monzo',    name: 'Monzo' },
    { id: 'chime',    name: 'Chime' },
    { id: 'monobank', name: 'Monobank' },
    { id: 'alipay',   name: 'Alipay' },
    { id: 'upi',      name: 'UPI' },
  ],
};

// ---------- coordinator base URL ----------
//
// Same resolution as the app, minus ?api=: this page only reads, but it still
// should not be pointed anywhere by a link. A loopback origin saved by the app
// is honoured so a dev setup works out of the box.
const API = (() => {
  let saved = null;
  try { saved = localStorage.getItem('zecp2p.api'); } catch (_) {}
  if (saved) return saved.replace(/\/+$/, '');
  if (location.protocol === 'file:' || location.port === '5173' || location.port === '8080') {
    return 'http://127.0.0.1:3000';
  }
  // Same origin, behind CloudFront's /api/* behaviour. Same-origin means no
  // preflight, and it keeps the read API on the one hostname the page already
  // trusts. It answers /stats from a snapshot.
  return '/api';
})();

// The escrow coordinator's read endpoints. Same origin in production, where
// CloudFront routes /escrow/* to the coordinator; the loopback coordinator
// serves both in a dev setup.
const ESCROW = API === '/api' ? '' : API;

const $ = (id) => document.getElementById(id);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

async function api(path, base = API) {
  const res = await fetch(base + path, { headers: { Accept: 'application/json' } });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    const m = body && (body.error || body.message);
    throw new Error(m ? String(m) : `HTTP ${res.status}`);
  }
  return body;
}

// ---------- fill the static parts ----------

function applySite() {
  $$('[data-fee]').forEach((el) => { el.textContent = SITE.feePercent + '%'; });
  $$('[data-link]').forEach((el) => {
    const href = SITE.links[el.dataset.link];
    if (href) el.href = href;
  });
}

// ---------- number formatting ----------

function usdFromUnits(units) {
  // 6-decimal USDC string -> "$1,234.56". BigInt keeps large totals exact.
  let n;
  try { n = BigInt(String(units)); } catch (_) { return null; }
  const whole = n / 1000000n;
  const cents = (n % 1000000n) / 10000n;
  return '$' + whole.toLocaleString('en-US') + '.' + String(cents).padStart(2, '0');
}

function ago(iso) {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return '';
  const s = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (s < 60) return s + 's ago';
  const m = Math.round(s / 60);
  if (m < 60) return m + 'm ago';
  const h = Math.round(m / 60);
  if (h < 48) return h + 'h ago';
  return Math.round(h / 24) + 'd ago';
}

// ---------- live strip ----------

function setState(el, state, text) {
  if (!el) return;
  el.dataset.state = state;
  const t = el.querySelector('[data-text]');
  if (t) t.textContent = text;
}

async function refreshStats() {
  const conn = $('conn');
  try {
    const s = await api('/stats');
    setState(conn, 'up', 'coordinator up');
    if ($('s-fills')) $('s-fills').textContent = String(s.fulfilled ?? 0);
    if ($('s-settled')) $('s-settled').textContent = usdFromUnits(s.settled_usdc ?? '0') || '—';
    if ($('s-open')) $('s-open').textContent = String(s.open_deposits ?? 0);
    if ($('s-open-sub')) $('s-open-sub').textContent = (s.in_flight ?? 0) + ' in flight';
    if ($('s-last')) $('s-last').textContent = s.last_fulfilled_at ? ago(s.last_fulfilled_at) : 'none yet';
    if ($('s-last-sub')) $('s-last-sub').textContent = "from the coordinator's log";
  } catch (e) {
    setState(conn, 'down', 'coordinator down');
    ['s-fills', 's-settled', 's-open', 's-last'].forEach((id) => { if ($(id)) $(id).textContent = '—'; });
  }
}

function money(n) {
  // 1140.274975 -> "1,140.27". The escrow API sends numbers.
  n = Number(n);
  if (!Number.isFinite(n)) return null;
  return n.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}

function cents(c) {
  // 518 -> "5.18". Integer cents from the escrow quote.
  return money(Number(c) / 100);
}

async function refreshRate() {
  if (!$('s-rate')) return;
  try {
    const c = await api('/escrow/capabilities', ESCROW);
    const r = money(c.rate_usd_per_zec);
    if (r) {
      $('s-rate').textContent = r;
      if ($('s-rate-sub')) $('s-rate-sub').textContent = 'USD per ZEC, market less spread';
      if ($('q-head')) $('q-head').textContent = '1 ZEC = $' + r;
    }
    if (Number.isFinite(c.spread_bps)) {
      $$('[data-spread]').forEach((el) => { el.textContent = (c.spread_bps / 100) + '%'; });
    }
  } catch (_) {
    $('s-rate').textContent = '—';
  }
}

// ---------- quote widget ----------

function validZec(v) {
  return /^\d+(\.\d{1,8})?$/.test(v) && Number(v) > 0;
}

function buildPicker() {
  const menu = $('picker-menu');
  const btn = $('picker-btn');
  if (!menu || !btn) return;

  menu.innerHTML = '';
  SITE.platforms.forEach((p) => {
    const li = document.createElement('li');
    li.setAttribute('role', 'option');
    li.setAttribute('aria-selected', p.on ? 'true' : 'false');
    if (!p.on) li.setAttribute('aria-disabled', 'true');
    const name = document.createElement('span');
    name.className = 'name';
    name.textContent = p.name;
    const tag = document.createElement('span');
    tag.className = 'tag';
    tag.textContent = p.on ? 'live' : 'soon';
    li.append(name, tag);
    if (p.on) li.addEventListener('click', () => close());
    menu.appendChild(li);
  });

  function open() { menu.hidden = false; btn.setAttribute('aria-expanded', 'true'); }
  function close() { menu.hidden = true; btn.setAttribute('aria-expanded', 'false'); }
  btn.addEventListener('click', () => (menu.hidden ? open() : close()));
  document.addEventListener('click', (e) => {
    if (!menu.hidden && !menu.contains(e.target) && e.target !== btn && !btn.contains(e.target)) close();
  });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') close(); });
}

let quoteSeq = 0;

async function getQuote() {
  const input = $('q-zec');
  const note = $('q-note');
  const v = input.value.trim();
  const seq = ++quoteSeq;
  note.className = 'quote-note';
  if (v === '') {
    $('q-out').hidden = true;
    note.textContent = 'type an amount to see what lands in their Venmo';
    return;
  }
  if (!validZec(v)) {
    $('q-out').hidden = true;
    note.textContent = 'Enter a ZEC amount, up to 8 decimal places.';
    note.className = 'quote-note err';
    return;
  }
  note.textContent = 'pricing…';
  try {
    const q = await api('/escrow/quote?amount=' + encodeURIComponent(v) + '&unit=zec', ESCROW);
    if (seq !== quoteSeq) return; // a newer keystroke owns the card now
    const feeCents = (q.lines || []).reduce((t, l) => t + Number(l.cents || 0), 0);
    $('q-fees').textContent = '$' + cents(feeCents);
    $('q-venmo').innerHTML = '';
    const cur = document.createElement('span');
    cur.className = 'cur';
    cur.textContent = '$';
    $('q-venmo').append(cur, document.createTextNode(cents(q.net_cents) || '—'));
    $('q-rate').textContent = money(q.rate_usd_per_zec) || '—';
    $('q-out').hidden = false;
    const exp = q.expires_at ? Date.parse(q.expires_at) : NaN;
    note.textContent = Number.isNaN(exp)
      ? 'priced'
      : 'price held until ' + new Date(exp).toLocaleTimeString();
    note.className = 'quote-note ok';
  } catch (e) {
    if (seq !== quoteSeq) return;
    $('q-out').hidden = true;
    note.textContent = e.message === 'Failed to fetch' ? 'coordinator unreachable; no quote' : e.message;
    note.className = 'quote-note err';
  }
}

function syncStart() {
  const v = $('q-zec').value.trim();
  const ok = validZec(v);
  $('q-start').href = ok ? 'app/?zec=' + encodeURIComponent(v) : 'app/';
  $('q-start').textContent = ok ? 'Start with ' + v + ' ZEC' : 'Continue in the app';
}

// ---------- boot ----------

applySite();
buildPicker();

if ($('q-zec')) {
  let timer = null;
  $('q-zec').addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); clearTimeout(timer); getQuote(); } });
  $('q-zec').addEventListener('input', () => {
    syncStart();
    clearTimeout(timer);
    timer = setTimeout(getQuote, 450);
  });
}

refreshStats();
setInterval(refreshStats, 30000);
refreshRate();
setInterval(refreshRate, 120000);

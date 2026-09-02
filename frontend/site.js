/* zpay front door: live numbers, the quote widget, the platform picker.
   Plain ES2020, no build step. Read-only against the coordinator: GET /stats,
   GET /health, GET /quote. Nothing here ever posts. */

'use strict';

// ---------- one place to edit ----------
//
// Every link and every number the copy leans on. Change it here, not in the
// markup: both index.html and takers/index.html fill from this block.
const SITE = {
  // Placeholder until the fee is fixed. Rendered everywhere as data-fee.
  feePercent: '0.15',

  // OfframpGlue on Base mainnet (chain 8453). /stats overrides this when the
  // coordinator answers, so a redeploy needs no page edit.
  glueContract: '0xafc314Ea35Bb05AaDb254F5B4A8e05db8e7739A9',
  chainId: 8453,

  // Repositories do not exist yet. Swap these when they do.
  links: {
    github: 'https://github.com/zpay-cash/zpay',
    githubTaker: 'https://github.com/zpay-cash/auto-taker',
    zkp2p: 'https://zkp2p.xyz',
    nearIntents: 'https://near-intents.org',
    escrow: 'https://basescan.org/address/0x777777779d229cdF3110e9de47943791c26300Ef',
    orchestrator: 'https://basescan.org/address/0x014025fDE093f8701d86e9f38e2C3a9b779cb5c7',
    verifier: 'https://basescan.org/address/0xC6F4a193576C60892a47e111Bb5706c30162502B',
    stakeVault: 'https://basescan.org/address/0x47c26258222e2f96424bD2B21bf173f0DA5034C7',
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
  return '';
})();

const $ = (id) => document.getElementById(id);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

async function api(path) {
  const res = await fetch(API + path, { headers: { Accept: 'application/json' } });
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
  setContract(SITE.glueContract, SITE.chainId);
}

function setContract(addr, chainId) {
  if (!addr) return;
  $$('[data-contract]').forEach((el) => { el.textContent = addr; });
  $$('[data-contract-link]').forEach((el) => {
    el.href = 'https://basescan.org/address/' + addr;
  });
  $$('[data-chain]').forEach((el) => { el.textContent = 'Base ' + chainId; });
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
    if (s.glue_contract) setContract(s.glue_contract, s.chain_id || SITE.chainId);
  } catch (e) {
    setState(conn, 'down', 'coordinator down');
    ['s-fills', 's-settled', 's-open', 's-last'].forEach((id) => { if ($(id)) $(id).textContent = '—'; });
  }
}

function money(decimalStr) {
  // "48.123456" -> "48.12". The API already formats these as decimal strings.
  const n = Number(decimalStr);
  if (!Number.isFinite(n)) return null;
  return n.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}

async function refreshRate() {
  if (!$('s-rate')) return;
  try {
    const q = await api('/quote?zec_amount=1');
    const r = money(q.rate);
    if (r) {
      $('s-rate').textContent = r;
      if ($('s-rate-sub')) $('s-rate-sub').textContent = 'USDC per ZEC, live from 1Click';
      if ($('q-head')) $('q-head').textContent = '1 ZEC = ' + r + ' USDC';
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
    note.textContent = 'type an amount to see the Venmo payout';
    return;
  }
  if (!validZec(v)) {
    $('q-out').hidden = true;
    note.textContent = 'Enter a ZEC amount, up to 8 decimal places.';
    note.className = 'quote-note err';
    return;
  }
  note.textContent = 'asking 1Click for a route…';
  try {
    const q = await api('/quote?zec_amount=' + encodeURIComponent(v));
    if (seq !== quoteSeq) return; // a newer keystroke owns the card now
    $('q-usdc').textContent = money(q.usdc_amount) + ' USDC';
    $('q-venmo').innerHTML = '';
    const cur = document.createElement('span');
    cur.className = 'cur';
    cur.textContent = '$';
    $('q-venmo').append(cur, document.createTextNode(money(q.venmo_amount) || '—'));
    $('q-rate').textContent = money(q.rate) || '—';
    $('q-out').hidden = false;
    const exp = q.expires_at ? Date.parse(q.expires_at) : NaN;
    note.textContent = Number.isNaN(exp)
      ? 'route found'
      : 'route quoted until ' + new Date(exp).toLocaleTimeString();
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

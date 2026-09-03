/* zpay main route: two fields, a zcash: link, a status link.
   Plain ES2020, no build step, no dependencies.

   The page holds a session key. That is the part worth reading carefully.

   There is no wallet to connect here: the sender pays from a Zcash wallet that
   knows nothing about Base, and the coordinator still needs an address to name
   as session.user, because rescue and withdrawFromZkp2p pay that address and
   nowhere else. So the page generates one 32-byte secret per order and derives
   from it the EVM address, the Zcash transparent refund address, and the
   signature that opens the order.

   The secret lives in the URL fragment of the status link. Fragments are never
   sent to a server, so the coordinator sees the order id and never the key.
   The link the sender is told to keep is therefore the whole recovery story;
   there is nothing else to back up.

   The old page refused to sign in-page, on the grounds that a web page asking
   for a private key is the shape of a wallet drainer. That objection is about
   a key holding the sender's savings. This key is created by the page, holds
   nothing but this order's claim on returned funds, and is never typed. The
   advanced route still never asks for one. */

'use strict';

// ---------- coordinator ----------

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

function esc(v) {
  return String(v === null || v === undefined ? '' : v)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

async function api(path, opts = {}) {
  let res;
  try {
    res = await fetch(API + path, {
      ...opts,
      headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
    });
  } catch (_) {
    throw new Error('Cannot reach zpay right now. Check your connection and try again.');
  }
  const raw = await res.text();
  let body = null;
  if (raw) { try { body = JSON.parse(raw); } catch (_) {} }
  if (!res.ok) {
    const err = new Error((body && (body.error || body.message)) || raw || res.statusText);
    err.status = res.status;
    // The coordinator sends the bridge's real floor alongside the sentence, so
    // the page can convert it and say what to type instead of repeating an
    // upstream category (U1-3).
    if (body && typeof body.min_zatoshi === 'number') err.minZatoshi = body.min_zatoshi;
    throw err;
  }
  return body;
}

function msg(host, kind, text) {
  const el = typeof host === 'string' ? $(host) : host;
  el.innerHTML = '';
  if (!text) return;
  const d = document.createElement('div');
  d.className = 'msg ' + kind;
  d.textContent = text;
  el.appendChild(d);
}

const money = (cents) =>
  '$' + (cents / 100).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });

// ---------- session key ----------
//
// secp256k1 over WebCrypto is not available (WebCrypto has no secp256k1), so
// the curve arithmetic is here. It is the minimum needed to derive a public
// key and make one ECDSA signature: scalar multiplication, and RFC 6979 is
// not used because a random k from crypto.getRandomValues is sound for a
// one-shot key and avoids shipping HMAC-DRBG.

const SECP = {
  p: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn,
  n: 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n,
  a: 0n,
  b: 7n,
  Gx: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
  Gy: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
};

const mod = (x, m) => ((x % m) + m) % m;

function invMod(x, m) {
  // Extended Euclid; x is never 0 where this is called.
  let [old_r, r] = [mod(x, m), m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  return mod(old_s, m);
}

// Points as {x, y} in affine, or null for infinity.
function ptAdd(P, Q) {
  if (!P) return Q;
  if (!Q) return P;
  if (P.x === Q.x && mod(P.y + Q.y, SECP.p) === 0n) return null;
  let lam;
  if (P.x === Q.x && P.y === Q.y) {
    lam = mod(3n * P.x * P.x * invMod(2n * P.y, SECP.p), SECP.p);
  } else {
    lam = mod((Q.y - P.y) * invMod(mod(Q.x - P.x, SECP.p), SECP.p), SECP.p);
  }
  const x = mod(lam * lam - P.x - Q.x, SECP.p);
  return { x, y: mod(lam * (P.x - x) - P.y, SECP.p) };
}

function ptMul(k, P) {
  let R = null;
  let A = P;
  let n = mod(k, SECP.n);
  while (n > 0n) {
    if (n & 1n) R = ptAdd(R, A);
    A = ptAdd(A, A);
    n >>= 1n;
  }
  return R;
}

const G = { x: SECP.Gx, y: SECP.Gy };

const toHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
const fromHex = (hex) => new Uint8Array(hex.match(/.{2}/g).map((h) => parseInt(h, 16)));
const bigToBytes = (n, len) => fromHex(n.toString(16).padStart(len * 2, '0'));
const bytesToBig = (b) => BigInt('0x' + toHex(b));

/** A fresh session key. */
function newSessionKey() {
  let d;
  do {
    const raw = new Uint8Array(32);
    crypto.getRandomValues(raw);
    d = bytesToBig(raw);
  } while (d === 0n || d >= SECP.n);
  return d;
}

/** 33-byte compressed public key, as hex. */
function compressedPubkey(d) {
  const P = ptMul(d, G);
  const prefix = (P.y & 1n) === 0n ? '02' : '03';
  return prefix + P.x.toString(16).padStart(64, '0');
}

// ---------- keccak256, for the EIP-191 digest ----------
//
// Needed because the message the coordinator checks is an EIP-191 personal_sign
// over a fixed string, and that is keccak, not SHA.

const KECCAK_RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];
const KECCAK_ROT = [
  0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];
const M64 = (1n << 64n) - 1n;
const rotl = (x, n) => n === 0 ? x : ((x << BigInt(n)) | (x >> BigInt(64 - n))) & M64;

function keccakF(A) {
  for (let round = 0; round < 24; round++) {
    const C = new Array(5);
    for (let x = 0; x < 5; x++) C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];
    for (let x = 0; x < 5; x++) {
      const D = C[(x + 4) % 5] ^ rotl(C[(x + 1) % 5], 1);
      for (let y = 0; y < 5; y++) A[x + 5 * y] ^= D;
    }
    const B = new Array(25).fill(0n);
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        B[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(A[x + 5 * y], KECCAK_ROT[x + 5 * y]);
      }
    }
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        A[x + 5 * y] = B[x + 5 * y] ^ (~B[((x + 1) % 5) + 5 * y] & B[((x + 2) % 5) + 5 * y] & M64);
      }
    }
    A[0] ^= KECCAK_RC[round];
  }
  return A;
}

function keccak256(bytes) {
  const rate = 136;
  const padded = new Uint8Array(Math.ceil((bytes.length + 1) / rate) * rate);
  padded.set(bytes);
  padded[bytes.length] = 0x01;                 // keccak padding, not SHA-3's 0x06
  padded[padded.length - 1] |= 0x80;

  let A = new Array(25).fill(0n);
  for (let off = 0; off < padded.length; off += rate) {
    for (let i = 0; i < rate / 8; i++) {
      let lane = 0n;
      for (let j = 7; j >= 0; j--) lane = (lane << 8n) | BigInt(padded[off + i * 8 + j]);
      A[i] ^= lane;
    }
    A = keccakF(A);
  }

  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) {
    let lane = A[i];
    for (let j = 0; j < 8; j++) { out[i * 8 + j] = Number(lane & 0xffn); lane >>= 8n; }
  }
  return out;
}

// ---------- ECDSA, EIP-191 ----------

function ecdsaSign(d, digest) {
  const z = bytesToBig(digest);
  for (;;) {
    const kb = new Uint8Array(32);
    crypto.getRandomValues(kb);
    const k = mod(bytesToBig(kb), SECP.n);
    if (k === 0n) continue;

    const R = ptMul(k, G);
    const r = mod(R.x, SECP.n);
    if (r === 0n) continue;

    let s = mod(invMod(k, SECP.n) * (z + r * d), SECP.n);
    if (s === 0n) continue;

    // Low-s, which every EVM verifier requires.
    let recovery = (R.y & 1n) === 0n ? 0 : 1;
    if (s > SECP.n / 2n) { s = SECP.n - s; recovery ^= 1; }

    return toHex(bigToBytes(r, 32)) + toHex(bigToBytes(s, 32)) + (27 + recovery).toString(16).padStart(2, '0');
  }
}

/** The exact bytes crates/zecp2p-coordinator/src/auth.rs recovers from. */
function ownershipMessage(action, address, scope) {
  return `zecp2p:${action}:${address}:${scope}`;
}

function personalSign(d, message) {
  const body = new TextEncoder().encode(message);
  const prefix = new TextEncoder().encode(`\x19Ethereum Signed Message:\n${body.length}`);
  const full = new Uint8Array(prefix.length + body.length);
  full.set(prefix); full.set(body, prefix.length);
  return '0x' + ecdsaSign(d, keccak256(full));
}

/** The EVM address for a session key, formatted exactly as the server writes it.
 *
 * Lowercase, with no EIP-55 checksum. `auth.rs` builds the message it recovers
 * from with alloy's `{:?}`, which prints lowercase hex, and the signature is
 * over those exact bytes. A checksummed address here derives the same key and
 * still fails every signature check, because the string signed would differ
 * from the string verified. That is what the vectors in
 * `frontend/app/test/session-key-vectors.js` exist to catch. */
function evmAddress(d) {
  const P = ptMul(d, G);
  const uncompressed = new Uint8Array(64);
  uncompressed.set(bigToBytes(P.x, 32), 0);
  uncompressed.set(bigToBytes(P.y, 32), 32);
  return '0x' + toHex(keccak256(uncompressed).slice(12));
}

// ---------- order state ----------

const state = {
  key: null,          // BigInt session secret
  orderId: null,
  unit: 'usd',
  quote: null,
  rails: [],
  feeLabel: 'zpay fee',
  poll: null,
  // Cents per whole ZEC from the last quote that succeeded, so a floor
  // rejection can be reported in dollars.
  lastRate: null,
};

/** Put the secret and the order id in the fragment, which no server sees. */
function statusLink(orderId, key) {
  const base = location.origin + location.pathname;
  return `${base}#order=${orderId}&k=${key.toString(16).padStart(64, '0')}`;
}

function readFragment() {
  const raw = location.hash.replace(/^#/, '');
  if (!raw) return null;
  const p = new URLSearchParams(raw);
  const order = p.get('order');
  const k = p.get('k');
  if (!order || !k || !/^[0-9a-f]{64}$/i.test(k)) return null;
  return { orderId: order, key: BigInt('0x' + k) };
}

// ---------- capabilities and the rail picker ----------

async function loadCapabilities() {
  try {
    const caps = await api('/v2/capabilities');
    state.rails = caps.rails || [];
    if (caps.fee && caps.fee.label) state.feeLabel = caps.fee.label;
  } catch (_) {
    // The picker still renders with Venmo alone, so the page works if this
    // call fails; it is a nicety, not a dependency.
    state.rails = [{ id: 'venmo', label: 'Venmo', live: true }];
  }

  const sel = $('rail');
  sel.innerHTML = '';
  for (const r of state.rails) {
    const opt = document.createElement('option');
    opt.value = r.id;
    opt.textContent = r.label;
    opt.disabled = !r.live;
    if (r.live && !sel.value) opt.selected = true;
    sel.appendChild(opt);
  }
  updateRailHint();
}

function updateRailHint() {
  const sel = $('rail');
  const rail = state.rails.find((r) => r.id === sel.value);
  $('rail-hint').textContent = rail && !rail.live
    ? `${rail.label} is not live yet. Venmo is the one that works today.`
    : '';
}

// ---------- quote ----------

let quoteTimer = null;
let expiryTimer = null;

async function doQuote() {
  const amount = $('amount').value.trim();
  if (!amount) { $('quote').hidden = true; return; }

  try {
    const q = await api(
      `/v2/quote?amount=${encodeURIComponent(amount)}&unit=${state.unit}` +
      `&rail=${encodeURIComponent($('rail').value)}`
    );
    state.quote = q;
    // Cents per whole ZEC, kept so a later floor rejection can be quoted in
    // dollars rather than in zatoshi.
    if (q.zec_zatoshi > 0) state.lastRate = q.net_cents / (q.zec_zatoshi / 1e8);
    renderQuote(q);
    msg('compose-msg', '');
  } catch (e) {
    state.quote = null;
    $('quote').hidden = true;
    msg('compose-msg', 'err', floorHint(e) || e.message);
  }
}

// The bridge has a smallest swap it will make, it moves with the ZEC network
// fee, and it is the reason a small amount is refused. Saying the number in the
// unit the sender is typing in is the whole point of carrying it back.
function floorHint(e) {
  if (!e || typeof e.minZatoshi !== 'number') return null;

  const zec = zecString(e.minZatoshi);
  if (state.unit === 'zec') {
    return `That is below the smallest swap this route can make right now. Send at least ${zec} ZEC.`;
  }

  // In dollars, price the floor so the sender is told a dollar amount rather
  // than being asked to convert zatoshi themselves. The rate comes from the
  // last quote that worked; without one, name the ZEC amount.
  const rate = state.lastRate;
  if (!rate) {
    return `That is below the smallest swap this route can make right now. Send at least ${zec} ZEC.`;
  }
  const cents = Math.ceil((e.minZatoshi / 1e8) * rate);
  return `That is below the smallest amount this route can send right now, about ${money(cents)}. Try that or more.`;
}

function renderQuote(q) {
  $('q-net').textContent = money(q.net_cents);

  const ul = $('q-lines');
  ul.innerHTML = '';
  for (const line of q.lines) {
    const li = document.createElement('li');
    li.className = line.is_zpay_fee ? 'fee' : '';
    li.innerHTML = `<span>${esc(line.label)}</span><span>${esc(money(line.cents))}</span>`;
    ul.appendChild(li);
  }

  const mins = Math.round(q.expected_seconds / 60);
  $('q-route').textContent = `${q.route_label} · usually under ${mins} minutes`;
  startCountdown(q.expires_at);
  $('quote').hidden = false;
}

function startCountdown(iso) {
  const el = $('q-expiry');
  if (expiryTimer) clearInterval(expiryTimer);
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) { el.textContent = ''; return; }
  const tick = () => {
    const left = Math.round((t - Date.now()) / 1000);
    if (left <= 0) {
      el.textContent = 'price expired';
      el.classList.add('stale');
      clearInterval(expiryTimer);
    } else {
      el.textContent = `price held ${Math.floor(left / 60)}:${String(left % 60).padStart(2, '0')}`;
      el.classList.remove('stale');
    }
  };
  tick();
  expiryTimer = setInterval(tick, 1000);
}

$('amount').addEventListener('input', () => {
  clearTimeout(quoteTimer);
  quoteTimer = setTimeout(doQuote, 500);
});
$('rail').addEventListener('change', () => { updateRailHint(); doQuote(); });

for (const [id, unit] of [['unit-usd', 'usd'], ['unit-zec', 'zec']]) {
  $(id).addEventListener('click', () => {
    state.unit = unit;
    $('unit-usd').classList.toggle('on', unit === 'usd');
    $('unit-zec').classList.toggle('on', unit === 'zec');
    $('unit-usd').setAttribute('aria-pressed', String(unit === 'usd'));
    $('unit-zec').setAttribute('aria-pressed', String(unit === 'zec'));
    $('amount-sigil').textContent = unit === 'usd' ? '$' : 'ᙇ';
    $('amount').placeholder = unit === 'usd' ? '25' : '0.5';

    // Clear rather than reinterpret. "25" means twenty-five dollars in one
    // unit and about twenty thousand dollars of ZEC in the other, and silently
    // requoting the same digits against the other meaning is how someone sends
    // far more than they meant to.
    $('amount').value = '';
    $('quote').hidden = true;
    state.quote = null;
    if (expiryTimer) clearInterval(expiryTimer);
    $('amount').focus();
  });
}

// ---------- open the order ----------

$('form-pay').addEventListener('submit', async (ev) => {
  ev.preventDefault();

  const handle = $('handle').value.trim().replace(/^@/, '');
  if (handle.length < 2) { msg('compose-msg', 'err', 'Enter the handle that gets paid.'); return; }
  if (!state.quote) { await doQuote(); if (!state.quote) return; }

  const btn = $('btn-pay');
  btn.disabled = true;
  btn.textContent = 'Preparing…';
  msg('compose-msg', '');

  try {
    // One key per order, made here and never sent anywhere.
    state.key = newSessionKey();
    const pubkey = compressedPubkey(state.key);
    const address = evmAddress(state.key);

    const rail = $('rail').value;
    const scope = `${state.quote.quote_id}:${rail}:${handle}`;
    const signature = personalSign(state.key, ownershipMessage('open', address, scope));

    const opened = await api('/v2/orders', {
      method: 'POST',
      headers: { 'x-zecp2p-signature': signature },
      body: JSON.stringify({
        quote_id: state.quote.quote_id,
        destination: { rail, handle },
        session_pubkey: pubkey,
        overrides: {},
      }),
    });

    state.orderId = opened.order_id;
    history.replaceState(null, '', statusLink(opened.order_id, state.key));
    showPayment(opened);
    startPolling();
  } catch (e) {
    msg('compose-msg', 'err', e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Continue';
  }
});

// ---------- the pay screen ----------

function zecString(zat) {
  const whole = Math.floor(zat / 1e8);
  const frac = String(zat % 1e8).padStart(8, '0').replace(/0+$/, '');
  return frac ? `${whole}.${frac}` : String(whole);
}

function showPayment(opened) {
  const d = opened.deposit;
  const amount = `${zecString(d.amount_zat)} ZEC`;

  $('pay-amount').textContent = amount;
  $('pay-amount-2').textContent = amount;
  $('pay-addr').textContent = d.address;
  $('pay-uri').href = d.zip321_uri;
  $('pay-open').href = d.zip321_uri;

  try {
    QR.draw($('qr'), d.zip321_uri);
  } catch (_) {
    // A QR that will not draw must not hide the address underneath it.
    $('qr').hidden = true;
    $('details') && ($('details').open = true);
  }

  $('pay-next').textContent =
    'Once it arrives we swap it, a payer sends the dollars, and their payment is ' +
    'proved before anything is released. Usually under 20 minutes.';

  $('view-compose').hidden = true;
  $('view-pay').hidden = false;
  $('view-status').hidden = false;
}

$('btn-copy-addr').addEventListener('click', () => copyText($('pay-addr').textContent, $('btn-copy-addr'), 'Copy address'));
$('btn-copy-link').addEventListener('click', () => copyText(location.href, $('btn-copy-link'), 'Copy link'));

async function copyText(text, btn, label) {
  try {
    await navigator.clipboard.writeText(text);
    btn.textContent = 'Copied';
  } catch (_) {
    btn.textContent = 'Press ctrl+C';
  }
  setTimeout(() => { btn.textContent = label; }, 2000);
}

// ---------- status ----------

const LADDER = [
  ['awaiting_zec', 'Waiting for your ZEC'],
  ['zec_seen',     'ZEC received'],
  ['in_escrow',    'In escrow'],
  ['paid_out',     'Payment sent'],
  ['done',         'Done'],
];

const RETURN_STAGES = ['returning', 'returned', 'failed'];

function renderStatus(view) {
  const stage = view.timeline.stage;
  const idx = LADDER.findIndex(([k]) => k === stage);

  const ol = $('ladder');
  ol.innerHTML = '';
  LADDER.forEach(([key, label], i) => {
    const li = document.createElement('li');
    li.dataset.state = idx < 0 ? 'todo' : i < idx ? 'done' : i === idx ? 'current' : 'todo';
    if (stage === 'done') li.dataset.state = 'done';
    li.textContent = label;
    ol.appendChild(li);
  });
  ol.hidden = RETURN_STAGES.includes(stage);

  if (stage === 'done') {
    $('status-headline').textContent = `${money(view.quote.net_cents)} landed in @${view.destination.handle}'s Venmo`;
    const fee = view.quote.lines.find((l) => l.is_zpay_fee);
    $('status-sub').textContent = fee ? `Includes the ${fee.label.replace(/^zpay fee /, '').replace(/[()]/g, '')} zpay fee of ${money(fee.cents)}.` : '';
  } else if (idx >= 0) {
    $('status-headline').textContent = LADDER[idx][1];
    $('status-sub').textContent = idx === 0
      ? 'Send the ZEC from your wallet. This page updates on its own.'
      : 'Nothing for you to do. This page updates on its own.';
  }

  renderReturns(view);
  renderDetails(view);
}

/** The failure screen. One field, one answer, and the answer is always ZEC. */
function renderReturns(view) {
  const r = view.returns;
  const box = $('returns');
  const form = $('form-return');

  if (!r || r.state === 'none') { box.hidden = true; return; }
  box.hidden = false;

  switch (r.state) {
    case 'usdc_at':
      // Never shown as something to collect: the sender holds ZEC and has
      // nowhere to put a dollar token. The page converts first and asks after.
      $('returns-title').textContent = 'Sending your ZEC back';
      $('returns-body').textContent =
        'Nobody filled this order, so we are converting the funds back to ZEC. ' +
        'Nothing for you to do yet; this page will ask where to send it.';
      form.hidden = true;
      break;

    case 'swapping_back':
      $('returns-title').textContent = 'Converting back to ZEC';
      $('returns-body').textContent = `About ${zecString(r.expected_zat)} ZEC, on its way.`;
      form.hidden = true;
      break;

    case 'zec_at':
      $('returns-title').textContent = 'Your ZEC came back';
      $('returns-body').textContent =
        `${zecString(r.zatoshi)} ZEC is waiting. Where should it go?`;
      form.hidden = false;
      break;

    case 'refundable_at_height':
      $('returns-title').textContent = 'Your ZEC is refundable';
      $('returns-body').textContent = `Claimable from block ${r.height}. Where should it go?`;
      form.hidden = false;
      break;

    case 'settled':
      $('returns-title').textContent = 'Your ZEC was returned';
      $('returns-body').textContent =
        `${zecString(r.zatoshi)} ZEC went to ${r.address}.`;
      form.hidden = true;
      break;

    default:
      box.hidden = true;
  }
}

// The advanced route is only reachable once there is a session to show it.
function setAdvancedLink(sessionId) {
  const a = $('advanced-link');
  if (!a) return;
  if (sessionId) {
    a.href = 'advanced/?session=' + encodeURIComponent(sessionId);
    a.hidden = false;
  } else {
    a.removeAttribute('href');
    a.hidden = true;
  }
}

function renderDetails(view) {
  const dl = $('detail-kv');
  dl.innerHTML = '';
  const session = (view.timeline.details || []).find(([k]) => k === 'session id');
  setAdvancedLink(session ? session[1] : null);
  for (const [k, v] of view.timeline.details || []) {
    const dt = document.createElement('dt'); dt.textContent = k;
    const dd = document.createElement('dd'); dd.textContent = v;
    dl.appendChild(dt); dl.appendChild(dd);
  }
}

// The client-side check on the return address. It decodes: base58check for
// t1/t3, bech32m for u1, the same decision `near.rs` makes. Length and prefix
// were what this used to check, which accepted `t1AAAA…` (U1-4).
function validZcashAddress(a) {
  return ZAddr.validateZcashAddress(a);
}

$('form-return').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const addr = $('return-addr').value.trim();
  const bad = validZcashAddress(addr);
  if (bad) { msg('return-msg', 'err', bad); return; }

  // Deliberately a stub, and it says so. Nothing is sent and nothing is
  // stored: claiming a return needs a signature from this page over a claim
  // the coordinator does not yet accept. Saying "recorded" would be a lie
  // about where the sender's address went.
  msg('return-msg', 'info',
    'That address is not saved yet. Claiming a return needs a signature from ' +
    'this page, which is still being built. Your ZEC stays claimable from this ' +
    'link, so keep it and check back.');
});

async function fetchStatus() {
  if (!state.orderId) return;
  try {
    const view = await api('/v2/orders/' + encodeURIComponent(state.orderId));
    renderStatus(view);
    if (['done', 'returned', 'failed'].includes(view.timeline.stage)) stopPolling();
  } catch (_) {
    // A failed poll is not worth a scary message; the next one may work.
  }
}

function startPolling() {
  stopPolling();
  fetchStatus();
  state.poll = setInterval(fetchStatus, 5000);
}
function stopPolling() {
  if (state.poll) { clearInterval(state.poll); state.poll = null; }
}

// ---------- health ----------

async function checkHealth() {
  try {
    await api('/health');
    $('conn').dataset.state = 'up';
    $('conn-text').textContent = 'online';
  } catch (_) {
    $('conn').dataset.state = 'down';
    $('conn-text').textContent = 'offline';
  }
}

// ---------- boot ----------

(async function boot() {
  await loadCapabilities();
  checkHealth();
  setInterval(checkHealth, 30000);

  // The launch page's quote widget hands the amount over in the query string,
  // so somebody who priced an order on the front door does not retype it.
  // Values are assigned to inputs, never rendered as markup.
  const params = new URLSearchParams(location.search);
  const deepZec = params.get('zec');
  const deepUsd = params.get('usd');
  const deepHandle = params.get('handle') || params.get('venmo');
  if (deepZec || deepUsd) {
    if (deepZec) $('unit-zec').click();
    $('amount').value = (deepZec || deepUsd).trim();
  }
  if (deepHandle) $('handle').value = deepHandle.trim().replace(/^@/, '');
  if (deepZec || deepUsd) doQuote();

  // Returning to a status link: the key comes back out of the fragment.
  const resumed = readFragment();
  if (resumed) {
    state.orderId = resumed.orderId;
    state.key = resumed.key;
    $('view-compose').hidden = true;
    $('view-status').hidden = false;
    // U1-6. The advanced page reads `?session=` as a session UUID and fetches
    // `/offramp/{id}`. An order id is not a session id, and a main-route order
    // has no session until it is funded, so this link went to "Session not
    // found" every time. It is filled in from the details list once a session
    // exists, and hidden until then.
    setAdvancedLink(null);
    startPolling();
  }
})();

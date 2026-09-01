/* zecp2p frontend — plain ES2020, no build step, no dependencies.
   Talks to the Axum coordinator described in crates/zecp2p-coordinator/src/api.rs */

'use strict';

// ---------- config ----------
// Same-origin by default so this works when the coordinator serves the files.
// Override with ?api=http://host:port , persisted in localStorage.
// A crafted ?api= link used to persist an attacker's coordinator into
// localStorage permanently, and the coordinator is what supplies the ZEC
// deposit address. Loopback still overrides silently, because that is the
// development case; anything else has to be confirmed and is not persisted.
function acceptApiOverride(raw) {
  let url;
  try { url = new URL(raw, location.origin); } catch (_) { return null; }

  const host = (url.hostname || '').replace(/^\[|\]$/g, '');
  const isLoopback = host === 'localhost' || host === '127.0.0.1' || host === '::1';
  if (isLoopback) return { url: raw, persist: true };

  const ok = confirm(
    'This link points the page at a different coordinator:\n\n' + url.origin +
    '\n\nThat server tells you which Zcash address to send funds to. Only ' +
    'continue if you trust it. It will not be remembered.'
  );
  return ok ? { url: raw, persist: false } : null;
}

const API = (() => {
  const q = new URLSearchParams(location.search).get('api');
  if (q) {
    const accepted = acceptApiOverride(q);
    if (accepted) {
      if (accepted.persist) { try { localStorage.setItem('zecp2p.api', accepted.url); } catch (_) {} }
      return accepted.url.replace(/\/+$/, '');
    }
  }
  let saved = null;
  try { saved = localStorage.getItem('zecp2p.api'); } catch (_) {}
  if (saved) return saved.replace(/\/+$/, '');
  // Opened as file:// or from a dev static server -> assume local coordinator.
  if (location.protocol === 'file:' || location.port === '5173' || location.port === '8080') {
    return 'http://127.0.0.1:3000';
  }
  return '';
})();

const $ = (id) => document.getElementById(id);
const API_LABEL = API || location.origin;

// ---------- tiny helpers ----------

// Everything the coordinator returns is treated as untrusted text.
function esc(v) {
  return String(v === null || v === undefined ? '' : v)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
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

function busy(btn, on, label) {
  btn.disabled = on;
  if (on) { btn.dataset.prev = btn.textContent; btn.textContent = label || 'working…'; }
  else if (btn.dataset.prev) { btn.textContent = btn.dataset.prev; delete btn.dataset.prev; }
}

async function api(path, opts = {}) {
  let res;
  try {
    res = await fetch(API + path, {
      ...opts,
      headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
    });
  } catch (_) {
    throw new Error(`Cannot reach coordinator at ${API_LABEL}. Is it running?`);
  }
  const raw = await res.text();
  let body = null;
  if (raw) { try { body = JSON.parse(raw); } catch (_) {} }
  if (!res.ok) {
    // AppError serialises as {error: "..."}; fall back to any string we got.
    const detail = (body && (body.error || body.message)) || raw || res.statusText;
    throw new Error(`${res.status} — ${detail}`);
  }
  return body;
}

// "20.640000" -> "20.64"; leaves non-numeric strings alone
function trimZeros(d) {
  if (typeof d !== 'string' || !/^\d+\.\d+$/.test(d)) return d;
  return d.replace(/0+$/, '').replace(/\.$/, '');
}

// expected_usdc comes back as raw 6-decimal integer string
function fmtUsdcRaw(raw) {
  if (raw === null || raw === undefined || raw === '') return null;
  const n = Number(raw);
  if (!Number.isFinite(n)) return String(raw);
  return (n / 1e6).toFixed(6).replace(/0+$/, '').replace(/\.$/, '') + ' USDC';
}

const nowStamp = () => new Date().toTimeString().slice(0, 8);

// ---------- health ----------

async function checkHealth() {
  const conn = $('conn'), text = $('conn-text');
  try {
    const h = await api('/health');
    conn.dataset.state = 'up';
    text.textContent = (h && h.status === 'ok') ? 'coordinator online' : 'coordinator responding';
  } catch (_) {
    conn.dataset.state = 'down';
    text.textContent = 'coordinator offline';
  }
}

// ---------- tabs ----------

const TABS = [['tab-new','view-new'], ['tab-watch','view-watch'], ['tab-manage','view-manage']];

function showTab(tabId) {
  for (const [t, v] of TABS) {
    const on = t === tabId;
    $(t).setAttribute('aria-selected', String(on));
    $(v).classList.toggle('hidden', !on);
  }
}
for (const [t] of TABS) $(t).addEventListener('click', () => showTab(t));

// ---------- client-side validation mirroring the Rust validators ----------

function validVenmo(u) {
  u = u.trim();
  if (u.length < 2)  return 'Venmo handle is too short (minimum 2 characters).';
  if (u.length > 30) return 'Venmo handle is too long (maximum 30 characters).';
  if (!/^[A-Za-z0-9_-]+$/.test(u)) return 'Venmo handle allows only letters, numbers, underscore and hyphen.';
  return null;
}

function validZec(a) {
  a = a.trim();
  if (!/^\d*\.?\d*$/.test(a) || a === '' || a === '.') return 'Enter a ZEC amount, for example 0.5';
  const parts = a.split('.');
  if (parts[1] && parts[1].length > 8) return 'ZEC amount allows at most 8 decimal places.';
  if (Number(a) <= 0) return 'ZEC amount must be greater than 0.';
  if (Number(a) > 21000000) return 'ZEC amount exceeds maximum supply.';
  return null;
}

function validEvm(a, label) {
  if (!/^0x[0-9a-fA-F]{40}$/.test(a.trim())) return `${label} must be a 0x-prefixed 40-character address.`;
  return null;
}

function validZecAddr(a) {
  a = a.trim();
  if (!/^(t1|t3|zs)/.test(a)) return 'ZEC refund address must start with t1, t3 or zs.';
  if (a[0] === 't' && a.length !== 35) return 'ZEC t-address must be exactly 35 characters.';
  if (a.startsWith('zs') && a.length < 78) return 'ZEC z-address is too short.';
  return null;
}

function mark(el, bad) { el.setAttribute('aria-invalid', bad ? 'true' : 'false'); }

// ---------- quote ----------

let lastQuote = null;

async function doQuote() {
  const zec = $('zec').value.trim();
  const err = validZec(zec);
  mark($('zec'), err);
  if (err) { msg('new-msg', 'err', err); return null; }

  const btn = $('btn-quote');
  busy(btn, true, 'quoting…');
  msg('new-msg', '');
  try {
    const q = await api('/quote?zec_amount=' + encodeURIComponent(zec));
    lastQuote = q;
    $('q-zec').innerHTML   = `${esc(q.zec_amount)}<span class="unit"> ZEC</span>`;
    $('q-usdc').innerHTML  = `${esc(trimZeros(q.usdc_amount))}<span class="unit"> USDC</span>`;
    $('q-venmo').textContent = '$' + q.venmo_amount;
    $('q-rate').textContent  = q.rate;
    renderExpiry(q.expires_at);
    $('quote-box').classList.remove('hidden');

    // Prefill min_rate with a 2% buffer under the quoted rate, if user left it blank.
    const mr = $('min_rate');
    if (!mr.value.trim()) {
      const r = Number(q.rate);
      if (Number.isFinite(r) && r > 0) mr.placeholder = (r * 0.98).toFixed(4) + ' (suggested)';
    }
    return q;
  } catch (e) {
    msg('new-msg', 'err', e.message);
    return null;
  } finally {
    busy(btn, false);
  }
}

let expiryTimer = null;
function renderExpiry(iso) {
  const el = $('q-expiry');
  if (expiryTimer) clearInterval(expiryTimer);
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) { el.textContent = ''; return; }
  const tick = () => {
    const left = Math.round((t - Date.now()) / 1000);
    if (left <= 0) {
      el.textContent = 'quote expired — request a new one';
      el.classList.add('stale');
      clearInterval(expiryTimer);
    } else {
      el.textContent = `quote valid for ${Math.floor(left / 60)}m ${String(left % 60).padStart(2, '0')}s`;
      el.classList.remove('stale');
    }
  };
  tick();
  expiryTimer = setInterval(tick, 1000);
}

$('btn-quote').addEventListener('click', doQuote);

// Re-quote when the amount changes and a quote is already on screen.
let quoteDebounce = null;
$('zec').addEventListener('input', () => {
  if ($('quote-box').classList.contains('hidden')) return;
  clearTimeout(quoteDebounce);
  quoteDebounce = setTimeout(doQuote, 600);
});

// ---------- remembered advanced fields ----------

const ADV_KEYS = ['user_address', 'taker_address', 'zec_refund_address', 'min_rate', 'timeout_seconds'];

function loadAdv() {
  let saved;
  try { saved = JSON.parse(localStorage.getItem('zecp2p.adv') || '{}'); } catch (_) { return; }
  let any = false;
  for (const k of ADV_KEYS) if (saved[k]) { $(k).value = saved[k]; any = true; }
  if (any) $('adv').open = false;
}

$('btn-remember').addEventListener('click', () => {
  const out = {};
  for (const k of ADV_KEYS) out[k] = $(k).value.trim();
  try {
    localStorage.setItem('zecp2p.adv', JSON.stringify(out));
    msg('new-msg', 'ok', 'Saved to this browser only. Nothing was sent anywhere.');
  } catch (_) {
    msg('new-msg', 'err', 'Browser storage is unavailable, so these were not saved.');
  }
});

$('btn-forget').addEventListener('click', () => {
  try { localStorage.removeItem('zecp2p.adv'); } catch (_) {}
  for (const k of ADV_KEYS) $(k).value = '';
  msg('new-msg', 'info', 'Cleared saved addresses from this browser.');
});

// ---------- create offramp ----------

$('form-new').addEventListener('submit', async (ev) => {
  ev.preventDefault();

  const venmo = $('venmo').value.trim().replace(/^@/, '');
  const zec   = $('zec').value.trim();
  const user  = $('user_address').value.trim();
  const taker = $('taker_address').value.trim();
  const refund= $('zec_refund_address').value.trim();
  const minR  = $('min_rate').value.trim();
  const tmo   = $('timeout_seconds').value.trim();

  const checks = [
    [validVenmo(venmo), $('venmo')],
    [validZec(zec), $('zec')],
    [validEvm(user, 'Your Base address'), $('user_address')],
    [validEvm(taker, 'Taker address'), $('taker_address')],
    [validZecAddr(refund), $('zec_refund_address')],
  ];
  let firstErr = null;
  for (const [e, el] of checks) { mark(el, e); if (e && !firstErr) firstErr = [e, el]; }
  if (minR && !(Number(minR) > 0)) firstErr = firstErr || ['Min rate must be a positive number.', $('min_rate')];
  if (tmo && !/^\d+$/.test(tmo))   firstErr = firstErr || ['Timeout must be a whole number of seconds.', $('timeout_seconds')];

  if (firstErr) {
    msg('new-msg', 'err', firstErr[0]);
    // Open the advanced section if the offending field lives inside it.
    if (ADV_KEYS.includes(firstErr[1].id)) $('adv').open = true;
    firstErr[1].focus();
    return;
  }

  // Opening a session names the Base address that rescue and withdraw will pay,
  // so the coordinator requires a signature from that address. Without it,
  // anyone could open a session naming someone else, which is how a
  // caller-supplied user_address became a way to reach a victim's funds. This
  // page holds no key and should not ask for one: a web page asking you to
  // paste a private key is the shape of every wallet drainer. The CLI signs
  // locally, so it does this part.
  //
  // Everything else here still works: quote, status, and watching a session.
  msg('new-msg', 'err',
    'Opening a session has to be signed by the wallet you want paid back, and ' +
    'this page holds no key. Run:\n\n' +
    `  zecp2p offramp ${zec} --venmo ${venmo} --zec-address ${refund}` +
    (minR ? ` --min-rate ${minR}` : '') +
    '\n\nwith ZECP2P_USER_PRIVATE_KEY set, then paste the session id here to ' +
    'watch it.');
});

// ---------- status ladder ----------

const STEPS = [
  ['created',             'session created',    'coordinator registered the session on-chain'],
  ['near_intent_pending', 'awaiting zec',       'send ZEC to the deposit address'],
  ['usdc_received',       'usdc received',      'NEAR Intent settled into the GlueContract'],
  ['zkp2p_deposited',     'zk-p2p escrow',      'USDC deposited to the zk-p2p escrow'],
  ['intent_signaled',     'taker signaled',     'a taker committed to pay your Venmo'],
  ['fulfilled',           'venmo paid',         'payment proven and released'],
];

const TERMINAL = { failed: 'bad', rescued: 'warn', withdrawn: 'warn', fulfilled: 'ok' };

function renderLadder(status) {
  const ol = $('ladder');
  ol.innerHTML = '';
  const idx = STEPS.findIndex((s) => s[0] === status);
  const dead = status === 'failed';

  STEPS.forEach(([key, label, note], i) => {
    let state = 'todo', glyph = '·';
    if (idx >= 0) {
      if (i < idx)      { state = 'done';    glyph = '✓'; }
      else if (i === idx) {
        if (status === 'fulfilled') { state = 'done'; glyph = '✓'; }
        else { state = 'current'; glyph = '▮'; }
      }
    } else if (dead) {
      state = 'todo';
    }
    const li = document.createElement('li');
    li.dataset.state = state;
    li.innerHTML = `<span class="mark">${glyph}</span>
      <span><span class="step-label">${label}</span><br><span class="step-note">${note}</span></span>`;
    ol.appendChild(li);
  });

  if (TERMINAL[status] && status !== 'fulfilled') {
    const li = document.createElement('li');
    li.dataset.state = status === 'failed' ? 'dead' : 'todo';
    const text = status === 'failed' ? 'session failed — try rescue or withdraw'
      : status === 'rescued' ? 'funds rescued to your Base address'
      : 'funds withdrawn from zk-p2p escrow';
    li.innerHTML = `<span class="mark">${status === 'failed' ? '✕' : '■'}</span>
      <span><span class="step-label">${esc(status)}</span><br><span class="step-note">${esc(text)}</span></span>`;
    ol.appendChild(li);
  }
}

let lastStatus = null;

function render(r) {
  $('watch-out').classList.remove('hidden');

  const tone = TERMINAL[r.status] || (r.status === 'created' || r.status === 'near_intent_pending' ? 'live' : 'live');
  const usdc = fmtUsdcRaw(r.expected_usdc);

  const rows = [
    ['session id', esc(r.session_id)],
    ['status', `<span class="pill" data-tone="${esc(tone)}">${esc(r.status)}</span>`],
  ];
  if (usdc) rows.push(['expected usdc', esc(usdc)]);
  if (r.error) rows.push(['error', esc(r.error)]);

  $('watch-kv').innerHTML = rows
    .map(([k, v]) => `<div class="rowline"><span class="k">${k}</span><span class="v">${v}</span></div>`)
    .join('');

  renderLadder(r.status);

  const box = $('deposit-box');
  if (r.near_deposit_address) {
    $('deposit-addr').textContent = r.near_deposit_address;
    box.classList.remove('hidden');
  } else {
    box.classList.add('hidden');
  }

  if (r.status !== lastStatus) {
    logLine(`status → ${r.status}`);
    lastStatus = r.status;
    if (r.error) logLine(`error: ${r.error}`);
  }
}

function logLine(text) {
  const log = $('log');
  const d = document.createElement('div');
  d.innerHTML = `<span class="t">[${nowStamp()}]</span> ${esc(text)}`;
  log.appendChild(d);
  log.scrollTop = log.scrollHeight;
}

// ---------- polling ----------

let pollTimer = null;
let pollId = null;

async function fetchOnce(id, quiet) {
  try {
    const r = await api('/offramp/' + encodeURIComponent(id));
    render(r);
    if (!quiet) msg('watch-msg', '');
    if (TERMINAL[r.status]) stopPolling(`session reached terminal state: ${r.status}`);
    return r;
  } catch (e) {
    msg('watch-msg', 'err', e.message);
    stopPolling();
    return null;
  }
}

function startPolling(id) {
  stopPolling();
  pollId = id;
  pollTimer = setInterval(() => fetchOnce(id, true), 5000);
  logLine('polling every 5s');
}

function stopPolling(note) {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; logLine(note || 'polling stopped'); }
}

$('form-watch').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const id = $('session_id').value.trim();
  if (!id) { msg('watch-msg', 'err', 'Enter a session id.'); return; }
  $('manage_id').value = id;
  lastStatus = null;
  msg('watch-msg', '');
  const r = await fetchOnce(id, false);
  if (r && !TERMINAL[r.status]) startPolling(id);
});

$('btn-refresh').addEventListener('click', () => {
  const id = $('session_id').value.trim() || pollId;
  if (id) fetchOnce(id, false);
});

$('btn-stop').addEventListener('click', () => stopPolling('polling stopped by user'));

$('btn-copy').addEventListener('click', async () => {
  const addr = $('deposit-addr').textContent;
  const btn = $('btn-copy');
  try {
    await navigator.clipboard.writeText(addr);
    btn.textContent = 'copied';
  } catch (_) {
    // Clipboard API needs a secure context; select the text instead.
    const range = document.createRange();
    range.selectNodeContents($('deposit-addr'));
    const sel = getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
    btn.textContent = 'selected — press ctrl+c';
  }
  setTimeout(() => { btn.textContent = 'copy address'; }, 2000);
});

// ---------- manage actions ----------

// Rescue and withdraw move a session's USDC, so the coordinator requires a
// signature from the address the session names, and the contract will only pay
// that address. This page holds no key and never should: a browser page asking
// for one is the shape of every wallet-drainer. The CLI signs locally, and with
// --self-signed it sends the transaction itself, which is the path that still
// works if this coordinator is gone.
const SIGNED_ACTIONS = {
  rescue: 'zecp2p rescue <session-id> --private-key <your key>',
  withdraw: 'zecp2p withdraw <session-id> --private-key <your key>',
  process: 'zecp2p status <session-id>',
};

async function manageAction(kind, btn, confirmText) {
  const id = $('manage_id').value.trim() || $('session_id').value.trim();
  if (!id) { msg('manage-msg', 'err', 'Enter a session id first.'); return; }

  if (SIGNED_ACTIONS[kind]) {
    msg('manage-msg', 'err',
      `${kind} has to be signed by the wallet that owns this session, and this page ` +
      `holds no key. Run:\n\n  ${SIGNED_ACTIONS[kind].replace('<session-id>', id)}\n\n` +
      (kind === 'process' ? '' :
       `Add --self-signed --glue <address> to send it straight to Base without the coordinator.`));
    return;
  }

  if (confirmText && !confirm(confirmText)) return;

  busy(btn, true, kind + '…');
  msg('manage-msg', '');
  try {
    const r = await api(`/offramp/${encodeURIComponent(id)}/${kind}`, { method: 'POST' });
    msg('manage-msg', 'ok', `${kind} accepted — session is now ${r.status}.`);
    $('session_id').value = id;
    logLine(`${kind} → ${r.status}`);
    render(r);
    showTab('tab-watch');
    if (!TERMINAL[r.status]) startPolling(id);
  } catch (e) {
    msg('manage-msg', 'err', e.message);
  } finally {
    busy(btn, false);
  }
}

$('btn-process').addEventListener('click', (e) => manageAction('process', e.currentTarget));
$('btn-rescue').addEventListener('click', (e) => manageAction('rescue', e.currentTarget,
  'Rescue returns USDC from the GlueContract to your Base address and ends this session. Continue?'));
$('btn-withdraw').addEventListener('click', (e) => manageAction('withdraw', e.currentTarget,
  'Withdraw pulls USDC out of the zk-p2p escrow and ends this session. Continue?'));

// ---------- boot ----------

$('api-base-label').textContent = API_LABEL;
loadAdv();
checkHealth();
setInterval(checkHealth, 30000);

// Deep link: ?session=<uuid> opens straight into watch.
const deepSession = new URLSearchParams(location.search).get('session');
if (deepSession) {
  $('session_id').value = deepSession;
  $('manage_id').value = deepSession;
  showTab('tab-watch');
  fetchOnce(deepSession, false).then((r) => { if (r && !TERMINAL[r.status]) startPolling(deepSession); });
}

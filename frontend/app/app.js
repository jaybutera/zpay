/* zpay main route, native Zcash escrow.

   Two fields, one address, a status link. What is different from a page that
   merely shows an address is that this page is a party to the escrow:

   - It draws the user's key `u` and derives the t3 address itself, from `u`,
     the payer's key and the refund height. The coordinator's answer is checked
     against that derivation, never trusted, so the address on screen is one
     whose timeout branch the page's own key can spend.
   - Once the ZEC has confirmed and the attestor has announced, it rebuilds the
     canonical terms from what it already knew, compares them to the payer's,
     computes the ZIP 244 digest of the release, and hands over an adaptor
     pre-signature. A term the payer changed is refused before anything is
     signed. See escrow.js and the vectors under test/.
   - If nobody pays, it signs the refund at height T with `u` alone and hands
     the bytes to any node.

   The key lives in the URL fragment, which no server sees, and in this
   browser's localStorage. There is no other copy. */

'use strict';

// ---------- coordinator ----------

const API = (() => {
  let saved = null;
  try { saved = localStorage.getItem('zecp2p.api'); } catch (_) {}
  const q = new URLSearchParams(location.search).get('api');
  if (q) { try { localStorage.setItem('zecp2p.api', q); } catch (_) {} return q.replace(/\/+$/, ''); }
  if (saved) return saved.replace(/\/+$/, '');
  if (location.protocol === 'file:' || location.port === '5173' || location.port === '8080') {
    return 'http://127.0.0.1:3000';
  }
  return '';
})();

/* The attestor key this page trusts, per network. The coordinator relays the
   attestor's announcement, so a coordinator that could also name the attestor
   could name one it controls; the pin is what stops that, and it has to come
   from somewhere the coordinator cannot reach.

   This one did: the private key is held off the hub, and the public key below
   is the point it multiplies out to. It was checked that way rather than by
   reading it back from /escrow/capabilities, which is the coordinator
   vouching for itself. On a test network the announced key is accepted. */
const PINS = {
  main: { attestor_pubkey: '0258603ee5702d5e571a19b08312e94d0eedd85df7405135cf4a02b2227f18c218' },
};

const $ = (id) => document.getElementById(id);
const E = Escrow;

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
  if (!res.ok) throw new Error((body && (body.error || body.message)) || raw || res.statusText);
  return body;
}

function msg(host, kind, text, action) {
  const el = typeof host === 'string' ? $(host) : host;
  el.innerHTML = '';
  if (!text) return;
  const d = document.createElement('div');
  d.className = 'msg ' + kind;
  d.textContent = text;
  if (action) {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'btn small';
    b.textContent = action.label;
    b.addEventListener('click', action.run);
    d.appendChild(document.createElement('br'));
    d.appendChild(b);
  }
  el.appendChild(d);
}

const money = (cents) =>
  '$' + (cents / 100).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
const zec = (zat) => E.zecString(zat) + ' ZEC';
const shortHex = (h) => h.length > 20 ? `${h.slice(0, 10)}…${h.slice(-8)}` : h;

// ---------- state ----------

const state = {
  caps: null,
  unit: 'zec',
  quote: null,
  key: null,          // BigInt u_priv
  orderId: null,
  record: null,       // what localStorage holds for this order
  order: null,        // last view from the coordinator
  presign: 'idle',    // idle | signing | sent | failed
  poll: null,
};

// ---------- the record: what the page must keep before the user sends ----------

const RECORD_PREFIX = 'zpay.escrow.';

function saveRecord(rec) {
  try { localStorage.setItem(RECORD_PREFIX + rec.orderId, JSON.stringify(rec)); } catch (_) {}
}
/** Rebuild the record from the coordinator's view of an order.
 *
 * The record normally comes from this browser: it is written when the order is
 * opened, and it is what `presign` and the refund are built from. A status
 * link opened anywhere else - another browser, another device, after the site
 * data was cleared - has the key in the fragment and no record, and every
 * field the record holds is also in the order view.
 *
 * The view cannot simply be believed, because these are the terms that get
 * signed. So the escrow address is derived again from the key in the fragment
 * and the numbers the view supplies, and the record is only returned if it
 * comes back to the address the escrow actually holds. A view that named a
 * different refund height, amount or payer key derives a different address and
 * is refused here rather than signed.
 */
function recordFromView(orderId, key, view) {
  const esc = view && view.escrow;
  if (!esc) return null;

  const uPub = E.pubkey(key);
  if (E.toHex(uPub) !== String(esc.u_pub || '').toLowerCase()) return null;

  const network = view.network || 'main';
  const redeem = E.redeemScript(uPub, E.fromHex(esc.l_pub), esc.refund_height);
  if (E.escrowAddress(redeem, network) !== esc.address) return null;

  return {
    orderId,
    network,
    uPriv: key.toString(16).padStart(64, '0'),
    uPub: E.toHex(uPub),
    lPub: esc.l_pub,
    refundHeight: esc.refund_height,
    amountZat: esc.amount_zat,
    address: esc.address,
    redeemScript: E.toHex(redeem),
    usdAmount6dec: esc.usd_amount_6dec,
    payeeHash: esc.payee_hash,
    platformFeeZat: esc.platform_fee_zat || 0,
    treasuryScript: esc.treasury_script || '',
    handle: (view.destination || {}).handle || '',
    createdAt: new Date().toISOString(),
    rebuiltFromView: true,
  };
}

function loadRecord(orderId) {
  try {
    const raw = localStorage.getItem(RECORD_PREFIX + orderId);
    return raw ? JSON.parse(raw) : null;
  } catch (_) { return null; }
}

function statusLink(orderId, key) {
  return `${location.origin}${location.pathname}#order=${encodeURIComponent(orderId)}&k=${key.toString(16).padStart(64, '0')}`;
}
function readFragment() {
  const raw = location.hash.replace(/^#/, '');
  if (!raw) return null;
  const p = new URLSearchParams(raw);
  const order = p.get('order');
  const k = p.get('k');
  if (!order) return null;
  return { orderId: order, key: k && /^[0-9a-f]{64}$/i.test(k) ? BigInt('0x' + k) : null };
}

// ---------- capabilities ----------

async function loadCapabilities() {
  try {
    state.caps = await api('/escrow/capabilities');
  } catch (e) {
    state.caps = null;
    $('q-note').textContent = 'zpay is not reachable from this page yet.';
    $('q-note').className = 'quote-note err';
    return;
  }
  const c = state.caps;
  if (c.network && c.network !== 'main') {
    $('net-tag').textContent = c.network === 'test' ? 'testnet' : c.network;
    $('net-tag').hidden = false;
  }
  if (c.fee && typeof c.fee.bps === 'number') {
    const pct = (c.fee.bps / 100).toFixed(2) + '%';
    document.querySelectorAll('[data-fee]').forEach((el) => { el.textContent = pct; });
  }
  if (c.rate_usd_per_zec) $('rate-head').textContent = `1 ZEC = $${Number(c.rate_usd_per_zec).toFixed(2)}`;
  const venmo = (c.rails || []).find((r) => r.id === 'venmo');
  if (venmo && venmo.live === false) $('rail-hint').textContent = 'Venmo is paused right now.';
}

// ---------- quote ----------

let quoteTimer = null;
let expiryTimer = null;

async function doQuote() {
  const amount = $('amount').value.trim();
  if (!amount) { $('q-out').hidden = true; state.quote = null; return; }
  if (!/^\d*\.?\d*$/.test(amount) || Number(amount) <= 0) {
    note('err', 'Enter a number.');
    return;
  }
  try {
    const q = await api(`/escrow/quote?amount=${encodeURIComponent(amount)}&unit=${state.unit}`);
    state.quote = q;
    renderQuote(q);
    note('', '');
  } catch (e) {
    state.quote = null;
    $('q-out').hidden = true;
    note('err', e.message);
  }
}

function note(kind, text) {
  const el = $('q-note');
  el.className = 'quote-note ' + kind;
  el.textContent = text || (kind || state.quote ? '' : 'type an amount to see what lands in their Venmo');
}

function renderQuote(q) {
  $('q-net').textContent = money(q.net_cents);
  const ul = $('q-lines');
  ul.innerHTML = '';
  const add = (label, right, cls) => {
    const li = document.createElement('li');
    li.className = cls || '';
    const a = document.createElement('span'); a.textContent = label;
    const b = document.createElement('span'); b.textContent = right;
    li.appendChild(a); li.appendChild(b);
    ul.appendChild(li);
  };
  add('you send', zec(q.amount_zat));
  for (const line of q.lines || []) add(line.label, money(line.cents), line.is_zpay_fee ? 'fee' : '');
  if (q.rate_usd_per_zec) add('rate', `$${Number(q.rate_usd_per_zec).toFixed(2)} / ZEC`);
  $('q-route').textContent = `${q.route_label || 'escrow on Zcash'} · usually under ${Math.max(1, Math.round((q.expected_seconds || 1200) / 60))} minutes`;
  startCountdown(q.expires_at);
  $('q-out').hidden = false;
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
  quoteTimer = setTimeout(doQuote, 400);
});

/** What the amount field means, which is not the same in both units. */
function setAmountLabel(unit) {
  const el = $('amount-label');
  if (el) el.textContent = unit === 'usd' ? 'they receive' : 'you send';
}
setAmountLabel(state.unit);

for (const [id, unit] of [['unit-zec', 'zec'], ['unit-usd', 'usd']]) {
  $(id).addEventListener('click', () => {
    if (state.unit === unit) return;
    state.unit = unit;
    $('unit-zec').classList.toggle('on', unit === 'zec');
    $('unit-usd').classList.toggle('on', unit === 'usd');
    $('unit-zec').setAttribute('aria-pressed', String(unit === 'zec'));
    $('unit-usd').setAttribute('aria-pressed', String(unit === 'usd'));
    $('amount').placeholder = unit === 'usd' ? '25' : '0.5';
    // The two units mean different sides of the trade. In dollars the number
    // is what the payee receives and the fees are added to the ZEC asked for;
    // in ZEC it is what leaves the wallet. Labelling both "you send" said the
    // opposite of the "lands in their Venmo" figure directly below it.
    setAmountLabel(unit);
    // Clear rather than reinterpret: "25" means twenty-five dollars in one
    // unit and about a thousand dollars of ZEC in the other.
    $('amount').value = '';
    $('q-out').hidden = true;
    state.quote = null;
    if (expiryTimer) clearInterval(expiryTimer);
    note('', '');
    $('amount').focus();
  });
}

// ---------- open the order ----------

const HANDLE_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{1,29}$/;

$('form-pay').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const handle = $('handle').value.trim().replace(/^@/, '');
  if (!HANDLE_RE.test(handle)) { note('err', 'Enter their Venmo username: letters, digits, - and _.'); return; }
  if (!state.caps) { note('err', 'zpay is not reachable from this page yet.'); return; }
  if (!state.quote) { await doQuote(); if (!state.quote) return; }

  const btn = $('btn-pay');
  btn.disabled = true;
  btn.textContent = 'Making your key…';
  note('', '');

  try {
    // One key per order, made here and never sent anywhere.
    const key = E.randomScalar();
    const uPub = E.pubkey(key);

    const opened = await api('/escrow/orders', {
      method: 'POST',
      body: JSON.stringify({
        quote_id: state.quote.quote_id,
        u_pub: E.toHex(uPub),
        destination: { rail: 'venmo', handle },
      }),
    });

    const esc = opened.escrow;
    const network = opened.network || state.caps.network;
    // The address is derived here, not read. The coordinator can only be
    // agreed with, and an escrow whose refund branch this key cannot spend is
    // refused before anyone sends to it.
    const lPub = E.fromHex(esc.l_pub);
    if (state.caps.l_pub && esc.l_pub !== state.caps.l_pub) {
      throw new Error('The payer key in the order is not the one this page was given. Nothing was sent.');
    }
    const redeem = E.redeemScript(uPub, lPub, esc.refund_height);
    const derived = E.escrowAddress(redeem, network);
    if (derived !== esc.address) {
      throw new Error('The address zpay returned is not the escrow this page derived. Nothing was sent.');
    }
    if (esc.amount_zat !== state.quote.amount_zat) {
      throw new Error('The order amount is not the quoted amount. Nothing was sent.');
    }

    state.key = key;
    state.orderId = opened.order_id;
    state.record = {
      orderId: opened.order_id,
      network,
      uPriv: key.toString(16).padStart(64, '0'),
      uPub: E.toHex(uPub),
      lPub: esc.l_pub,
      refundHeight: esc.refund_height,
      amountZat: esc.amount_zat,
      address: esc.address,
      redeemScript: E.toHex(redeem),
      usdAmount6dec: esc.usd_amount_6dec,
      payeeHash: esc.payee_hash,
      platformFeeZat: esc.platform_fee_zat || 0,
      treasuryScript: esc.treasury_script || '',
      handle,
      createdAt: new Date().toISOString(),
    };
    // Stored before the address is shown, so a crash between here and the
    // user's wallet still leaves a refundable escrow (spec 5.3).
    saveRecord(state.record);
    state.presign = 'idle';
    history.replaceState(null, '', statusLink(opened.order_id, key));
    showOrder(opened);
    startPolling();
  } catch (e) {
    note('err', e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Get the address';
  }
});

// ---------- the order view ----------

function showOrder(view) {
  const esc = view.escrow;
  const uri = esc.zip321_uri || E.zip321(esc.address, esc.amount_zat);
  $('pay-amount').textContent = zec(esc.amount_zat);
  $('pay-addr').textContent = esc.address;
  $('pay-uri').href = uri;
  $('pay-open').href = uri;
  $('pay-to').textContent = view.quote ? `@${view.destination.handle} gets ${money(view.quote.net_cents)}.` : '';
  try {
    QR.draw($('qr'), uri);
  } catch (_) {
    $('qr').hidden = true;
  }
  $('view-compose').hidden = true;
  $('view-order').hidden = false;
  render(view);
}

const LADDER = [
  ['awaiting_zec', 'Send the ZEC'],
  ['confirming', 'ZEC confirms'],
  ['locked', 'Escrow locks'],
  ['paid', 'Payer sends the dollars'],
  ['released', 'Escrow releases'],
];
const STAGE_INDEX = {
  awaiting_zec: 0, confirming: 1, needs_presignature: 2, locked: 3, paid: 4, released: 5,
};
const RETURN_STAGES = ['unpaid', 'refundable', 'refunded', 'failed'];

function render(view) {
  state.order = view;
  const stage = view.stage;
  const esc = view.escrow;
  const f = view.funding;
  const handle = view.destination ? view.destination.handle : (state.record && state.record.handle) || '';
  const net = view.quote ? money(view.quote.net_cents) : '';

  $('pay-block').hidden = stage !== 'awaiting_zec';
  $('stage-block').hidden = stage === 'awaiting_zec';
  $('keep-link').hidden = ['released', 'refunded'].includes(stage);
  $('keep-open').hidden = !['awaiting_zec', 'confirming', 'needs_presignature'].includes(stage);

  // ladder
  const idx = STAGE_INDEX[stage];
  const ol = $('ladder');
  ol.innerHTML = '';
  ol.hidden = RETURN_STAGES.includes(stage);
  LADDER.forEach(([key, label], i) => {
    const li = document.createElement('li');
    li.dataset.state = idx === undefined ? 'todo' : i < idx ? 'done' : i === idx ? 'current' : 'todo';
    if (stage === 'released') li.dataset.state = 'done';
    const n = document.createElement('span'); n.className = 'n'; n.textContent = String(i + 1).padStart(2, '0');
    const t = document.createElement('span'); t.textContent = label;
    const side = document.createElement('span'); side.className = 'side';
    if (key === 'confirming' && f && stage === 'confirming') side.textContent = f.mempool ? 'in the mempool' : `${f.confirmations} / ${f.required}`;
    if (key === 'locked' && stage === 'needs_presignature') side.textContent = state.presign === 'signing' ? 'signing…' : state.presign === 'failed' ? 'not signed' : 'signing';
    if (key === 'paid' && view.payment) side.textContent = money(view.payment.cents);
    li.appendChild(n); li.appendChild(t); li.appendChild(side);
    ol.appendChild(li);
  });

  // headline
  const live = $('order-live');
  live.dataset.state = '';
  let head = 'status', liveText = '', headline = '', sub = '';
  switch (stage) {
    case 'awaiting_zec':
      head = 'send'; liveText = 'waiting for your ZEC';
      break;
    case 'confirming':
      liveText = 'confirming';
      headline = 'ZEC received, confirming';
      // `confirmations: 0` on a mined output cannot happen, so a zero here is
      // either a mempool sighting or nothing at all. The coordinator marks the
      // first with `mempool`, and without reading it this line said "0 of 10
      // confirmations" for a transaction in no block, and quoted a countdown
      // off a first confirmation that has not happened. The wait until mining
      // is not a number of blocks, so it is not given as one.
      sub = !f ? ''
        : f.mempool ? 'Your transaction is in the mempool, waiting to be mined. Leave this page open.'
        : `${f.confirmations} of ${f.required} confirmations. About ${Math.ceil(((f.required - f.confirmations) * (state.caps && state.caps.block_seconds || 75)) / 60)} minutes.`;
      break;
    case 'needs_presignature':
      liveText = 'locking';
      headline = 'Locking the escrow';
      sub = state.key
        ? 'This page is signing the release. It takes a moment.'
        : 'Open the link you kept, in this browser, so the page can sign. Nothing is lost.';
      break;
    case 'locked':
      liveText = 'locked';
      headline = 'Escrow locked';
      sub = 'A payer can now send the dollars. Usually under 20 minutes. Nothing for you to do.';
      break;
    case 'paid':
      liveText = 'proving';
      headline = `Dollars sent to @${handle}`;
      sub = 'Their payment is being proved. The escrow releases against that proof and nothing else.';
      break;
    case 'released':
      live.dataset.state = 'done'; liveText = 'done';
      headline = net ? `${net} landed in @${handle}'s Venmo` : `Paid @${handle}`;
      sub = view.release ? `Released on Zcash in ${shortHex(view.release.txid)}.` : '';
      break;
    case 'unpaid':
      live.dataset.state = 'bad'; liveText = 'nobody paid';
      headline = 'Nobody paid';
      break;
    case 'refundable':
      live.dataset.state = 'bad'; liveText = 'refundable';
      headline = 'Your ZEC is refundable';
      break;
    case 'refunded':
      live.dataset.state = 'done'; liveText = 'refunded';
      headline = 'Your ZEC went back';
      sub = view.refund ? `In ${shortHex(view.refund.txid)}.` : '';
      break;
    case 'failed':
      live.dataset.state = 'bad'; liveText = 'stopped';
      headline = 'This order stopped';
      sub = view.reason || '';
      break;
    default:
      liveText = stage;
      headline = stage;
  }
  $('order-head').textContent = head;
  $('order-live-text').textContent = liveText;
  $('stage-headline').textContent = headline;
  $('stage-sub').textContent = sub;

  renderReturns(view);
  renderDetails(view);

  // A status link opened in another browser has the key but no record, and
  // everything the pre-signature needs is in this view. Rebuilding it here -
  // against the key, checked by re-deriving the escrow address - is what lets
  // that link still sign. Without it `presign` read `rec.amountZat` off null.
  if (!state.record && state.key && state.orderId) {
    const rebuilt = recordFromView(state.orderId, state.key, view);
    if (rebuilt) {
      state.record = rebuilt;
      saveRecord(rebuilt);
    }
  }

  if (stage === 'needs_presignature' && state.key && state.presign === 'idle') presign(view);
  // `failed` keeps polling until T: the page has to notice when the refund
  // becomes possible, and the coordinator moves the stage to `refundable` on
  // the sweep that crosses it. Stopping here left a stopped order frozen on a
  // screen that never offered the refund.
  // A height of 0 means the coordinator could not read the chain. It makes
  // this false, so the page keeps polling - which is the safe direction: it
  // would rather ask again than stop on a screen that never offers the refund.
  const h = view.current_height || 0;
  const pastT = h > 0 && h >= view.escrow.refund_height;
  if (['released', 'refunded'].includes(stage) || (stage === 'failed' && pastT)) stopPolling();
}

// ---------- the pre-signature ----------

async function presign(view) {
  state.presign = 'signing';
  msg('order-msg', '');
  try {
    // Last line before the terms are built. `renderStatus` rebuilds the record
    // from the view when this browser has none, so a null here means that
    // rebuild refused: the key in the link does not derive the escrow this
    // order names. Signing on it anyway would sign somebody else's terms.
    const rec = state.record;
    if (!rec) {
      throw new Error(
        'This link does not match the escrow zpay is describing, so this page will not sign it. ' +
        'Open the original status link, and if this keeps happening your ZEC stays refundable from it.'
      );
    }
    const caps = state.caps || {};
    const network = view.network || rec.network;
    const a = view.announcement;
    if (!a || !view.funding) throw new Error('The announcement has not arrived yet.');

    let pinned = (PINS[network] || {}).attestor_pubkey;
    if (network === 'main') {
      if (!pinned) {
        throw new Error('This page has no attestor key pinned for mainnet, so it will not sign. Your ZEC stays refundable from this link at block ' + Number(rec.refundHeight).toLocaleString() + '.');
      }
    } else {
      pinned = pinned || a.P;
    }

    const prepared = E.prepareEscrow(
      {
        uPriv: state.key,
        amountZat: rec.amountZat,
        lPub: E.fromHex(rec.lPub),
        refundHeight: rec.refundHeight,
        usdAmount6dec: rec.usdAmount6dec,
        payeeHash: E.fromHex(rec.payeeHash),
        platformFeeZat: rec.platformFeeZat,
        treasuryScript: E.fromHex(rec.treasuryScript || ''),
      },
      {
        // Explorers and RPCs print txids reversed; the terms carry internal order.
        fundingTxid: E.reversed(E.fromHex(view.funding.txid)),
        vout: view.funding.vout,
        consensusBranchId: view.consensus_branch_id,
      },
      a.terms,
      { P: E.fromHex(a.P), R: E.fromHex(a.R), eventId: E.fromHex(a.event_id) },
      E.fromHex(pinned),
      { lpOutputScript: E.fromHex(a.lp_output_script), minerFeeZat: a.miner_fee_zat },
    );

    // The chain facts go into the record now, so the refund can be rebuilt
    // from this browser alone if the coordinator is never seen again.
    state.record = {
      ...rec,
      fundingTxid: view.funding.txid,
      vout: view.funding.vout,
      consensusBranchId: view.consensus_branch_id,
      termsHash: E.toHex(prepared.termsHash),
      preSignedAt: new Date().toISOString(),
    };
    saveRecord(state.record);

    await api(`/escrow/orders/${encodeURIComponent(state.orderId)}/presign`, {
      method: 'POST',
      body: JSON.stringify({
        pre_signature: E.toHex(prepared.preSignature),
        terms_hash: E.toHex(prepared.termsHash),
        u_pub: rec.uPub,
      }),
    });
    state.presign = 'sent';
    void caps;
    fetchStatus();
  } catch (e) {
    state.presign = 'failed';
    msg('order-msg', 'err', e.message, { label: 'Try again', run: () => { state.presign = 'idle'; fetchStatus(); } });
    render(view);
  }
}

// ---------- returns: the refund at T ----------

/* The screen a stopped order gets when the dollars may already have gone.
 *
 * Three stages can reach it - `unpaid`, `refundable` and the `failed` default -
 * and all three have to decide it the same way, on the boolean the view carries
 * rather than on `view.payment`. Only one of the four failure writers that
 * follow a journal claim records a payment on the order; the other three leave
 * it null while the journal holds an open line. R5-1 was that read on two of
 * the branches; R6-1 was the third branch not reading it at all.
 *
 * The wording is "may already have been sent", not "were already sent" (R6-2).
 * The boolean is true on an open `Paying` line, on `NeedsOperator`, and on a
 * journal the coordinator could not read at all - and in every one of those the
 * truth is "may have", which is what the driver's own reason string above it
 * says. The action the page takes is the same either way: this one needs a
 * person, not a button.
 */
function needsAPerson(view) {
  return view.fiat_may_have_left || view.payment;
}

function sayItNeedsAPerson(view, tail) {
  $('returns-title').textContent = 'This one needs a person';
  $('returns-body').textContent =
    `${view.reason ? view.reason + ' ' : ''}The dollars for this order may already have been ` +
    `sent, so the refund is not yours to take on your own${tail} Keep this link and get in touch.`;
  $('form-return').hidden = true;
}

function renderReturns(view) {
  const box = $('returns');
  const form = $('form-return');
  const out = $('return-out');
  const stage = view.stage;
  if (!RETURN_STAGES.includes(stage) && stage !== 'failed') { box.hidden = true; return; }
  box.hidden = false;
  out.hidden = !out.dataset.raw;

  const T = view.escrow.refund_height;
  // 0 means the coordinator could not read the chain, not that the chain is at
  // genesis. Treated as a height it renders the wait as T blocks - about eighty
  // years on mainnet - and says it with a confident "about". Unknown is a
  // different thing from far away, and the page says so.
  const now = view.current_height || 0;
  const heightKnown = now > 0;
  const blocks = heightKnown ? Math.max(0, T - now) : null;
  const hours = heightKnown
    ? (blocks * ((state.caps && state.caps.block_seconds) || 75)) / 3600
    : null;
  const whenText = heightKnown
    ? `about ${hours < 1 ? Math.ceil(hours * 60) + ' minutes' : hours.toFixed(1) + ' hours'} from now`
    : 'zpay cannot reach the Zcash network to say when';

  switch (stage) {
    case 'unpaid':
      // R6-1: the same question the other two branches ask, asked here too.
      //
      // No driver path produces an `unpaid` order with the boolean true.
      // `Unpaid` is written only by `check_deadlines`, and every call of it
      // that follows a reservation follows a retract to `Cancelled`, which
      // reads false. The guard is here so that stays true by construction
      // rather than by the next writer having to re-derive the argument - the
      // view carries the answer for every stage, and a branch that ignores it
      // is the one that will be wrong when the set of writers changes.
      if (needsAPerson(view)) { sayItNeedsAPerson(view, '.'); break; }
      // R5-2's page half. The coordinator has asked the chain what became of
      // this escrow's only evidence of funding - a transaction seen in the
      // mempool - and been told nothing is there: it expired unmined and no
      // wallet resent it, so the coins never left the user's own wallet.
      //
      // Without this the screen below says "N ZEC is in the escrow" over an
      // empty one and shows the form. The builder then makes a refund spending
      // an outpoint no block holds, taken from the view or from this page's own
      // record of the signing, the endpoint refuses it for want of a funding it
      // never learned, and the page tells the user any node will accept bytes
      // no node will. There is nothing to refund and nothing to wait for; the
      // only honest thing to say is that the payment never arrived.
      if (view.escrow_is_empty) {
        $('returns-title').textContent = 'Your ZEC never arrived';
        $('returns-body').textContent =
          'The transaction that would have funded this escrow never confirmed, so nothing ' +
          'was ever sent to it and there is nothing here to come back. Your coins are still ' +
          'in your own wallet. Start again whenever you like.';
        form.hidden = true;
        break;
      }
      // Past T the coordinator moves this to `refundable`, but the page must
      // not depend on having seen that: it can be opened at any moment, and
      // the chain is the authority on whether the timeout branch is spendable.
      if (heightKnown && blocks === 0) {
        $('returns-title').textContent = 'Where should your ZEC go?';
        $('returns-body').textContent =
          `Nobody sent the dollars, and block ${T.toLocaleString()} has passed. ` +
          `${zec(view.escrow.amount_zat)} is in the escrow and this page signs the refund ` +
          'with your key; no one else is involved.';
        form.hidden = !state.key;
        if (!state.key) $('returns-body').textContent += ' Open the link you kept so this page can sign.';
      } else {
        $('returns-title').textContent = 'Your ZEC comes back to you';
        $('returns-body').textContent =
          `Nobody sent the dollars in time. Your coins are refundable at block ${T.toLocaleString()}, ` +
          `${whenText}. Only your key can take them, and it is in this page. Nothing to do until then.`;
        form.hidden = true;
      }
      break;
    case 'refundable':
      // Same guard as the stopped branch, one stage along. The coordinator now
      // promotes finished orders to `refundable`, so this is where a user whose
      // dollars already went would land - and offering the form here would be
      // this page telling them to race a release the LP holds.
      if (needsAPerson(view)) { sayItNeedsAPerson(view, '.'); break; }
      $('returns-title').textContent = 'Where should your ZEC go?';
      // R4-3: the reason survives the promotion to `refundable`, and it is the
      // only place the user learns why the trade stopped. A page opened after
      // the sweep never saw the `failed` screen that carried it.
      $('returns-body').textContent =
        `${view.reason ? view.reason + ' ' : ''}` +
        `${zec(view.escrow.amount_zat)} is in the escrow and block ${T.toLocaleString()} has passed. ` +
        'This page signs the refund with your key; no one else is involved.';
      form.hidden = !state.key;
      if (!state.key) $('returns-body').textContent += ' Open the link you kept so this page can sign.';
      break;
    case 'refunded':
      $('returns-title').textContent = 'Refund sent';
      $('returns-body').textContent = view.refund ? `Transaction ${view.refund.txid}.` : '';
      form.hidden = true;
      break;
    default:
      // `failed`, and anything else that stops the trade with the escrow still
      // funded. The refund is owed exactly as it is on `unpaid`: the coin is
      // the user's, the timeout branch pays it out at T, and hiding the form
      // here is what left a stopped order with no way back to it.
      //
      // Unless the dollars already went. `failed` is also what the coordinator
      // writes when the Venmo payment left and the release did not broadcast,
      // and there the LP holds a valid release over this same escrow. Offering
      // the form would be this page telling the user to race it - and the loss
      // on that race is the LP's, so the page would be steering them into
      // spending against the party that already paid them. That case needs a
      // person, not a button.
      $('returns-title').textContent = 'This order stopped';
      // Keyed on the journal, not on `view.payment`. Only one of the four
      // failure writers that follow a journal claim records a payment on the
      // order; the other three leave it null while the journal says the
      // dollars may be gone. Reading `payment` here offered the form on
      // exactly the failures the sweep withholds the promotion for.
      if (needsAPerson(view)) {
        sayItNeedsAPerson(view, ' - zpay has to settle this one by hand.');
        break;
      }
      if (heightKnown && blocks === 0) {
        $('returns-body').textContent =
          `${view.reason ? view.reason + ' ' : ''}Block ${T.toLocaleString()} has passed, so ` +
          `${zec(view.escrow.amount_zat)} can come back to you now. This page signs the refund ` +
          'with your key.';
        form.hidden = !state.key;
        if (!state.key) $('returns-body').textContent += ' Open the link you kept so this page can sign.';
      } else {
        $('returns-body').textContent =
          `${view.reason ? view.reason + ' ' : ''}Your ZEC is refundable at block ` +
          `${T.toLocaleString()}, ${whenText}. Only your key can take it, and it is in this page.`;
        form.hidden = true;
      }
  }
}

$('form-return').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const addr = $('return-addr').value.trim();
  const view = state.order;
  const rec = state.record;
  const btn = $('btn-return');
  msg('order-msg', '');
  let script;
  try {
    script = E.scriptForAddress(addr, view.network || rec.network);
  } catch (e) {
    msg('order-msg', 'err', e.message);
    return;
  }
  btn.disabled = true;
  try {
    // The LIVE view wins over the saved record for the outpoint.
    //
    // The record's outpoint is whatever this page saw when it signed. Under a
    // mempool announcement that is the unconfirmed transaction, and Zcash
    // expires an unmined transaction after 40 blocks - so a wallet that resends
    // produces a different txid, the coordinator learns it, and a refund built
    // over the saved one spends an outpoint that never existed on chain. No
    // node would take it, while this page told the user any node would.
    //
    // The record is still the fallback, for the case it was written for: a view
    // that has not caught up, or an order this page knows more about than the
    // coordinator has served yet.
    const f = view.funding || {};
    const fundingTxid = f.txid || rec.fundingTxid;
    const vout = f.vout !== undefined ? f.vout : rec.vout;
    const branch = view.consensus_branch_id || rec.consensusBranchId;
    if (!fundingTxid || branch === undefined) throw new Error('The funding transaction is not known to this page yet.');

    const terms = E.escrowTerms({
      fundingTxid: E.reversed(E.fromHex(fundingTxid)), vout,
      amountZat: rec.amountZat, uPub: E.fromHex(rec.uPub), lPub: E.fromHex(rec.lPub), refundHeight: rec.refundHeight,
    }, branch);
    const fee = E.refundFeeTransparent(terms.redeemScript.length);
    const signed = E.signRefund(state.key, terms, script, fee);
    const rawHex = E.toHex(signed.raw);
    const txidHex = E.toHex(E.reversed(signed.txid));

    const out = $('return-out');
    out.dataset.raw = rawHex;
    $('return-raw').textContent = rawHex;
    out.hidden = false;

    try {
      await api(`/escrow/orders/${encodeURIComponent(state.orderId)}/refund`, {
        method: 'POST',
        body: JSON.stringify({ raw_tx: rawHex, txid: txidHex, address: addr }),
      });
      msg('order-msg', 'ok', `Refund broadcast. ${zec(rec.amountZat - fee)} to ${addr}, transaction ${txidHex}.`);
      $('form-return').hidden = true;
      fetchStatus();
    } catch (e) {
      msg('order-msg', 'err', `zpay could not broadcast it: ${e.message}\nThe signed transaction is below; any Zcash node accepts it after block ${rec.refundHeight.toLocaleString()}.`);
    }
  } catch (e) {
    msg('order-msg', 'err', e.message);
  } finally {
    btn.disabled = false;
  }
});

// ---------- details ----------

function renderDetails(view) {
  const dl = $('detail-kv');
  dl.innerHTML = '';
  const rows = [];
  const esc = view.escrow;
  rows.push(['order', view.order_id]);
  rows.push(['escrow', esc.address]);
  rows.push(['amount', zec(esc.amount_zat)]);
  rows.push(['refund height', String(esc.refund_height)]);
  if (view.current_height) rows.push(['chain height', String(view.current_height)]);
  if (view.funding) rows.push(['funding', `${view.funding.txid}:${view.funding.vout}${view.funding.mempool ? ' (in the mempool)' : ''}`]);
  if (view.announcement) rows.push(['terms hash', view.announcement.terms_hash || '']);
  if (view.payment) rows.push(['venmo', `${money(view.payment.cents)} at ${view.payment.sent_at}`]);
  if (view.release) rows.push(['release', view.release.txid]);
  if (view.refund) rows.push(['refund', view.refund.txid]);
  if (state.record) rows.push(['your key', 'held in this page and in the link']);
  for (const [k, v] of rows) {
    const dt = document.createElement('dt'); dt.textContent = k;
    const dd = document.createElement('dd'); dd.textContent = v;
    dl.appendChild(dt); dl.appendChild(dd);
  }
}

// ---------- copy ----------

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

// ---------- polling ----------

async function fetchStatus() {
  if (!state.orderId) return;
  try {
    const view = await api('/escrow/orders/' + encodeURIComponent(state.orderId));
    if ($('view-order').hidden) showOrder(view); else render(view);
  } catch (e) {
    // A failed poll is not worth a scary message; the next one may work.
  }
}

function startPolling() {
  stopPolling();
  fetchStatus();
  state.poll = setInterval(fetchStatus, 4000);
}
function stopPolling() {
  if (state.poll) { clearInterval(state.poll); state.poll = null; }
}

// ---------- health ----------

async function checkHealth() {
  try {
    await api('/health');
    $('conn').dataset.state = 'up';
    $('conn-text').textContent = 'coordinator up';
  } catch (_) {
    $('conn').dataset.state = 'down';
    $('conn-text').textContent = 'coordinator down';
  }
}

// ---------- boot ----------

(async function boot() {
  await loadCapabilities();
  checkHealth();
  setInterval(checkHealth, 30000);

  // The front door hands the amount over in the query string.
  const params = new URLSearchParams(location.search);
  const deepZec = params.get('zec');
  const deepUsd = params.get('usd');
  const deepHandle = params.get('handle') || params.get('venmo');
  if (deepUsd && !deepZec) $('unit-usd').click();
  if (deepZec || deepUsd) $('amount').value = (deepZec || deepUsd).trim();
  if (deepHandle) $('handle').value = deepHandle.trim().replace(/^@/, '');
  if (deepZec || deepUsd) doQuote();

  // Returning to a status link: the key comes back out of the fragment, and
  // the record out of this browser.
  const resumed = readFragment();
  if (resumed) {
    state.orderId = resumed.orderId;
    state.record = loadRecord(resumed.orderId);
    state.key = resumed.key || (state.record ? BigInt('0x' + state.record.uPriv) : null);
    if (state.key && !state.record) {
      // The link came from another browser. The refund still needs the chain
      // facts, which the coordinator's view supplies; the key is enough.
      state.record = null;
    }
    startPolling();
  }
})();

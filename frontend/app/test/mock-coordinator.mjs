/* A stand-in for the coordinator's native-escrow API, for driving the page
   locally. Not a backend. It is the LP's side of the protocol run in
   JavaScript with fixed keys, so the page can be walked from a quote to a
   released escrow (or to a refund) without a Zcash node, an attestor or a
   Venmo account.

   What is real: the payer key, the attestor's announcement and outcome
   scalar, the terms, the pre-signature check, adaptor decryption, the
   assembled release transaction and its txid, all computed with escrow.js.
   What is fake: the chain. Funding "confirms" on a timer, the payment is a
   timestamp, and no node ever sees a transaction.

   Every release it assembles is written to MOCK_OUT_DIR as JSON that
   `cargo run -p zecp2p-escrow --example frontend_vectors -- check-release`
   verifies against the crate: it recomputes the digest and runs the scriptSig
   through the consensus interpreter.

     node frontend/app/test/mock-coordinator.mjs           # http://127.0.0.1:8787/app/
     MOCK_STEP_MS=1000 node frontend/app/test/mock-coordinator.mjs

   A handle of `nobody-pays` runs the abandoned-escrow path instead. */

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const HERE = path.dirname(fileURLToPath(import.meta.url));
const E = require(path.join(HERE, '..', 'escrow.js'));
const SITE = path.resolve(HERE, '..', '..');

const PORT = Number(process.env.MOCK_PORT || 8787);
const STEP = Number(process.env.MOCK_STEP_MS || 2500);
const OUT_DIR = process.env.MOCK_OUT_DIR || '';

// ---------- fixed identities ----------

const NETWORK = 'test';
const L_PRIV = E.scalarFromBytes(E.fromHex('22'.repeat(32)));
const L_PUB = E.pubkey(L_PRIV);
const ATTESTOR_D = E.scalarFromBytes(E.fromHex('d1'.repeat(32)));
const ATTESTOR_P = E.pubkey(ATTESTOR_D);
const LP_PAYOUT = 'tmVHejhMFq979Z7oRwseWMW7snYoQsj22yn';
const TREASURY = 'tmVHejhMFq979Z7oRwseWMW7snYoQsj22yn';
const LP_SCRIPT = E.scriptForAddress(LP_PAYOUT, NETWORK);
const TREASURY_SCRIPT = E.scriptForAddress(TREASURY, NETWORK);

const BRANCH_ID = 0x37a5165b;
const BLOCK_SECONDS = 75;
const REFUND_DELAY = 1152;
const FEE_BPS = 20;
const RATE_USD_PER_ZEC = 40.25;
const MIN_ZAT = 120_000;
const MAX_ZAT = 5_000_000_000;

let height = 3_470_700;

const requiredDepth = (usd6) => usd6 <= 50_000_000 ? 10 : usd6 <= 500_000_000 ? 30 : 100;
const platformFee = (zat) => { const f = Math.floor((zat * FEE_BPS) / 10_000); return f < 54 ? 0 : f; };
// The redeem script is 115 bytes at present heights; the fee depends only on
// its length, which the quote can know before the user's key exists.
const REDEEM_LEN = E.redeemScript(L_PUB, L_PUB, 3_472_000).length;

// ---------- quotes and orders ----------

const quotes = new Map();
const orders = new Map();
let seq = 1;

function quoteFor(amount, unit) {
  const n = Number(amount);
  if (!(n > 0)) throw new Error('Enter a number.');
  let amountZat;
  if (unit === 'usd') amountZat = Math.round((n / RATE_USD_PER_ZEC) * 1e8);
  else amountZat = Math.round(n * 1e8);
  if (amountZat < MIN_ZAT) throw new Error(`The smallest escrow is ${E.zecString(MIN_ZAT)} ZEC.`);
  if (amountZat > MAX_ZAT) throw new Error(`The largest escrow right now is ${E.zecString(MAX_ZAT)} ZEC.`);
  const fee = platformFee(amountZat);
  const miner = E.releaseFee(REDEEM_LEN, fee > 0 ? 2 : 1);
  const grossCents = Math.round((amountZat / 1e8) * RATE_USD_PER_ZEC * 100);
  const feeCents = Math.round((fee / 1e8) * RATE_USD_PER_ZEC * 100);
  const minerCents = Math.round((miner / 1e8) * RATE_USD_PER_ZEC * 100);
  const netCents = grossCents - feeCents - minerCents;
  if (netCents < 100) throw new Error('That is under a dollar after fees.');
  const id = 'q' + (seq++).toString(36) + Math.random().toString(36).slice(2, 8);
  const q = {
    quote_id: id,
    amount_zat: amountZat,
    gross_cents: grossCents,
    net_cents: netCents,
    usd_amount_6dec: netCents * 10_000,
    platform_fee_zat: fee,
    miner_fee_zat: miner,
    rate_usd_per_zec: RATE_USD_PER_ZEC,
    lines: [
      { label: `zpay fee (${(FEE_BPS / 100).toFixed(2)}%)`, cents: feeCents, is_zpay_fee: true },
      { label: 'zcash network fee', cents: minerCents, is_zpay_fee: false },
    ],
    route_label: 'escrow on Zcash',
    expected_seconds: 1200,
    expires_at: new Date(Date.now() + 5 * 60_000).toISOString(),
  };
  quotes.set(id, q);
  return q;
}

function openOrder(body) {
  const q = quotes.get(body.quote_id);
  if (!q) throw new Error('That quote has expired. Type the amount again.');
  const handle = String((body.destination || {}).handle || '').replace(/^@/, '');
  if (!/^[A-Za-z0-9][A-Za-z0-9_-]{1,29}$/.test(handle)) throw new Error('That is not a Venmo username.');
  const uPub = E.fromHex(String(body.u_pub || ''));
  E.pointFromBytes(uPub); // must be a point

  const refundHeight = height + REFUND_DELAY;
  const redeem = E.redeemScript(uPub, L_PUB, refundHeight);
  const address = E.escrowAddress(redeem, NETWORK);
  const payeeHash = E.sha256(E.ascii('venmo:' + handle.toLowerCase()));
  const id = 'esc_' + (seq++).toString(36) + Math.random().toString(36).slice(2, 10);

  const o = {
    id, createdAt: Date.now(), handle, scenario: handle === 'nobody-pays' ? 'abandon' : 'paid',
    quote: q, uPub, redeem, address, refundHeight, payeeHash,
    funding: null, announcement: null, presig: null, presignedAt: null, payment: null, release: null, refund: null,
    stage: 'awaiting_zec', k: E.randomScalar(),
  };
  orders.set(id, o);
  return view(o);
}

function fundingTxidFor(o) {
  // Internal order; explorers print it reversed.
  return E.sha256(E.ascii('mock funding for ' + o.id));
}

/** Advances the fake chain for one order, based on elapsed time. */
function tick(o) {
  const t = Date.now() - o.createdAt;
  const required = requiredDepth(o.quote.usd_amount_6dec);
  if (o.stage === 'awaiting_zec' && t >= STEP) {
    o.funding = { txid: fundingTxidFor(o), vout: 0, confirmations: 0, required, seenAt: Date.now() };
    o.stage = 'confirming';
  }
  if (o.stage === 'confirming') {
    o.funding.confirmations = Math.min(required, Math.floor((Date.now() - o.funding.seenAt) / STEP) * 4);
    if (o.funding.confirmations >= required) {
      const lockConfirmedMs = Date.now();
      const canonical = {
        fundingTxid: o.funding.txid, vout: 0, amountZat: o.quote.amount_zat,
        uPub: o.uPub, lPub: L_PUB, refundHeight: o.refundHeight,
        usdAmount6dec: o.quote.usd_amount_6dec, rate18dec: E.IDENTITY_RATE_18DEC, payeeHash: o.payeeHash,
        lockConfirmedMs, platformFeeZat: o.quote.platform_fee_zat,
        treasuryScript: o.quote.platform_fee_zat > 0 ? TREASURY_SCRIPT : new Uint8Array(0),
      };
      const event = E.eventId(o.funding.txid, 0);
      const tHash = E.termsHash(canonical);
      const R = E.mulG(o.k);
      o.announcement = {
        canonical, event, tHash, R,
        Y: E.outcomePoint(R, E.pointFromBytes(ATTESTOR_P), event, tHash),
      };
      const terms = E.escrowTerms(canonical, BRANCH_ID);
      const split = { payoutScript: LP_SCRIPT, minerFeeZat: o.quote.miner_fee_zat, platformFeeZat: o.quote.platform_fee_zat, treasuryScript: canonical.treasuryScript };
      o.releaseTx = E.buildRelease(terms, split);
      o.digest = E.sighash(o.releaseTx);
      o.terms = terms;
      o.stage = 'needs_presignature';
    }
  }
  if (o.stage === 'locked' && o.scenario === 'paid' && Date.now() - o.presignedAt >= STEP) {
    o.payment = { sent_at: new Date().toISOString(), cents: o.quote.net_cents };
    o.stage = 'paid';
  }
  if (o.stage === 'paid' && Date.now() - o.presignedAt >= 2 * STEP && !o.release) {
    // The attestor signs, the LP decrypts and broadcasts.
    const s = E.signOutcome(o.k, ATTESTOR_D, o.announcement.event, o.announcement.tHash);
    const sigU = E.adaptorDecrypt(o.presig, s);
    if (!E.ecdsaVerify(E.pointFromBytes(o.uPub), o.digest, sigU)) throw new Error('mock: decrypted signature does not verify');
    const sigL = E.ecdsaSign(L_PRIV, o.digest);
    const scriptSig = E.releaseScriptSig(E.encodeSignature(sigU), E.encodeSignature(sigL), o.redeem);
    const raw = E.serialize(o.releaseTx, scriptSig);
    const txid = E.txid(o.releaseTx);
    o.release = { txid, raw };
    o.stage = 'released';
    height += 1;
    if (OUT_DIR) {
      const run = {
        funding_txid: E.toHex(o.funding.txid), vout: 0, amount_zat: o.quote.amount_zat,
        u_pub: E.toHex(o.uPub), l_pub: E.toHex(L_PUB), refund_height: o.refundHeight, consensus_branch_id: BRANCH_ID,
        lp_output_script: E.toHex(LP_SCRIPT), miner_fee_zat: o.quote.miner_fee_zat,
        platform_fee_zat: o.quote.platform_fee_zat, treasury_script: E.toHex(o.announcement.canonical.treasuryScript),
        pre_signature: E.toHex(o.presig), outcome_point: E.toHex(E.pointToBytes(o.announcement.Y)),
        outcome_secret: s.toString(16).padStart(64, '0'),
        release_script_sig: E.toHex(scriptSig), release_raw: E.toHex(raw), release_txid: E.toHex(txid),
      };
      fs.mkdirSync(OUT_DIR, { recursive: true });
      fs.writeFileSync(path.join(OUT_DIR, `release-${o.id}.json`), JSON.stringify(run, null, 2));
    }
  }
  if (o.stage === 'locked' && o.scenario === 'abandon' && Date.now() - o.presignedAt >= STEP) {
    o.stage = 'unpaid';
  }
  if (o.stage === 'unpaid' && Date.now() - o.presignedAt >= 3 * STEP) {
    height = Math.max(height, o.refundHeight);
    o.stage = 'refundable';
  }
}

const hexRev = (b) => E.toHex(E.reversed(b));

function view(o) {
  tick(o);
  const a = o.announcement;
  return {
    order_id: o.id,
    network: NETWORK,
    consensus_branch_id: BRANCH_ID,
    stage: o.stage,
    current_height: height,
    destination: { rail: 'venmo', handle: o.handle },
    quote: { net_cents: o.quote.net_cents, gross_cents: o.quote.gross_cents, lines: o.quote.lines },
    escrow: {
      address: o.address,
      amount_zat: o.quote.amount_zat,
      refund_height: o.refundHeight,
      u_pub: E.toHex(o.uPub),
      l_pub: E.toHex(L_PUB),
      payee_hash: E.toHex(o.payeeHash),
      usd_amount_6dec: o.quote.usd_amount_6dec,
      platform_fee_zat: o.quote.platform_fee_zat,
      treasury_script: o.quote.platform_fee_zat > 0 ? E.toHex(TREASURY_SCRIPT) : '',
      zip321_uri: E.zip321(o.address, o.quote.amount_zat),
    },
    funding: o.funding ? { txid: hexRev(o.funding.txid), vout: 0, confirmations: o.funding.confirmations, required: o.funding.required } : null,
    announcement: a ? {
      P: E.toHex(ATTESTOR_P),
      R: E.toHex(E.pointToBytes(a.R)),
      event_id: E.toHex(a.event),
      terms_hash: E.toHex(a.tHash),
      terms: E.termsToWire(a.canonical),
      lp_output_script: E.toHex(LP_SCRIPT),
      miner_fee_zat: o.quote.miner_fee_zat,
    } : null,
    pre_signature: o.presig ? { received_at: new Date(o.presignedAt).toISOString() } : null,
    payment: o.payment,
    release: o.release ? { txid: hexRev(o.release.txid) } : null,
    refund: o.refund,
  };
}

function acceptPresign(o, body) {
  if (o.stage !== 'needs_presignature') throw new Error(`not expecting a pre-signature in stage ${o.stage}`);
  const pre = E.fromHex(String(body.pre_signature || ''));
  if (String(body.terms_hash) !== E.toHex(o.announcement.tHash)) throw new Error('terms hash mismatch');
  // The LP's check before it pays (spec 5.3 step 5).
  if (!E.adaptorVerify(pre, o.digest, E.pointFromBytes(o.uPub), o.announcement.Y)) {
    throw new Error('the pre-signature does not verify against u_pub and Y; the LP will not pay');
  }
  o.presig = pre;
  o.presignedAt = Date.now();
  o.stage = 'locked';
  console.log(`[mock] ${o.id}: pre-signature verified, escrow locked`);
}

function acceptRefund(o, body) {
  if (o.stage !== 'refundable') throw new Error(`not refundable in stage ${o.stage}`);
  const raw = E.fromHex(String(body.raw_tx || ''));
  if (raw.length < 100) throw new Error('that is not a transaction');
  o.refund = { txid: String(body.txid || ''), broadcast_at: new Date().toISOString() };
  o.stage = 'refunded';
  console.log(`[mock] ${o.id}: refund accepted, ${raw.length} bytes, txid ${o.refund.txid}`);
  return { txid: o.refund.txid };
}

// ---------- http ----------

const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript', '.mjs': 'text/javascript', '.png': 'image/png', '.woff2': 'font/woff2', '.json': 'application/json' };

function send(res, status, body) {
  const json = JSON.stringify(body);
  res.writeHead(status, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': '*' });
  res.end(json);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (c) => { data += c; if (data.length > 1e6) req.destroy(); });
    req.on('end', () => { try { resolve(data ? JSON.parse(data) : {}); } catch (e) { reject(new Error('bad json')); } });
    req.on('error', reject);
  });
}

function serveStatic(req, res, url) {
  let p = decodeURIComponent(url.pathname);
  if (p.endsWith('/')) p += 'index.html';
  const file = path.normalize(path.join(SITE, p));
  if (!file.startsWith(SITE)) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404); return res.end('not found'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' });
    res.end(data);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const p = url.pathname;
  try {
    if (req.method === 'OPTIONS') return send(res, 204, {});
    if (p === '/health') return send(res, 200, { ok: true, mock: true });
    if (p === '/escrow/capabilities') {
      return send(res, 200, {
        network: NETWORK,
        rails: [{ id: 'venmo', label: 'Venmo', live: true }],
        fee: { bps: FEE_BPS, label: 'zpay fee' },
        l_pub: E.toHex(L_PUB),
        attestor_pubkey: E.toHex(ATTESTOR_P),
        consensus_branch_id: BRANCH_ID,
        block_seconds: BLOCK_SECONDS,
        refund_delay_blocks: REFUND_DELAY,
        limits: { min_zat: MIN_ZAT, max_zat: MAX_ZAT },
        rate_usd_per_zec: RATE_USD_PER_ZEC,
        mock: true,
      });
    }
    if (p === '/escrow/quote' && req.method === 'GET') {
      return send(res, 200, quoteFor(url.searchParams.get('amount'), url.searchParams.get('unit') || 'zec'));
    }
    if (p === '/escrow/orders' && req.method === 'POST') {
      const v = openOrder(await readBody(req));
      console.log(`[mock] ${v.order_id}: opened, ${v.escrow.address}, ${E.zecString(v.escrow.amount_zat)} ZEC to @${v.destination.handle}`);
      return send(res, 200, v);
    }
    const m = p.match(/^\/escrow\/orders\/([^/]+)(?:\/(presign|refund))?$/);
    if (m) {
      const o = orders.get(m[1]);
      if (!o) return send(res, 404, { error: 'no such order' });
      if (!m[2] && req.method === 'GET') return send(res, 200, view(o));
      if (m[2] === 'presign' && req.method === 'POST') { view(o); acceptPresign(o, await readBody(req)); return send(res, 200, { ok: true }); }
      if (m[2] === 'refund' && req.method === 'POST') { view(o); return send(res, 200, acceptRefund(o, await readBody(req))); }
    }
    if (p.startsWith('/escrow/')) return send(res, 404, { error: 'not found' });
    return serveStatic(req, res, url);
  } catch (e) {
    return send(res, 400, { error: e.message });
  }
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`mock coordinator on http://127.0.0.1:${PORT}/app/  (step ${STEP} ms, network ${NETWORK})`);
});

/* zpay front door: the links, the fee, and the coordinator's status dot.
   Plain ES2020, no build step. Read-only against the coordinator: one GET of
   /escrow/capabilities, the same call the app makes first, so the dot in this
   nav and the dot in the app's nav agree. Nothing here ever posts. */

'use strict';

// ---------- one place to edit ----------
//
// Every link and every number the copy leans on. Change it here, not in the
// markup: index.html and takers/index.html fill from this block.
const SITE = {
  // Rendered everywhere as data-fee. A live coordinator's fee.bps overrides
  // it below, so the page and the app never disagree once one answers.
  feePercent: '0.15',

  // The Base-rail contract the takers page still documents. Not on the front
  // door any more: the escrow is on Zcash.
  glueContract: '0x617544CC688F7f742cA68B5d9106890500b6C689',
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
};

// ---------- coordinator base URL ----------
//
// Same resolution as the app, minus ?api=: this page only reads, but it still
// should not be pointed anywhere by a link. A loopback origin saved by the app
// is honoured so a dev setup works out of the box. Same origin otherwise.
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

function setFee(pct) {
  $$('[data-fee]').forEach((el) => { el.textContent = pct + '%'; });
}

function applySite() {
  setFee(SITE.feePercent);
  $$('[data-link]').forEach((el) => {
    const href = SITE.links[el.dataset.link];
    if (href) el.href = href;
  });
  $$('[data-contract]').forEach((el) => { el.textContent = SITE.glueContract; });
  $$('[data-contract-link]').forEach((el) => {
    el.href = 'https://basescan.org/address/' + SITE.glueContract;
  });
  $$('[data-chain]').forEach((el) => { el.textContent = 'Base ' + SITE.chainId; });
}

// ---------- the status dot ----------

function setState(el, state, text) {
  if (!el) return;
  el.dataset.state = state;
  const t = el.querySelector('[data-text]');
  if (t) t.textContent = text;
}

async function refreshStatus() {
  const conn = $('conn');
  try {
    const c = await api('/escrow/capabilities');
    setState(conn, 'up', 'coordinator up');
    if (c && c.fee && typeof c.fee.bps === 'number') setFee((c.fee.bps / 100).toFixed(2));
  } catch (_) {
    setState(conn, 'down', 'coordinator down');
  }
}

// ---------- boot ----------

applySite();
refreshStatus();
setInterval(refreshStatus, 30000);

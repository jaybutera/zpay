/* Which outpoint does the page build a refund over?
 *
 *   node frontend/app/test/refund-outpoint.js
 *
 * The page keeps a localStorage record written when it signed, and it also
 * gets a live view from the coordinator on every poll. Both carry a funding
 * outpoint, and they can disagree.
 *
 * They disagree for an ordinary reason, not an attack. Zcash expires an
 * unmined transaction after 40 blocks, so a wallet that funded an escrow and
 * saw it sit in the mempool resends it under a new txid. The coordinator
 * learns the outpoint that actually confirmed; this page still holds the one
 * it signed over. Building the refund from the record then produces a
 * transaction spending an outpoint that never existed on chain - no node will
 * take it - while the page tells the user any node will.
 *
 * So the live view has to win, and the record stays as the fallback it was
 * written to be: a view that has not caught up yet, or a page that knows more
 * than the coordinator has served.
 *
 * This reads the precedence out of app.js rather than restating it, so the
 * test fails if the source changes rather than passing against a copy.
 */
'use strict';

const fs = require('fs');
const path = require('path');

const SRC = path.join(__dirname, '..', 'app.js');
const src = fs.readFileSync(SRC, 'utf8');

let failures = 0;
function check(name, got, want) {
  const ok = got === want;
  if (!ok) failures++;
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}${ok ? '' : `\n       got  ${got}\n       want ${want}`}`);
}

// The three lines the refund builder picks its inputs with.
const txidExpr = (src.match(/const fundingTxid = ([^\n;]+);/) || [])[1];
const voutExpr = (src.match(/const vout = ([^\n;]+);/) || [])[1];
const branchExpr = (src.match(/const branch = ([^\n;]+);/) || [])[1];

if (!txidExpr || !voutExpr || !branchExpr) {
  console.log('FAIL could not find the refund builder in app.js');
  process.exit(1);
}
console.log(`refund builder reads:\n  fundingTxid = ${txidExpr.trim()}\n  vout        = ${voutExpr.trim()}\n  branch      = ${branchExpr.trim()}\n`);

// Evaluate those exact expressions against the two states that matter.
function pick(rec, view) {
  const f = view.funding || {};
  const fn = new Function('rec', 'view', 'f', `return [${txidExpr}, ${voutExpr}, ${branchExpr}];`);
  return fn(rec, view, f);
}

// 1. The resend. Signed over A; B is what confirmed.
{
  const rec = { fundingTxid: 'aa'.repeat(32), vout: 0, consensusBranchId: 0x37a5165b };
  const view = { funding: { txid: 'bb'.repeat(32), vout: 0 }, consensus_branch_id: 0x37a5165b };
  const [txid, vout] = pick(rec, view);
  check('a resent funding refunds over the CONFIRMED outpoint', txid, 'bb'.repeat(32));
  check('  and its vout', vout, 0);
}

// 2. A resend that also landed at a different index.
{
  const rec = { fundingTxid: 'aa'.repeat(32), vout: 0, consensusBranchId: 1 };
  const view = { funding: { txid: 'bb'.repeat(32), vout: 3 }, consensus_branch_id: 1 };
  const [, vout] = pick(rec, view);
  check('the vout comes from the view too', vout, 3);
}

// 3. vout 0 from the view must not be read as "missing" and fall back.
{
  const rec = { fundingTxid: 'aa'.repeat(32), vout: 7, consensusBranchId: 1 };
  const view = { funding: { txid: 'bb'.repeat(32), vout: 0 }, consensus_branch_id: 1 };
  const [, vout] = pick(rec, view);
  check('vout 0 in the view is a value, not an absence', vout, 0);
}

// 4. The fallback the record exists for: the view has no funding yet.
{
  const rec = { fundingTxid: 'aa'.repeat(32), vout: 2, consensusBranchId: 7 };
  const view = {};
  const [txid, vout, branch] = pick(rec, view);
  check('with no funding in the view, the record is used', txid, 'aa'.repeat(32));
  check('  its vout', vout, 2);
  check('  its branch id', branch, 7);
}

console.log(`\n${failures === 0 ? 'all checks passed' : failures + ' check(s) failed'}`);
process.exit(failures === 0 ? 0 : 1);

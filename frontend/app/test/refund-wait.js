/* What the refund screens say about when the ZEC comes back.
 *
 *   node frontend/app/test/refund-wait.js
 *
 * `read_order` serves `current_height` 0 when the coordinator cannot reach its
 * node. Read as a height, that is not "unknown", it is genesis - so the page
 * computed the wait as T blocks and said it with a confident "about". On
 * mainnet T is around three and a half million, which renders as roughly
 * eighty years of waiting on an escrow that is refundable tomorrow.
 *
 * This exercises the arithmetic the way `renderReturns` does, out of the real
 * source, for the three cases: the node is down, T is still ahead, and T has
 * passed.
 */
'use strict';

const fs = require('fs');
const path = require('path');

const src = fs.readFileSync(path.join(__dirname, '..', 'app.js'), 'utf8');
let failures = 0;
function check(name, ok, detail) {
  if (!ok) failures++;
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}${ok ? '' : `\n       ${detail}`}`);
}

// Pull the block out of renderReturns so this tests the shipped expressions.
const block = src.match(/const T = view\.escrow\.refund_height;[\s\S]*?const whenText = [\s\S]*?;\n/);
if (!block) {
  console.log('FAIL could not find the wait computation in app.js');
  process.exit(1);
}

function evaluate(currentHeight, refundHeight) {
  const view = { escrow: { refund_height: refundHeight }, current_height: currentHeight };
  const state = { caps: { block_seconds: 75 } };
  const fn = new Function('view', 'state', `${block[0]} return { heightKnown, blocks, whenText };`);
  return fn(view, state);
}

// 1. Node down. Mainnet-sized T, so the old bug is unmistakable.
{
  const r = evaluate(0, 3_473_682);
  check('a node outage does not claim to know the wait', !r.heightKnown,
    `heightKnown was ${r.heightKnown}`);
  check('  and does not render decades of hours',
    !/\d+\.\d+ hours from now/.test(r.whenText), `said: ${r.whenText}`);
  check('  it says it cannot tell', /cannot reach/.test(r.whenText), `said: ${r.whenText}`);
}

// 2. T still ahead: an hour of blocks.
{
  const r = evaluate(1_000, 1_048);
  check('a real height gives a real wait', r.heightKnown && r.blocks === 48,
    `blocks=${r.blocks}`);
  check('  phrased in minutes or hours', /from now/.test(r.whenText), `said: ${r.whenText}`);
}

// 3. T passed: the refund is available now.
{
  const r = evaluate(1_100, 1_048);
  check('past T reads as zero blocks left', r.heightKnown && r.blocks === 0,
    `blocks=${r.blocks}`);
}

console.log(`\n${failures === 0 ? 'all checks passed' : failures + ' check(s) failed'}`);
process.exit(failures === 0 ? 0 : 1);

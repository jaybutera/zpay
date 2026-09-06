/* What the confirming screen says about a transaction that is in no block.
 *
 *   node frontend/app/test/confirming-mempool.js
 *
 * `FundingView.mempool` exists because `confirmations: 0` on a mined output
 * cannot happen, so a zero without the flag is not a depth - it is "in no
 * block, and it may never be". The page ignored the flag and rendered both
 * states identically: "0 of 10 confirmations", plus a countdown computed off a
 * first confirmation that had not happened, for a transaction a node might
 * never mine.
 *
 * This drives the two shipped expressions - the ladder's side text and the
 * `confirming` sub-line - out of app.js, for a mempool sighting and for a
 * mined output at the same depth.
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

// Lift the expressions rather than restating them, so this cannot pass against
// a copy of the rule that the page does not use.
const ladderLine = src.match(/if \(key === 'confirming' &&[^)]*\) (side\.textContent = [^\n]*?);\n/);
if (!ladderLine) {
  console.log('FAIL could not find the ladder side text in app.js');
  process.exit(1);
}
// Match the assignment inside `case 'confirming':` whatever shape it has, so
// that a regression to the old one-line ternary is caught by the checks below
// rather than by this lift failing to find a pattern.
const confirmingCase = src.match(/case 'confirming':[\s\S]*?\n      break;/);
if (!confirmingCase) {
  console.log("FAIL could not find case 'confirming' in app.js");
  process.exit(1);
}
const subBlock = confirmingCase[0].match(/\n(\s*)sub = [\s\S]*?;\n/);
if (!subBlock) {
  console.log('FAIL could not find the confirming sub-line in app.js');
  process.exit(1);
}

function ladder(f) {
  const side = { textContent: '' };
  new Function('side', 'f', `${ladderLine[1]};`)(side, f);
  return side.textContent;
}
function sub(f) {
  const state = { caps: { block_seconds: 75 } };
  return new Function('f', 'state', `let sub; ${subBlock[0]} return sub;`)(f, state);
}

const MEMPOOL = { txid: 'ab'.repeat(32), vout: 0, confirmations: 0, required: 10, mempool: true };
const MINED_0 = { txid: 'ab'.repeat(32), vout: 0, confirmations: 0, required: 10, mempool: false };
const MINED_2 = { txid: 'ab'.repeat(32), vout: 0, confirmations: 2, required: 10, mempool: false };

// 1. The two zero-depth states must not render the same. This is the whole
//    reason the flag is on the wire.
check('a mempool sighting and a mined zero do not read alike (ladder)',
  ladder(MEMPOOL) !== ladder(MINED_0),
  `both said: ${ladder(MEMPOOL)}`);
check('a mempool sighting and a mined zero do not read alike (sub-line)',
  sub(MEMPOOL) !== sub(MINED_0),
  `both said: ${sub(MEMPOOL)}`);

// 2. A transaction in no block is not reported as a depth out of ten.
check('the ladder does not count a mempool sighting as a confirmation',
  !/\d+\s*\/\s*\d+/.test(ladder(MEMPOOL)), `said: ${ladder(MEMPOOL)}`);
check('the sub-line does not call a mempool sighting 0 of 10 confirmations',
  !/of \d+ confirmations/.test(sub(MEMPOOL)), `said: ${sub(MEMPOOL)}`);
check('  and says where the transaction actually is',
  /mempool/i.test(sub(MEMPOOL)), `said: ${sub(MEMPOOL)}`);

// 3. No countdown off a first confirmation that has not happened. The old line
//    quoted "About 13 minutes" for a transaction a node might never mine.
check('the sub-line promises no time to a transaction that is not mined',
  !/minutes|hours/.test(sub(MEMPOOL)), `said: ${sub(MEMPOOL)}`);

// 4. The mined path is untouched: still a depth, still a countdown.
check('a mined output still shows its depth', ladder(MINED_2) === '2 / 10',
  `said: ${ladder(MINED_2)}`);
check('  and still quotes the wait', /About 10 minutes/.test(sub(MINED_2)),
  `said: ${sub(MINED_2)}`);
check('a mined zero still shows its depth', ladder(MINED_0) === '0 / 10',
  `said: ${ladder(MINED_0)}`);

// 5. A view with no funding at all stays silent rather than throwing.
check('no funding yields no sub-line', sub(null) === '', `said: ${sub(null)}`);

// 6. The flag is absent on older stored views; `serde(default)` makes that
//    false, and the page must read a missing flag as mined, not as mempool.
check('a view with no mempool field is treated as mined',
  ladder({ confirmations: 3, required: 10 }) === '3 / 10',
  `said: ${ladder({ confirmations: 3, required: 10 })}`);

console.log(failures ? `\n${failures} failed` : '\nall passed');
process.exit(failures ? 1 : 0);

/* When does the page offer the refund form, and when must it not?
 *
 *   node frontend/app/test/refund-form-visibility.js
 *
 * The form signs the escrow's timeout branch with the user's key. That is the
 * right thing to offer when the trade is over and nobody was paid, and the
 * wrong thing to offer when the dollars already left: the LP holds a valid
 * release over the same escrow, and on a race the loss is the LP's. A page that
 * shows the form there is this coordinator telling the user to spend against
 * the party that just paid them.
 *
 * `renderReturns` is a DOM function, so this drives it under a stub: enough of
 * document.getElementById to record what each branch sets. That is the seam the
 * Rust suite cannot reach, and where two of these rules were previously wrong.
 */
'use strict';

const fs = require('fs');
const path = require('path');

const src = fs.readFileSync(path.join(__dirname, '..', 'app.js'), 'utf8');

// Lift renderReturns out of the module rather than restating it.
const start = src.indexOf('function renderReturns(view) {');
if (start < 0) {
  console.log('FAIL could not find renderReturns in app.js');
  process.exit(1);
}
// Balance braces to find the end of the function.
let depth = 0, end = -1;
for (let i = src.indexOf('{', start); i < src.length; i++) {
  if (src[i] === '{') depth++;
  else if (src[i] === '}') { depth--; if (depth === 0) { end = i + 1; break; } }
}
const fnSrc = src.slice(start, end);

function run(view, hasKey) {
  const els = {};
  const el = (id) => (els[id] = els[id] || { textContent: '', hidden: false, dataset: {} });
  const ctx = {
    $: el,
    zec: (z) => (z / 1e8).toFixed(8),
    state: { key: hasKey ? 'a-key' : null, caps: { block_seconds: 75 } },
    RETURN_STAGES: ['unpaid', 'refundable', 'refunded', 'failed'],
  };
  const make = new Function(
    '$', 'zec', 'state', 'RETURN_STAGES',
    `${fnSrc}; return renderReturns;`
  );
  make(ctx.$, ctx.zec, ctx.state, ctx.RETURN_STAGES)(view);
  return { form: el('form-return'), body: el('returns-body'), title: el('returns-title') };
}

let failures = 0;
function check(name, ok, detail) {
  if (!ok) failures++;
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}${ok ? '' : `\n       ${detail}`}`);
}

const escrow = { refund_height: 1000, amount_zat: 5_000_000 };
const paid = { sent_at: '2026-09-05T00:00:00Z', cents: 200 };

// The three failure writers that follow a journal claim and leave `payment`
// null. Each one means the browser may already have sent the dollars, and only
// the journal knows - which is what `fiat_may_have_left` carries. The reasons
// are the driver's own text.
const JOURNAL_ONLY_FAILURES = [
  ['the Venmo leg errored inside pay',
   'the payment could not be completed: the browser died halfway through the payment. ' +
   'Check the Venmo feed before anything else: a payment may have left.'],
  ['a stale Paying line this instance will not adopt',
   'this escrow has a payment line that is not this run\'s, and the feed has to be read ' +
   'before anything else happens.'],
  ['another payment already under way',
   'another payment is already under way for this escrow. Check the Venmo feed: two ' +
   'identical payments cannot be told apart.'],
];

for (const [what, reason] of JOURNAL_ONLY_FAILURES) {
  for (const stage of ['failed', 'refundable']) {
    const r = run({ stage, escrow, current_height: 1004, payment: null,
                    fiat_may_have_left: true, reason }, true);
    check(`${stage}: ${what} hides the form`, r.form.hidden === true,
      `form.hidden=${r.form.hidden} body=${r.body.textContent.slice(0, 120)}`);
    check('  and does not tell the user to broadcast',
      !/can come back to you now/.test(r.body.textContent),
      `said: ${r.body.textContent.slice(0, 160)}`);
  }
}

// The same three with a clean journal are ordinary refusals, and the form is
// exactly what the user needs.
{
  const r = run({ stage: 'failed', escrow, current_height: 1004, payment: null,
                  fiat_may_have_left: false,
                  reason: 'the funding transaction was replaced after you signed' }, true);
  check('a failure with a clean journal still offers the form', r.form.hidden === false,
    `form.hidden=${r.form.hidden}`);
}

// 1. Stopped, dollars already sent: never the form.
{
  const r = run({ stage: 'failed', escrow, current_height: 1001, payment: paid,
                  reason: 'the dollars were sent and the release did not broadcast' }, true);
  check('a stopped order whose dollars left hides the form', r.form.hidden === true,
    `form.hidden=${r.form.hidden}`);
  check('  and says a person is needed', /get in touch/.test(r.body.textContent),
    `said: ${r.body.textContent}`);
}

// 2. Promoted to refundable with a payment: still never the form.
{
  const r = run({ stage: 'refundable', escrow, current_height: 1001, payment: paid,
                  reason: 'the dollars were sent and the release did not broadcast' }, true);
  check('a refundable order whose dollars left hides the form', r.form.hidden === true,
    `form.hidden=${r.form.hidden}`);
}

// 3. Refundable, nobody paid: the form, and the reason survives.
{
  const r = run({ stage: 'refundable', escrow, current_height: 1001, payment: null,
                  reason: 'the funding transaction was replaced after you signed' }, true);
  check('a refundable order with no payment offers the form', r.form.hidden === false,
    `form.hidden=${r.form.hidden}`);
  check('  and still shows why the trade stopped', /replaced/.test(r.body.textContent),
    `said: ${r.body.textContent}`);
}

// 4. Refundable but this browser has no key: no form, and it says why.
{
  const r = run({ stage: 'refundable', escrow, current_height: 1001, payment: null }, false);
  check('without the key the form stays hidden', r.form.hidden === true,
    `form.hidden=${r.form.hidden}`);
  check('  and points at the saved link', /link you kept/.test(r.body.textContent),
    `said: ${r.body.textContent}`);
}

// 5. Stopped, nobody paid, T not reached: no form yet.
{
  const r = run({ stage: 'failed', escrow, current_height: 900, payment: null,
                  reason: 'the funding transaction was replaced after you signed' }, true);
  check('before T a stopped order does not offer the form', r.form.hidden === true,
    `form.hidden=${r.form.hidden}`);
  check('  and names the block it becomes possible at', /1,000/.test(r.body.textContent),
    `said: ${r.body.textContent}`);
}

console.log(`\n${failures === 0 ? 'all checks passed' : failures + ' check(s) failed'}`);
process.exit(failures === 0 ? 0 : 1);

/* Check frontend/app/zaddr.js: SHA-256, base58check and bech32m.
 *
 *   node frontend/app/test/zaddr-vectors.js
 *
 * All three fail silently when they are wrong, and wrong here is expensive: an
 * address that passes a broken checksum is a refund sent somewhere unspendable.
 * The round 1 audit found the old check was a length test, so `t1AAAA...` and
 * the repo's own placeholder both passed it, and 1Click accepted them too.
 *
 * The unified addresses below were produced by `zcash_address` 0.13 from the
 * coordinator's own test helper, so this cross-checks the hand-written bech32m
 * against the library the server side uses.
 */
const path = require('path');
const ZAddr = require(path.join(__dirname, '..', 'zaddr.js'));

let failures = 0;
function check(what, got, want) {
  const ok = got === want;
  if (!ok) failures++;
  console.log(`${ok ? 'ok  ' : 'FAIL'}  ${what}${ok ? '' : `\n        got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`}`);
}

// ---------- SHA-256, against the published vectors ----------

const hex = (b) => Buffer.from(b).toString('hex');
const sha = (t) => hex(ZAddr.sha256(new TextEncoder().encode(t)));

check('sha256("")', sha(''),
  'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
check('sha256("abc")', sha('abc'),
  'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
check('sha256(56-byte vector)',
  sha('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'),
  '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1');
check('sha256(one million "a")', sha('a'.repeat(1000000)),
  'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0');

// ---------- base58check ----------

// Bitcoin's private-key-1 address, the standard base58check vector.
check('base58check decodes a known Bitcoin address',
  hex(ZAddr.base58checkDecode('1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH')),
  '00751e76e8199196d454941c45d1b3a323f1433bd6');

const GOOD_T = [
  't1KhV8ADhTGvVvBpTiEcJGnhTvBBFWERZu7',
  't3Vz22vK5z2LcKEdg16Yv4FFneEL1zg9ojd',
];
for (const a of GOOD_T) check(`accepts ${a}`, ZAddr.validateZcashAddress(a), null);

// Everything the audit found the old check let through.
const BAD_T = [
  ['t1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'right length, no checksum'],
  ['t1KhV8ADhTGvVvBpTiEcJGnhTvBBFVFYHXx', 'the old repo placeholder'],
  ['t1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', '34 characters of nothing'],
  ['t3aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'the same for t3'],
];
for (const [a, why] of BAD_T) {
  const got = ZAddr.validateZcashAddress(a);
  check(`refuses ${a} (${why})`, typeof got === 'string', true);
}

// ---------- bech32m, against addresses zcash_address encoded ----------

const GOOD_U = [
  'u1ycfgwzzvdt5lu7v48gyfnccw2caf7lqppvmt535qdy8fxy2d0nextcg22t6ha04g5zxqyyzy7k5rjdr0kjqm58a3u5ups776fuv977hc',
  'u1f0k4js70auau2zsj7r8qc9u4lgf5u8tux0f7qhy0e8t3qdj69945faxpqyy4gcj95sxgv6vl72ms02e2km7dtup2r80ral5ummakz9cm4w6u4kn5tq4yrg67hm9l0sdrk08kudrpr8r',
  'u1d2udnm29xpx7p6z5e3w3s30yqsqql97w6d7dklkdgmke7kdakwzas52etauaf7ktnq7gws0kaxddmu235mtfzwvr874daugemsjaefq9',
];
for (const u of GOOD_U) {
  check(`accepts a real unified address (${u.slice(0, 12)}…)`,
    ZAddr.validateZcashAddress(u), null);
}

check('refuses u1notarealaddressatall',
  typeof ZAddr.validateZcashAddress('u1notarealaddressatall') === 'string', true);

// A checksum that catches nothing would still pass everything above. This is
// the test that says it catches something.
let corrupted = 0, caught = 0;
for (const u of GOOD_U) {
  for (let i = 1; i < u.length; i++) {
    const c = u[i] === 'q' ? 'p' : 'q';
    if (c === u[i]) continue;
    corrupted++;
    if (ZAddr.validateZcashAddress(u.slice(0, i) + c + u.slice(i + 1))) caught++;
  }
}
check(`refuses every one-character corruption of a unified address (${corrupted} of them)`,
  caught, corrupted);

let tCorrupted = 0, tCaught = 0;
for (const a of GOOD_T) {
  for (let i = 2; i < a.length; i++) {
    const c = a[i] === 'a' ? 'b' : 'a';
    tCorrupted++;
    if (ZAddr.validateZcashAddress(a.slice(0, i) + c + a.slice(i + 1))) tCaught++;
  }
}
check(`refuses every one-character corruption of a t-address (${tCorrupted} of them)`,
  tCaught, tCorrupted);

// ---------- U2-6: the case a QR scanner hands back ----------

// BIP 173 allows an all-upper-case bech32m string, `validateZcashAddress`
// accepts one, and the server matched `starts_with("u1")` case-sensitively and
// refused it. `normalizeZcashAddress` is the page's half of that fix: it turns
// the upper-case form into the one both decoders take, and leaves everything
// else alone.
for (const u of GOOD_U) {
  const upper = u.toUpperCase();
  check(`accepts the upper-case form of ${u.slice(0, 12)}…`,
    ZAddr.validateZcashAddress(upper), null);
  check(`normalises the upper-case form of ${u.slice(0, 12)}… to the one the server takes`,
    ZAddr.normalizeZcashAddress(upper), u);
  check(`leaves the lower-case form of ${u.slice(0, 12)}… alone`,
    ZAddr.normalizeZcashAddress(u), u);
}

// base58 is case-significant, so a t-address must survive untouched: lowering
// one would turn a valid address into a different, invalid string.
for (const a of GOOD_T) {
  check(`leaves the t-address ${a.slice(0, 8)}… untouched`,
    ZAddr.normalizeZcashAddress(a), a);
}

// Mixed case is not a valid bech32m encoding of anything, so it must not be
// laundered into one by lower-casing it.
for (const u of GOOD_U) {
  const mixed = u.slice(0, 20).toUpperCase() + u.slice(20);
  check(`refuses the mixed-case form of ${u.slice(0, 12)}…`,
    typeof ZAddr.validateZcashAddress(mixed) === 'string', true);
  check(`does not launder the mixed-case form of ${u.slice(0, 12)}…`,
    ZAddr.normalizeZcashAddress(mixed), mixed);
}

check('trims surrounding whitespace', ZAddr.normalizeZcashAddress(`  ${GOOD_U[0]}  `), GOOD_U[0]);

// ---------- the things that are not addresses ----------

for (const [a, what] of [
  ['', 'empty'],
  ['   ', 'blank'],
  ['zs1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqq', 'a Sapling address'],
  ['0x0000000000000000000000000000000000000000', 'an EVM address'],
  ['1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH', 'a valid Bitcoin address'],
]) {
  check(`refuses ${what}`, typeof ZAddr.validateZcashAddress(a) === 'string', true);
}

console.log(failures === 0 ? '\nall checks passed' : `\n${failures} FAILED`);
process.exit(failures === 0 ? 0 : 1);

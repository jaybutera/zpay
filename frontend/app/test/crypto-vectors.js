/* Check the page's hand-written crypto against published vectors.
 *
 *   node frontend/app/test/crypto-vectors.js
 *
 * keccak256 is the empty-string and "abc" vectors; secp256k1 is private key 1,
 * whose public key is the generator itself and whose address is a widely
 * published value. The addresses are lowercase because that is the form the
 * coordinator signs over; see session-key-vectors.js.
 */
const fs=require('fs');
// Pull the crypto helpers out of app.js without running its DOM code.
const src=fs.readFileSync(require('path').join(__dirname,'..','app.js'),'utf8');
const start=src.indexOf('const SECP = {');
const end=src.indexOf('// ---------- order state ----------');
const code=src.slice(start,end);
const ctx={TextEncoder,crypto:require('crypto').webcrypto};
new Function('globalThis',
  `with(globalThis){${code}
   globalThis.__x={newSessionKey,compressedPubkey,evmAddress,keccak256,personalSign,ownershipMessage,toHex};}`
).call(ctx,ctx);
const X=ctx.__x;

let fail=0;
const check=(name,got,want)=>{const ok=String(got).toLowerCase()===String(want).toLowerCase();
  if(!ok){fail++;console.log(`FAIL ${name}\n  got  ${got}\n  want ${want}`);}else console.log(`PASS ${name}`);};

// keccak256 of the empty string, the standard vector.
check('keccak256("")', X.toHex(X.keccak256(new Uint8Array(0))),
  'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470');
check('keccak256("abc")', X.toHex(X.keccak256(new TextEncoder().encode('abc'))),
  '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45');
check('keccak256("testing")', X.toHex(X.keccak256(new TextEncoder().encode('testing'))),
  '5f16f4c7f149ac4f9510d9cf8cf384038ad348b3bcdc01915f95de12df9d1b02');

// secp256k1: private key 1 gives the generator; the well-known address for
// private key 1 is a published test vector.
check('pubkey(1)', X.compressedPubkey(1n),
  '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
check('address(1)', X.evmAddress(1n), '0x7e5f4552091a69125d5dfcb7b8c2659029395bdf');
check('address(2)', X.evmAddress(2n), '0x2b5ad5c4795c026514f8317c7a215e218dccd6cf');
// Lowercase, not EIP-55: auth.rs signs over alloy's `{:?}` formatting.
check('address(0xf00d)', X.evmAddress(0xf00dn), '0x2fbe5d18a830abf220ccf3c4e74253ef91496b41');

console.log(fail? `\n${fail} failed` : '\nall crypto vectors pass');
process.exit(fail?1:0);

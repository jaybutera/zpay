/* Print signature vectors the page produces, for the Rust side to verify.
 *
 * The page derives its own EVM address and makes its own ECDSA signature, in
 * secp256k1 and keccak written by hand because WebCrypto has neither. If that
 * disagrees with the coordinator anywhere, every order fails to open, and the
 * failure is a 401 that says nothing about why.
 *
 *   node frontend/app/test/session-key-vectors.js > /tmp/js-sigs.json
 *   cargo run -p zecp2p-coordinator --example verify_js_sigs -- /tmp/js-sigs.json
 *
 * The bug this caught: the page formatted the address with an EIP-55 checksum
 * while `auth.rs` builds the signed message with alloy's `{:?}`, which is
 * lowercase. Same key, same signature algorithm, different bytes signed, and
 * every open request would have been rejected.
 */
const fs=require('fs');
const src=fs.readFileSync(require('path').join(__dirname,'..','app.js'),'utf8');
const code=src.slice(src.indexOf('const SECP = {'), src.indexOf('// ---------- order state ----------'));
const ctx={TextEncoder,crypto:require('crypto').webcrypto};
new Function('globalThis',`with(globalThis){${code}
  globalThis.__x={compressedPubkey,evmAddress,personalSign,ownershipMessage};}`).call(ctx,ctx);
const X=ctx.__x;
const out=[];
for(const secret of ['0000000000000000000000000000000000000000000000000000000000000001',
                     '000000000000000000000000000000000000000000000000000000000000f00d',
                     '7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f']){
  const d=BigInt('0x'+secret);
  const addr=X.evmAddress(d);
  const message=X.ownershipMessage('open',addr,'q1:venmo:jane-doe');
  out.push({secret,address:addr,pubkey:X.compressedPubkey(d),message,sig:X.personalSign(d,message)});
}
console.log(JSON.stringify(out));

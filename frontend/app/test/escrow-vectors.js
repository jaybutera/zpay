/* Checks frontend/app/escrow.js against crates/zecp2p-escrow.

   Usage:
     cargo run -p zecp2p-escrow --example frontend_vectors -- emit > vectors.json
     node frontend/app/test/escrow-vectors.js vectors.json js-out.json
     cargo run -p zecp2p-escrow --example frontend_vectors -- check vectors.json js-out.json

   The first half recomputes every intermediate value the crate emitted and
   compares. The second half produces what only the page can produce, a
   pre-signature and a signed refund, plus a completed release assembled the
   way the mock LP does it, and writes them for the crate to verify. */

'use strict';

const fs = require('fs');
const path = require('path');
const E = require(path.join(__dirname, '..', 'escrow.js'));

const [vectorsPath, outPath] = process.argv.slice(2);
if (!vectorsPath) {
  console.error('usage: escrow-vectors.js <vectors.json> [js-out.json]');
  process.exit(2);
}
const { inputs: I, expected: X } = JSON.parse(fs.readFileSync(vectorsPath, 'utf8'));

let failures = 0;
function eq(what, got, want) {
  if (got === want) {
    console.log('ok  ', what);
  } else {
    failures++;
    console.log('FAIL', what);
    console.log('      got ', got);
    console.log('      want', want);
  }
}
const h = E.toHex;

// ---------- keys, script, address ----------

const uPriv = E.scalarFromBytes(E.fromHex(I.u_priv));
const lPriv = E.scalarFromBytes(E.fromHex(I.l_priv));
const d = E.scalarFromBytes(E.fromHex(I.attestor_d));
const k = E.scalarFromBytes(E.fromHex(I.attestor_k));
const uPub = E.pubkey(uPriv);
const lPub = E.pubkey(lPriv);
eq('u_pub', h(uPub), X.u_pub);
eq('l_pub', h(lPub), X.l_pub);

const redeem = E.redeemScript(uPub, lPub, I.refund_height);
eq('redeem script', h(redeem), X.redeem_script);
const spk = E.p2shScript(redeem);
eq('P2SH scriptPubKey', h(spk), X.script_pubkey);
eq('t3 address', E.escrowAddress(redeem, I.network), X.address);

const lpScript = E.scriptForAddress(I.lp_address, I.network);
const treasuryScript = E.scriptForAddress(I.treasury_address, I.network);
const refundScript = E.scriptForAddress(I.refund_to, I.network);
eq('LP payout script', h(lpScript), X.lp_script);
eq('treasury script', h(treasuryScript), X.treasury_script);
eq('refund script', h(refundScript), X.refund_script);

// ---------- fees ----------

const platformFee = X.platform_fee_zat;
const minerFee = E.releaseFee(redeem.length, platformFee > 0 ? 2 : 1);
const refundFee = E.refundFeeTransparent(redeem.length);
eq('release miner fee', minerFee, X.miner_fee_zat);
eq('refund fee', refundFee, X.refund_fee_zat);

// ---------- terms, event, outcome ----------

const fundingTxid = E.fromHex(I.funding_txid);
const canonical = {
  fundingTxid, vout: I.vout, amountZat: I.amount_zat, uPub, lPub, refundHeight: I.refund_height,
  usdAmount6dec: I.usd_amount_6dec, rate18dec: E.IDENTITY_RATE_18DEC, payeeHash: E.fromHex(I.payee_hash),
  lockConfirmedMs: I.lock_confirmed_ms, platformFeeZat: platformFee, treasuryScript: platformFee > 0 ? treasuryScript : new Uint8Array(0),
};
eq('canonical json', E.canonicalJson(canonical), X.canonical_json);
const tHash = E.termsHash(canonical);
eq('terms hash', h(tHash), X.terms_hash);
eq('intent hash', h(E.intentHash(canonical)), X.intent_hash);
const event = E.eventId(fundingTxid, I.vout);
eq('event id', h(event), X.event_id);

const Pk = E.mulG(d), R = E.mulG(k);
eq('attestor P', h(E.pointToBytes(Pk)), X.attestor_p);
eq('attestor R', h(E.pointToBytes(R)), X.attestor_r);
const Y = E.outcomePoint(R, Pk, event, tHash);
eq('outcome point Y', h(E.pointToBytes(Y)), X.outcome_point);
const s = E.signOutcome(k, d, event, tHash);
eq('outcome secret s', s.toString(16).padStart(64, '0'), X.outcome_secret);
const sG = E.mulG(s);
eq('s*G == Y', h(E.pointToBytes(sG)), h(E.pointToBytes(Y)));

// ---------- the two transactions and their digests ----------

const terms = E.escrowTerms(canonical, I.consensus_branch_id);
const split = { payoutScript: lpScript, minerFeeZat: minerFee, platformFeeZat: platformFee, treasuryScript: canonical.treasuryScript };
const release = E.buildRelease(terms, split);
eq('release sighash', h(E.sighash(release)), X.release_digest);
eq('release txid', h(E.txid(release)), X.release_txid);
eq('release bytes (placeholder scriptSig)', h(E.serialize(release, new Uint8Array([0]))), X.release_raw_placeholder);

const refund = E.buildRefund(terms, refundScript, refundFee);
eq('refund sighash', h(E.sighash(refund)), X.refund_digest);
eq('refund txid', h(E.txid(refund)), X.refund_txid);
eq('refund bytes (placeholder scriptSig)', h(E.serialize(refund, new Uint8Array([0]))), X.refund_raw_placeholder);

// ---------- the handshake as the page runs it ----------

const wire = E.termsToWire(canonical);
const prepared = E.prepareEscrow(
  { uPriv, amountZat: I.amount_zat, lPub, refundHeight: I.refund_height, usdAmount6dec: I.usd_amount_6dec,
    payeeHash: canonical.payeeHash, platformFeeZat: platformFee, treasuryScript: canonical.treasuryScript },
  { fundingTxid, vout: I.vout, consensusBranchId: I.consensus_branch_id },
  wire,
  { P: E.pointToBytes(Pk), R: E.pointToBytes(R), eventId: event },
  E.pointToBytes(Pk),
  { lpOutputScript: lpScript, minerFeeZat: minerFee },
);
eq('prepareEscrow digest', h(prepared.digest), X.release_digest);
eq('prepareEscrow terms hash', h(prepared.termsHash), X.terms_hash);

// A changed field must be refused before anything is signed.
let refused = false;
try {
  E.prepareEscrow(
    { uPriv, amountZat: I.amount_zat, lPub, refundHeight: I.refund_height, usdAmount6dec: I.usd_amount_6dec,
      payeeHash: canonical.payeeHash, platformFeeZat: platformFee, treasuryScript: canonical.treasuryScript },
    { fundingTxid, vout: I.vout, consensusBranchId: I.consensus_branch_id },
    { ...wire, usd_amount_6dec: wire.usd_amount_6dec - 1 },
    { P: E.pointToBytes(Pk), R: E.pointToBytes(R), eventId: event },
    E.pointToBytes(Pk),
    { lpOutputScript: lpScript, minerFeeZat: minerFee },
  );
} catch (e) { refused = /not the ones you accepted/.test(e.message); }
eq('prepareEscrow refuses altered terms', refused, true);

// ---------- what the LP does with it (the mock's side) ----------

const sigU = E.adaptorDecrypt(prepared.preSignature, s);
eq('decrypted signature verifies under u_pub', E.ecdsaVerify(E.pointFromBytes(uPub), prepared.digest, sigU), true);
eq('recover s from the completed signature', E.adaptorRecover(prepared.preSignature, sigU, Y).toString(16), s.toString(16));
const sigL = E.ecdsaSign(lPriv, prepared.digest);
const releaseScriptSig = E.releaseScriptSig(E.encodeSignature(sigU), E.encodeSignature(sigL), redeem);
const releaseRaw = E.serialize(release, releaseScriptSig);

// ---------- the refund, signed by the page alone ----------

const signedRefund = E.signRefund(uPriv, terms, refundScript, refundFee);
eq('signed refund txid equals the unsigned txid (ZIP 244)', h(signedRefund.txid), X.refund_txid);

if (outPath) {
  const refundScriptSig = signedRefund.scriptSig;
  fs.writeFileSync(outPath, JSON.stringify({
    pre_signature: h(prepared.preSignature),
    release_script_sig: h(releaseScriptSig),
    release_raw: h(releaseRaw),
    release_txid: h(E.txid(release)),
    refund_script_sig: h(refundScriptSig),
    refund_raw: h(signedRefund.raw),
    refund_txid: h(signedRefund.txid),
  }, null, 2));
  console.log('wrote', outPath);
}

if (failures) {
  console.log(`${failures} check(s) failed`);
  process.exit(1);
}
console.log('all vector checks passed');

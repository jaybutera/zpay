// Generate a real Peer/zk-p2p TEE attestation for a real Venmo payment.
//
// This is the zk payment leg, standalone. It does not touch any chain and
// spends nothing: it sends the captured Venmo session cookie, encrypted to the
// enclave's attested key, to the Peer attestation service. The enclave replays
// the Venmo stories request itself, finds the payment, and returns an EIP-712
// signature over (intentHash, releaseAmount, dataHash).
//
// The cookie is encrypted client-side as a JWE against a key whose attestation
// document we verify to the AWS Nitro root first, so the service operator
// cannot read it outside the enclave. It is still equivalent to the raw cookie
// in power, so it is never written to disk here and never logged.
//
// Usage:
//   VENMO_COOKIE='...' VENMO_SENDER_ID=1234567890 node prove_payment.mjs
//
// Env:
//   VENMO_COOKIE      required. The Cookie header from a logged-in account.venmo.com request.
//   VENMO_SENDER_ID   required. Casper's NUMERIC Venmo id (not the @handle).
//   VENMO_USER_AGENT  the browser UA that cookie was captured with.
//   PAYMENT_INDEX     which entry in the feed, 0 = most recent (default 0).
//   INTENT_HASH       intent to bind the attestation to (default: the staged Sepolia intent).
//   CHAIN_ID          default 8453. The enclave only signs for 8453.
//   OUT               where to write the attestation (default attestation.json).

import { writeFileSync } from 'node:fs';
import {
  verifyBuyerTeePayment,
  verifyBuyerTeePaymentAttestation,
  fetchAndVerifyAttestation,
} from '@zkp2p/zkp2p-attestation';

const need = (k) => {
  const v = process.env[k];
  if (!v) { console.error(`missing ${k}. See scripts/proof/README.md.`); process.exit(2); }
  return v;
};

const attestationServiceUrl = process.env.ATTESTATION_URL ?? 'https://attestation-service.zkp2p.xyz';
const chainId = Number(process.env.CHAIN_ID ?? 8453);
const verifyingContract = process.env.VERIFIER ?? '0xC6F4a193576C60892a47e111Bb5706c30162502B';
const index = Number(process.env.PAYMENT_INDEX ?? 0);
const out = process.env.OUT ?? 'attestation.json';

const cookie = need('VENMO_COOKIE');
const senderId = need('VENMO_SENDER_ID');
const userAgent = process.env.VENMO_USER_AGENT
  ?? 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36';

// The staged Base Sepolia intent, for reference. On mainnet pass the real one.
const intentHash = process.env.INTENT_HASH
  ?? '0xfd728abd63355b81519bb4ce34cf8ca1690a14fb9f3af8b17432e93de453ae8e';

const intent = {
  intentHash,
  amount: process.env.INTENT_AMOUNT ?? '1000000',
  // String, like every other IntentDetails field. The server's Zod schema
  // rejects a number here with "Expected string, received number".
  timestampMs: String(process.env.INTENT_TIMESTAMP_MS ?? Date.now()),
  paymentMethod: '0x90262a3db0edd0be2369c6b28f9e8511ec0bac7136cefbada0880602f87e7268', // keccak("venmo")
  fiatCurrency: '0xc4ae21aac0c6549d71dd96035b7e0bdb6c79ebdba8891b666115bc976d16a29e', // keccak("USD")
  conversionRate: process.env.INTENT_RATE ?? '1000000000000000000',
  payeeDetails: process.env.PAYEE_HASH
    ?? '0x853410f0416f12611961e72ee5397ec6839a3f6475467f8a557bbdb3fc8555db', // @test-payee
};

console.log('attestation service :', attestationServiceUrl);
console.log('chainId             :', chainId, chainId === 8453 ? '' : '(enclave signs only for 8453)');
console.log('intentHash          :', intent.intentHash);
console.log('payeeDetails        :', intent.payeeDetails, '(@test-payee)');
console.log('feed index          :', index);
console.log('cookie              : <%d chars, not logged>', cookie.length);

// Pin the enclave before handing it anything.
const pinned = await fetchAndVerifyAttestation({ attestationServiceUrl, onWarning: () => {} });
const advertised = pinned?.payload?.advertised ?? {};
console.log('enclave signer      :', advertised.expectedSigner);
console.log('enclave chainId     :', advertised.chainId);
if (advertised.chainId !== chainId) {
  console.warn(`\n!! the enclave signs for chain ${advertised.chainId}, you asked for ${chainId}.`);
  console.warn('   the resulting attestation will NOT verify against chain', chainId);
}

if (!advertised.expectedSigner) {
  console.error('\nthe attestation document advertised no expectedSigner; refusing to run');
  console.error('without a signer to pin the local verification against.');
  process.exit(1);
}

const warnings = [];
let attestation;
try {
  attestation = await verifyBuyerTeePayment({
    platform: 'venmo',
    actionType: 'transfer_venmo',
    sessionMaterial: { Cookie: cookie, 'User-Agent': userAgent },
    params: { SENDER_ID: senderId, index },
    chainId,
    intent,
    attestationServiceUrl,
    onWarning: (w) => warnings.push(w?.code ?? String(w)),
  });
} catch (e) {
  console.error('\nattestation FAILED:', e?.message ?? e);
  // The service's own rejection reason rides on the error as a structured
  // ServiceResponse, not in the message. Print it; it is the only thing that
  // says *why* verify said no.
  if (e?.code) console.error('code              :', e.code);
  if (e?.details !== undefined) console.error('details           :', JSON.stringify(e.details, null, 2));
  if (e?.cause !== undefined) console.error('cause             :', JSON.stringify(e.cause, null, 2) ?? String(e.cause));
  if (process.env.PROVE_DEBUG) {
    console.error('raw error         :', JSON.stringify(e, Object.getOwnPropertyNames(e), 2));
  }
  console.error('\nCommon causes:');
  console.error('  - the cookie has expired: re-capture it from a fresh account.venmo.com request');
  console.error('  - SENDER_ID is the @handle instead of the numeric id');
  console.error('  - PAYMENT_INDEX points at a different payment; try 0, 1, 2');
  console.error('  - the payment is not visible in the "me" feed yet; wait and retry');
  process.exit(1);
}

console.log('\n=== ATTESTATION OBTAINED ===');
console.log('signer            :', attestation.signer);
console.log('domainSeparator   :', attestation.domainSeparator);
console.log('typedDataSpec     :', attestation.typedDataSpec);
console.log('typedDataValue    :', JSON.stringify(attestation.typedDataValue));
console.log('signature         :', attestation.signature);
if (attestation.metadata) console.log('metadata          :', JSON.stringify(attestation.metadata));
if (warnings.length) console.log('warnings          :', warnings.join(', '));

// Check the signature ourselves rather than trusting the round trip.
const verified = verifyBuyerTeePaymentAttestation(attestation, {
  expectedPlatform: 'venmo',
  expectedActionType: 'transfer_venmo',
  expectedDomain: { chainId, verifyingContract },
  expectedIntentHash: intent.intentHash,
  // Required. The signer we pinned from the Nitro attestation document above,
  // so this check rejects a signature from anything but that enclave.
  trustedSigners: [advertised.expectedSigner],
  onWarning: (w) => console.log('verify warning    :', w?.code ?? String(w)),
});
console.log('\nlocal verification: PASS');
if (verified?.releaseAmount !== undefined) console.log('releaseAmount     :', String(verified.releaseAmount));

writeFileSync(out, JSON.stringify({ attestation, intent, chainId, verifyingContract }, null, 2));
console.log('\nwrote', out);
console.log('This file is the proof that the $1 Venmo payment happened, signed by the Peer enclave.');

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
//   VENMO_SENDER_ID   required. the payer's NUMERIC Venmo id (not the @handle).
//   VENMO_USER_AGENT  the browser UA that cookie was captured with.
//   PAYMENT_INDEX     which entry in the feed, 0 = most recent (default 0).
//   INTENT_HASH       required. The intent to bind the attestation to, as it
//                     appears in the IntentSignaled log on chain.
//   INTENT_AMOUNT     required. Release amount in 6-decimal USDC units.
//   PAYEE_HASH        required. The curator's hashedOnchainId for the payee.
//   INTENT_TIMESTAMP_MS  the intent's on-chain signal time in milliseconds. The
//                     verifier compares it against the stored intent and reverts
//                     with "UPV: Snapshot timestamp mismatch" if it differs, so
//                     pass the real value for anything that will be submitted.
//   CHAIN_ID          default 8453. The enclave only signs for 8453.
//   VERIFIER          UnifiedPaymentVerifierV3, the EIP-712 verifyingContract.
//   ATTESTATION_URL   attestation service base URL.
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

// The enclaves we will encrypt a live Venmo cookie to, and the PCR8 each one
// must measure. These are the values @zkp2p/zkp2p-attestation ships in its own
// bundled table; naming them here means the pin does not depend on that table
// staying keyed by hostname, and means an unknown host is a refusal rather than
// a fallback.
//
// The fallback is the whole point. The library resolves a pin as: caller pin,
// then bundled table, then -- unless strictPin is set -- the PCR8 the service
// advertises about itself. Against an unknown host that last branch compares
// the enclave measurement to a number the server supplied, which is
// verification that cannot fail. One line in .env pointing ATTESTATION_URL at
// an attacker's host was enough to encrypt the cookie to a key they hold, and
// the cookie is full Venmo account access.
const TRUSTED_ENCLAVES = {
  'attestation-service.zkp2p.xyz':
    '41a4ae0b9b96752cab5addb7d22689b3070e564e29f90a54316fa33fa38ea51387a6e887ea4f5a4b0cc34f69cea3f40e',
  'attestation-service-staging.zkp2p.xyz':
    '5636e3bd96f847cf12cfd9de7faa8cad0e6fa00962ce16ba185f8e5ea57105abb3cc9cc34f1e1e4de3444ceabcca7485',
  'attestation-service-preprod.zkp2p.xyz':
    '5453c5bfb7d040285be5ba9af142f4fbdd9685d082f244b66c62bf7b22d8d02a638fa2e02b9a6fe8877953a9429209e0',
};

/// Resolve the attestation URL, refusing anything not on the allowlist.
///
/// ATTESTATION_URL stays overridable, because staging and preprod are real
/// destinations, but only to a host whose expected PCR8 we know. Pointing it
/// somewhere else now fails here rather than silently downgrading the pin.
function resolveAttestationService(raw) {
  let url;
  try {
    url = new URL(raw);
  } catch {
    console.error(`ATTESTATION_URL is not a valid URL: ${raw}`);
    process.exit(2);
  }

  if (url.protocol !== 'https:') {
    console.error(`ATTESTATION_URL must be https, got ${url.protocol}//. The Venmo cookie`);
    console.error('is encrypted to the enclave, but the request itself is not something');
    console.error('to hand to a plaintext connection.');
    process.exit(2);
  }

  const hostname = url.hostname.toLowerCase();
  const expectedPcr8Hex = TRUSTED_ENCLAVES[hostname];
  if (!expectedPcr8Hex) {
    console.error(`refusing to send a Venmo cookie to ${hostname}: no PCR8 pin is known for it.`);
    console.error('Known hosts:');
    for (const known of Object.keys(TRUSTED_ENCLAVES)) console.error(`  ${known}`);
    console.error('');
    console.error('Without a pin, the enclave measurement would be compared against a');
    console.error('number the server itself supplied, which is not verification. Add the');
    console.error("host and its PCR8 to TRUSTED_ENCLAVES if it is genuinely yours.");
    process.exit(2);
  }

  return { attestationServiceUrl: raw, hostname, expectedPcr8Hex };
}

const { attestationServiceUrl, hostname: attestationHostname, expectedPcr8Hex } =
  resolveAttestationService(process.env.ATTESTATION_URL ?? 'https://attestation-service.zkp2p.xyz');
const chainId = Number(process.env.CHAIN_ID ?? 8453);
const verifyingContract = process.env.VERIFIER ?? '0xC6F4a193576C60892a47e111Bb5706c30162502B';
const index = Number(process.env.PAYMENT_INDEX ?? 0);
const out = process.env.OUT ?? 'attestation.json';

const cookie = need('VENMO_COOKIE');
const senderId = need('VENMO_SENDER_ID');
const userAgent = process.env.VENMO_USER_AGENT
  ?? 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36';

// The intent this attestation is bound to. There is no sensible default: an
// attestation minted for the wrong intent is rejected by the verifier, and a
// stale built-in default is the easiest way to mint one by accident.
const intentHash = need('INTENT_HASH');
const payeeDetails = need('PAYEE_HASH');
const intentAmount = need('INTENT_AMOUNT');

if (!/^0x[0-9a-fA-F]{64}$/.test(intentHash)) {
  console.error(`INTENT_HASH is not a 32-byte hex value: ${intentHash}`);
  process.exit(2);
}
if (!/^0x[0-9a-fA-F]{64}$/.test(payeeDetails)) {
  console.error(`PAYEE_HASH is not a 32-byte hex value: ${payeeDetails}`);
  process.exit(2);
}
if (!/^[0-9]+$/.test(intentAmount)) {
  console.error(`INTENT_AMOUNT must be an integer in 6-decimal USDC units: ${intentAmount}`);
  process.exit(2);
}
if (!process.env.INTENT_TIMESTAMP_MS) {
  console.warn('INTENT_TIMESTAMP_MS unset: using the wall clock. The verifier');
  console.warn('compares this against the intent stored on chain, so an');
  console.warn('attestation built this way will not fulfil a real intent.');
}

const intent = {
  intentHash,
  amount: intentAmount,
  // String, like every other IntentDetails field. The server's Zod schema
  // rejects a number here with "Expected string, received number".
  timestampMs: String(process.env.INTENT_TIMESTAMP_MS ?? Date.now()),
  paymentMethod: '0x90262a3db0edd0be2369c6b28f9e8511ec0bac7136cefbada0880602f87e7268', // keccak("venmo")
  fiatCurrency: '0xc4ae21aac0c6549d71dd96035b7e0bdb6c79ebdba8891b666115bc976d16a29e', // keccak("USD")
  conversionRate: process.env.INTENT_RATE ?? '1000000000000000000',
  payeeDetails,
};

console.log('attestation service :', attestationServiceUrl);
console.log('chainId             :', chainId, chainId === 8453 ? '' : '(enclave signs only for 8453)');
console.log('intentHash          :', intent.intentHash);
console.log('payeeDetails        :', intent.payeeDetails);
console.log('feed index          :', index);
console.log('cookie              : <%d chars, not logged>', cookie.length);

// Pin the enclave before handing it anything.
//
// strictPin makes an unpinned host throw instead of falling back to the PCR8 the
// service advertises about itself, and the explicit expectedPcr8Hex is the pin
// this script is willing to trust rather than whatever table the library ships.
// Warnings are collected rather than discarded: any of them here is a reason not
// to send the cookie.
const pinWarnings = [];
let pinned;
try {
  pinned = await fetchAndVerifyAttestation({
    attestationServiceUrl,
    trust: { expectedPcr8Hex, strictPin: true },
    onWarning: (w) => pinWarnings.push(w?.code ?? String(w)),
  });
} catch (e) {
  console.error('\nenclave attestation FAILED:', e?.message ?? e);
  if (e?.code) console.error('code              :', e.code);
  console.error('\nNothing was sent. The cookie has not been read.');
  process.exit(1);
}

// Any warning at this stage is about the identity of the thing we are about to
// hand a live Venmo session to. There is no such thing as a warning here worth
// proceeding past.
// Benign-by-construction: the library emits CERT_VALIDITY_NEAR_EXPIRY purely
// because an AWS Nitro leaf cert expires within 7 days. Nitro enclave leaf certs
// rotate roughly every 3 hours, so this fires on every healthy production
// enclave. A cert actually OUTSIDE its validity window raises CERT_NOT_TIME_VALID
// and throws, and a wrong enclave raises PCR8_PIN_MISMATCH and throws; neither is
// a warning. Every other warning code is still fatal here, and the PCR8 pin,
// chain-to-AWS-root, COSE signature, nonce binding and freshness checks all still
// run unchanged inside fetchAndVerifyAttestation above.
const BENIGN = new Set(['CERT_VALIDITY_NEAR_EXPIRY']);
const fatalWarnings = pinWarnings.filter((w) => !BENIGN.has(String(w)));
if (fatalWarnings.length) {
  console.error('\nthe enclave attestation raised warnings:', fatalWarnings.join(', '));
  console.error('refusing to send the cookie. A pin warning means the enclave is not');
  console.error('the one this script pinned, or could not be checked against it.');
  process.exit(1);
}
if (pinWarnings.length) {
  console.log('advisory (ignored)  :', pinWarnings.join(', '));
}
// Belt and braces: assert the pin matched the production value explicitly,
// independently of the library's own comparison.
const EXPECTED_PCR8 = '41a4ae0b9b96752cab5addb7d22689b3070e564e29f90a54316fa33fa38ea51387a6e887ea4f5a4b0cc34f69cea3f40e';
if (String(pinned?.payload?.pcr8Hex).toLowerCase() !== EXPECTED_PCR8) {
  console.error('\nPCR8 MISMATCH. Refusing to send the cookie.');
  console.error('  actual  :', pinned?.payload?.pcr8Hex);
  console.error('  expected:', EXPECTED_PCR8);
  process.exit(1);
}
console.log('PCR8 asserted       : matches pinned production value');

console.log('attestation pin     : PCR8 verified against the pinned value');

const advertised = pinned?.payload?.advertised ?? {};
console.log('enclave signer      :', advertised.expectedSigner);
console.log('enclave chainId     :', advertised.chainId);

// Both of these used to warn and then send the cookie anyway. Spending a cookie
// exposure on an attestation the script has already predicted will not verify is
// never right.
if (advertised.chainId !== chainId) {
  console.error(`\nthe enclave signs for chain ${advertised.chainId}, you asked for ${chainId}.`);
  console.error('the resulting attestation would not verify against chain', chainId);
  console.error('Nothing was sent.');
  process.exit(1);
}

if (
  advertised.verifyingContract &&
  advertised.verifyingContract.toLowerCase() !== verifyingContract.toLowerCase()
) {
  console.error(`\nthe enclave signs for verifier ${advertised.verifyingContract},`);
  console.error(`you asked for ${verifyingContract}. The attestation would not verify.`);
  console.error('Nothing was sent.');
  process.exit(1);
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
    // The same pin as the fetch above. This is the call that encrypts and
    // transmits the cookie, so it is the one that matters most, and it used to
    // pass no `trust` at all (NEW-5 in the 2026-08-31 re-audit). It still
    // pinned hard, because the library consults its bundled table before the
    // strictPin throw and the allowlist restricts the host to the three bundled
    // ones. What it did not do is pin to the values named in this file, which
    // is the independence the comment above claims. With a caret range in
    // package.json, a 3.x release that rotated a PCR8 would have left the two
    // calls pinning to different numbers without a word.
    trust: { expectedPcr8Hex, strictPin: true },
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
if (warnings.length) {
  console.error('warnings          :', warnings.join(', '));
  // TRUST_PIN_NOT_PROVIDED here would mean the pin degraded on this call even
  // though the fetch above was strict. The cookie is already spent at this
  // point, but the attestation is not something to trust or submit.
  if (warnings.some((w) => String(w).startsWith('TRUST_PIN'))) {
    console.error('\na pin warning on the payment call means the enclave was not the');
    console.error('pinned one. Refusing to write this attestation out.');
    process.exit(1);
  }
}

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
console.log('This file is the proof that the Venmo payment happened, signed by the Peer enclave.');

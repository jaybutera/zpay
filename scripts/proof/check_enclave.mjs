// Read-only: proves the Peer TEE attestation service is reachable and that its
// AWS Nitro attestation document verifies to the AWS Nitro root. Sends no
// cookies, no payment data, and nothing about the operator. Costs nothing.
import { fetchAndVerifyAttestation, getUnifiedPaymentVerifierDomainSeparator } from '@zkp2p/zkp2p-attestation';

// The enclaves we trust, and the PCR8 each must measure. Same table as
// prove_payment.mjs; a host that is not here has no pin, and without a pin the
// library falls back to comparing PCR8 against a number the server supplied,
// which is verification that cannot fail.
const TRUSTED_ENCLAVES = {
  'attestation-service.zkp2p.xyz':
    '41a4ae0b9b96752cab5addb7d22689b3070e564e29f90a54316fa33fa38ea51387a6e887ea4f5a4b0cc34f69cea3f40e',
  'attestation-service-staging.zkp2p.xyz':
    '5636e3bd96f847cf12cfd9de7faa8cad0e6fa00962ce16ba185f8e5ea57105abb3cc9cc34f1e1e4de3444ceabcca7485',
  'attestation-service-preprod.zkp2p.xyz':
    '5453c5bfb7d040285be5ba9af142f4fbdd9685d082f244b66c62bf7b22d8d02a638fa2e02b9a6fe8877953a9429209e0',
};

const url = process.env.ATTESTATION_URL ?? 'https://attestation-service.zkp2p.xyz';
const verifier = process.env.VERIFIER ?? '0xC6F4a193576C60892a47e111Bb5706c30162502B';

const parsed = new URL(url);
if (parsed.protocol !== 'https:') {
  console.error(`ATTESTATION_URL must be https, got ${parsed.protocol}//`);
  process.exit(2);
}
const expectedPcr8Hex = TRUSTED_ENCLAVES[parsed.hostname.toLowerCase()];
if (!expectedPcr8Hex) {
  console.error(`no PCR8 pin is known for ${parsed.hostname}. Known hosts:`);
  for (const known of Object.keys(TRUSTED_ENCLAVES)) console.error(`  ${known}`);
  process.exit(2);
}

const warnings = [];
const att = await fetchAndVerifyAttestation({
  attestationServiceUrl: url,
  // Pin explicitly and refuse to fall back. Without this the check reports a
  // pass for any host, which is worse than not running it.
  trust: { expectedPcr8Hex, strictPin: true },
  onWarning: (w) => warnings.push(w?.code ?? String(w)),
});
console.log('attestation service :', url);
console.log('verified to AWS Nitro root : yes');
console.log('PCR8 pinned         : yes');
for (const k of ['pcr8', 'pcr0', 'moduleId', 'timestamp']) {
  const v = att?.[k] ?? att?.document?.[k] ?? att?.pcrs?.[k];
  if (v !== undefined) console.log(`${k.padEnd(20)}:`, typeof v === 'string' ? v.slice(0, 80) : v);
}
console.log('publicKey present   :', Boolean(att?.publicKey ?? att?.document?.public_key));
if (warnings.length) {
  console.error('warnings            :', warnings.join(', '));
  // A pin warning means the enclave is not the one pinned, or could not be
  // checked against it. This script exists to answer that question, so it must
  // not exit 0 having seen one.
  if (warnings.some((w) => String(w).startsWith('TRUST_PIN'))) {
    console.error('a pin warning means the enclave is not the pinned one.');
    process.exit(1);
  }
}

// The EIP-712 domain the enclave signs against is pinned to chain + verifier.
for (const [chainId, label] of [[8453, 'Base mainnet'], [84532, 'Base Sepolia']]) {
  const ds = getUnifiedPaymentVerifierDomainSeparator({ chainId, verifyingContract: verifier });
  console.log(`domainSeparator ${String(chainId).padEnd(6)} (${label}) : ${ds}`);
}

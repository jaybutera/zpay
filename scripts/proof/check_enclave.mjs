// Read-only: proves the Peer TEE attestation service is reachable and that its
// AWS Nitro attestation document verifies to the AWS Nitro root. Sends no
// cookies, no payment data, and nothing about Casper. Costs nothing.
import { fetchAndVerifyAttestation, getUnifiedPaymentVerifierDomainSeparator } from '@zkp2p/zkp2p-attestation';

const url = process.env.ATTESTATION_URL ?? 'https://attestation-service.zkp2p.xyz';
const verifier = process.env.VERIFIER ?? '0xC6F4a193576C60892a47e111Bb5706c30162502B';
const warnings = [];
const att = await fetchAndVerifyAttestation({
  attestationServiceUrl: url,
  onWarning: (w) => warnings.push(w?.code ?? String(w)),
});
console.log('attestation service :', url);
console.log('verified to AWS Nitro root : yes');
for (const k of ['pcr8', 'pcr0', 'moduleId', 'timestamp']) {
  const v = att?.[k] ?? att?.document?.[k] ?? att?.pcrs?.[k];
  if (v !== undefined) console.log(`${k.padEnd(20)}:`, typeof v === 'string' ? v.slice(0, 80) : v);
}
console.log('publicKey present   :', Boolean(att?.publicKey ?? att?.document?.public_key));
if (warnings.length) console.log('warnings            :', warnings.join(', '));

// The EIP-712 domain the enclave signs against is pinned to chain + verifier.
for (const [chainId, label] of [[8453, 'Base mainnet'], [84532, 'Base Sepolia']]) {
  const ds = getUnifiedPaymentVerifierDomainSeparator({ chainId, verifyingContract: verifier });
  console.log(`domainSeparator ${String(chainId).padEnd(6)} (${label}) : ${ds}`);
}

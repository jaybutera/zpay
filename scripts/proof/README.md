# Standalone Venmo payment proof

Generates a real Peer (zk-p2p) payment attestation for a real Venmo payment,
without the PeerAuth browser extension and without touching any chain. The
extension was only ever a cookie-capture UI; proving itself is a plain HTTPS
call, which is what this script makes.

## What a "proof" is here

Not a ZK proof. Peer's V3 moved payment verification into an AWS Nitro enclave.
The enclave takes your logged-in Venmo session, replays

```
GET https://account.venmo.com/api/stories?feedType=me&externalId=<SENDER_ID>
```

from inside the enclave, finds the payment at `$.stories[<index>]`, and returns
an ECDSA **EIP-712** signature over
`PaymentAttestation(bytes32 intentHash, uint256 releaseAmount, bytes32 dataHash)`.
That signature is what `OrchestratorV3.fulfillIntent` accepts on Base mainnet.

The cookie is encrypted client-side into a JWE against the enclave's public key,
and we verify that key's AWS Nitro attestation document to the AWS root before
sending anything. The service operator cannot read the cookie outside the
enclave. It is still as powerful as the raw cookie, so this script never writes
it to disk and never logs it.

## Chain binding (why this cannot run on Base Sepolia)

The enclave advertises `chainId: 8453` and signs an EIP-712 domain bound to that
chain plus `UnifiedPaymentVerifierV3 0xC6F4a193576C60892a47e111Bb5706c30162502B`.
The domain separators differ per chain:

| chain | domainSeparator |
|---|---|
| 8453 Base mainnet | `0xe27fb63a4c62dd4015ccc6378579f3bb3759a7fc50a072a670cb7d0fc0f164f9` |
| 84532 Base Sepolia | `0xf9465d2ffa893d1c13854b37f54fc3a43fb462eb91f5a69d3960a91d10492e7a` |

So an attestation is valid only against Base mainnet. Peer publishes no Sepolia
deployment at all: `@zkp2p/contracts-v2` ships exactly two networks, `base` and
`baseStaging`, and both declare `chainId 8453`.

## Check the service first (spends nothing, sends nothing personal)

```bash
node scripts/proof/check_enclave.mjs
```

## Capture the two inputs

Both come from a browser already logged into Venmo.

**1. The cookie.** In Chrome on `https://account.venmo.com/?feed=mine`:
DevTools -> Network -> reload -> click any `account.venmo.com` request ->
Headers -> Request Headers -> copy the whole `Cookie:` value.

**2. The numeric SENDER_ID.** Not the `@handle`. With the same tab open, in the
DevTools Console:

```js
await (await fetch('/api/stories?feedType=me', {credentials:'include'}))
  .json().then(d => d.stories[0].title.sender.id)
```

Or find `externalId=` in the URL of the stories request in the Network tab.

## Generate the proof

The coordinator drives `prove_payment_pinned.mjs` itself. By hand:

```bash
export VENMO_COOKIE='<the whole Cookie header>'
export VENMO_SENDER_ID='<numeric id>'
export INTENT_HASH=0x...          # required; from the IntentSignaled log
export PAYEE_HASH=0x...           # required; the curator's hashedOnchainId
export INTENT_AMOUNT=1000000      # required; 6-decimal USDC units
export INTENT_TIMESTAMP_MS=...    # the intent's on-chain signal time, in ms
export PAYMENT_INDEX=0            # 0 = most recent payment in your feed
node scripts/proof/prove_payment.mjs
```

`INTENT_TIMESTAMP_MS` is not optional in practice. `UnifiedPaymentVerifierV3`
compares the attested snapshot's timestamp against the intent stored on chain
and reverts with `UPV: Snapshot timestamp mismatch` if they differ, so an
attestation built from the wall clock verifies locally and then fails on chain.

Writes `attestation.json` with the signature, the signer, the EIP-712 typed
data, and the intent it is bound to. Expected signer today:
`0xe078d93bfdd87a8c5c5cca5905dcba0dd7a1f0bd`.

The script verifies the signature locally with
`verifyBuyerTeePaymentAttestation` before writing, so a PASS means the
attestation really is well-formed and correctly signed, not merely returned.

## Useful env overrides

| Var | Meaning |
|---|---|
| `INTENT_HASH` | required. The intent to bind to, from its `IntentSignaled` log |
| `PAYEE_HASH` | required. The curator's `hashedOnchainId` for the payee |
| `INTENT_AMOUNT` | required. 6-decimal USDC units |
| `INTENT_TIMESTAMP_MS` | the intent's on-chain signal time in ms; see above |
| `PAYMENT_INDEX` | feed position, try 0 then 1, 2 |
| `CHAIN_ID` | default 8453; the enclave only signs for 8453 |
| `VERIFIER` | the EIP-712 verifyingContract |
| `ATTESTATION_URL` | default `https://attestation-service.zkp2p.xyz` |

There are no defaults for the first three on purpose. An attestation minted
against a stale built-in intent is the easiest way to produce a signature that
looks right and fulfils nothing.

## Notes

- No API key is needed. A run with a deliberately invalid cookie reached the
  service and came back `POST /buyer/verify returned an unsuccessful
  ServiceResponse`, which confirms the endpoint is open and the failure is
  authentication of the Venmo session, not authorization of the caller.
- The enclave enforces no capture-age or one-use replay limit on buyer session
  material, so treat the JWE as equivalent to the cookie itself.

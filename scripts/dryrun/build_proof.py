#!/usr/bin/env python3
"""Turn an attestation.json from scripts/proof into fulfillIntent calldata.

The `paymentProof` layout was not guessed: it was decoded from a real accepted
mainnet fulfillIntent, tx 0xad5a0d99...dac7, as

    (bytes32 intentHash, uint256 releaseAmount, bytes32 dataHash,
     bytes[] signatures, bytes paymentDetails, bytes metadata)

with the invariant dataHash == keccak(paymentDetails), which our attestation
also satisfies.

Usage: build_proof.py <attestation.json>   -> prints 0x-hex paymentProof
"""
import json
import sys

from eth_abi import encode as abienc
from eth_utils import keccak

PROOF_TYPE = "(bytes32,uint256,bytes32,bytes[],bytes,bytes)"


def build(att):
    v = att["typedDataValue"]
    details = bytes.fromhex(att["encodedPaymentDetails"][2:])
    if "0x" + keccak(details).hex() != v["dataHash"].lower():
        raise SystemExit("dataHash != keccak(encodedPaymentDetails); refusing to build")
    meta = att.get("metadata") or "0x"
    if isinstance(meta, str) and meta.startswith("0x"):
        meta = bytes.fromhex(meta[2:])
    return abienc(
        [PROOF_TYPE],
        [(
            bytes.fromhex(v["intentHash"][2:]),
            int(v["releaseAmount"]),
            bytes.fromhex(v["dataHash"][2:]),
            [bytes.fromhex(att["signature"][2:])],
            details,
            meta,
        )],
    )


if __name__ == "__main__":
    doc = json.load(open(sys.argv[1]))
    print("0x" + build(doc["attestation"]).hex())

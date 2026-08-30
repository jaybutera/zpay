#!/usr/bin/env python3
"""Buy gas ETH with USDC, for a key that holds USDC but no ETH.

A fresh deployer funded only from the Circle faucet has USDC and no way to pay
gas. This does the swap without needing ETH first: the EOA delegates to a
Simple7702Account (EIP-7702), so it becomes the sender of an ERC-4337
UserOperation and signs everything with its own key. Gas is paid in USDC through
the Circle paymaster, and the swap output is unwrapped straight to the EOA.

One UserOperation, batched:
  1. USDC.approve(SwapRouter02, amount)
  2. router.multicall[ exactInputSingle(USDC -> WETH), unwrapWETH9(-> EOA) ]

The 7702 authorization is only signed when the EOA is not already delegated;
re-runs skip it. Only the deployer key signs: the authorization, the EIP-2612
permit to the paymaster, and the UserOperation.

Usage:
  scripts/testnet/03_usdc_to_eth_aa.py --amount 5 --dry-run
  scripts/testnet/03_usdc_to_eth_aa.py --amount 5

Env:
  PRIVATE_KEY            deployer key, holds the USDC (required; or --key-file)
  BASE_SEPOLIA_RPC_URL   default https://sepolia.base.org
  AA_BUNDLER_URL         default https://public.pimlico.io/v2/84532/rpc

--dry-run does everything except submit: it quotes the swap, signs, and runs the
bundler's gas estimation, which exercises paymaster validation on-chain. If a
dry run passes, the real one generally does too.

Defaults target Base Sepolia (84532). The contract addresses below are that
chain's; --chain-id alone will not move it to another network.
"""
import argparse
import json
import os
import sys
import time

import requests
from eth_abi import encode as abi_encode
from eth_account import Account
from eth_utils import keccak, to_checksum_address

# Base Sepolia. EntryPoint v0.8 and the paymaster that is staked on it.
DEFAULTS = {
    "chain_id": 84532,
    "rpc": "https://sepolia.base.org",
    "bundler": "https://public.pimlico.io/v2/84532/rpc",
    "usdc": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
    "weth": "0x4200000000000000000000000000000000000006",
    "router": "0x94cC0AaC535CCDB3C01d6787D6413C739ae12bc4",
    "quoter": "0xC5290058841028F1614F3A6F0F5816cAd0df5E27",
    "entrypoint": "0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108",
    "paymaster": "0x3BA9A96eE3eFf3A69E2B18886AcF52027EFF8966",
    "delegate": "0xe6Cae83BdE06E4c305530e199D7217f42808555B",
    "pool_fee": 3000,
}

# The paymaster refunds in postOp and reverts if given less gas than its own
# additionalGasCharge(). Bundler estimates come in under that, so pin a floor.
POSTOP_GAS_FLOOR = 25_000
# USDC permit deadline. The paymaster rejects short deadlines; use no expiry.
PERMIT_DEADLINE = 2**256 - 1


class Rpc:
    def __init__(self, url):
        self.url = url

    def __call__(self, method, params):
        r = requests.post(
            self.url,
            json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
            timeout=120,
        )
        body = r.json()
        if "error" in body:
            raise RuntimeError(f"{method}: {json.dumps(body['error'])[:600]}")
        return body["result"]


def selector(sig):
    return keccak(text=sig)[:4]


def encode_call(sig, types, values):
    return selector(sig) + abi_encode(types, values)


def pack_two(hi, lo):
    """Two uint128 into one bytes32, as ERC-4337 packs gas limits and fees."""
    return (hi << 128 | lo).to_bytes(32, "big")


def load_key(args):
    if args.key_file:
        for line in open(args.key_file):
            if line.startswith("PRIVATE_KEY="):
                return line.split("=", 1)[1].strip()
        sys.exit(f"no PRIVATE_KEY line in {args.key_file}")
    key = os.environ.get("PRIVATE_KEY")
    if not key:
        sys.exit("set PRIVATE_KEY, or pass --key-file")
    return key.strip()


def sign_permit(key, eoa, usdc, spender, value, nonce, chain_id):
    """EIP-2612 permit letting the paymaster take USDC for gas."""
    message = {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "Permit": [
                {"name": "owner", "type": "address"},
                {"name": "spender", "type": "address"},
                {"name": "value", "type": "uint256"},
                {"name": "nonce", "type": "uint256"},
                {"name": "deadline", "type": "uint256"},
            ],
        },
        "primaryType": "Permit",
        "domain": {
            "name": "USDC",
            "version": "2",
            "chainId": chain_id,
            "verifyingContract": usdc,
        },
        "message": {
            "owner": eoa,
            "spender": spender,
            "value": value,
            "nonce": nonce,
            "deadline": PERMIT_DEADLINE,
        },
    }
    signed = Account.sign_typed_data(key, full_message=message)
    return signed.r.to_bytes(32, "big") + signed.s.to_bytes(32, "big") + bytes([signed.v])


def main():
    ap = argparse.ArgumentParser(description="Swap USDC for gas ETH via ERC-4337.")
    ap.add_argument("--amount", type=float, required=True, help="USDC to swap, e.g. 5")
    ap.add_argument("--max-gas-usdc", type=float, default=3.0,
                    help="cap on USDC the paymaster may take for gas (default 3)")
    ap.add_argument("--slippage-bps", type=int, default=300,
                    help="slippage tolerance in basis points (default 300 = 3%%)")
    ap.add_argument("--dry-run", action="store_true",
                    help="quote, sign and estimate, but do not submit")
    ap.add_argument("--key-file", help="read PRIVATE_KEY from this file instead of env")
    ap.add_argument("--chain-id", type=int, default=DEFAULTS["chain_id"])
    ap.add_argument("--rpc", default=os.environ.get("BASE_SEPOLIA_RPC_URL", DEFAULTS["rpc"]))
    ap.add_argument("--bundler", default=os.environ.get("AA_BUNDLER_URL", DEFAULTS["bundler"]))
    ap.add_argument("--pool-fee", type=int, default=DEFAULTS["pool_fee"],
                    help="Uniswap v3 fee tier (default 3000; the deepest USDC/WETH pool)")
    ap.add_argument("--timeout", type=int, default=300, help="seconds to wait for the receipt")
    args = ap.parse_args()

    swap_usdc = int(round(args.amount * 10**6))
    max_gas_usdc = int(round(args.max_gas_usdc * 10**6))
    if swap_usdc <= 0:
        sys.exit("--amount must be positive")

    usdc = to_checksum_address(DEFAULTS["usdc"])
    weth = to_checksum_address(DEFAULTS["weth"])
    router = to_checksum_address(DEFAULTS["router"])
    quoter = to_checksum_address(DEFAULTS["quoter"])
    entrypoint = to_checksum_address(DEFAULTS["entrypoint"])
    paymaster = to_checksum_address(DEFAULTS["paymaster"])
    delegate = to_checksum_address(DEFAULTS["delegate"])

    rpc = Rpc(args.rpc)
    bundler = Rpc(args.bundler)

    key = load_key(args)
    account = Account.from_key(key)
    eoa = to_checksum_address(account.address)

    def call(to, data):
        return rpc("eth_call", [{"to": to, "data": "0x" + data.hex()}, "latest"])

    chain_id = int(rpc("eth_chainId", []), 16)
    if chain_id != args.chain_id:
        sys.exit(f"RPC is chain {chain_id}, expected {args.chain_id}")

    print(f"EOA        {eoa}")
    print(f"chain      {chain_id} via {args.rpc}")

    balance = int(call(usdc, encode_call("balanceOf(address)", ["address"], [eoa])), 16)
    eth_before = int(rpc("eth_getBalance", [eoa, "latest"]), 16)
    print(f"USDC       {balance / 1e6}")
    print(f"ETH        {eth_before / 1e18}")
    if balance < swap_usdc + max_gas_usdc:
        sys.exit(f"need {(swap_usdc + max_gas_usdc) / 1e6} USDC (swap + gas cap), have {balance / 1e6}")

    code = rpc("eth_getCode", [eoa, "latest"])
    delegated = code.startswith("0xef0100")
    if delegated:
        current = to_checksum_address("0x" + code[8:48])
        print(f"delegated  yes -> {current}")
        if current != delegate:
            sys.exit(f"EOA is delegated to {current}, not {delegate}; refusing to redelegate")
    else:
        print("delegated  no, will authorize this run")

    # Quote the swap so we can set a slippage floor.
    quoted = call(quoter, encode_call(
        "quoteExactInputSingle((address,address,uint256,uint24,uint160))",
        ["(address,address,uint256,uint24,uint160)"],
        [(usdc, weth, swap_usdc, args.pool_fee, 0)]))
    amount_out = int(quoted[2:66], 16)
    min_out = amount_out * (10_000 - args.slippage_bps) // 10_000
    print(f"quote      {swap_usdc / 1e6} USDC -> {amount_out / 1e18} ETH (min {min_out / 1e18})")

    # Approve the router, then swap and unwrap in one router multicall. The
    # swap sends WETH to the router itself so unwrapWETH9 can pay out native
    # ETH directly to the EOA.
    approve = encode_call("approve(address,uint256)", ["address", "uint256"], [router, swap_usdc])
    swap = encode_call(
        "exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))",
        ["(address,address,uint24,address,uint256,uint256,uint160)"],
        [(usdc, weth, args.pool_fee, router, swap_usdc, min_out, 0)])
    unwrap = encode_call("unwrapWETH9(uint256,address)", ["uint256", "address"], [min_out, eoa])
    router_call = encode_call("multicall(bytes[])", ["bytes[]"], [[swap, unwrap]])
    call_data = "0x" + encode_call(
        "executeBatch((address,uint256,bytes)[])",
        ["(address,uint256,bytes)[]"],
        [[(usdc, 0, approve), (router, 0, router_call)]]).hex()

    permit_nonce = int(call(usdc, encode_call("nonces(address)", ["address"], [eoa])), 16)
    permit_sig = sign_permit(key, eoa, usdc, paymaster, max_gas_usdc, permit_nonce, chain_id)
    # Circle paymasterData: reserved byte, token, max USDC for gas, permit sig.
    paymaster_data = (bytes([0]) + bytes.fromhex(usdc[2:])
                      + max_gas_usdc.to_bytes(32, "big") + permit_sig)

    op = {
        "sender": eoa,
        "nonce": hex(int(call(entrypoint, encode_call(
            "getNonce(address,uint192)", ["address", "uint192"], [eoa, 0])), 16)),
        "callData": call_data,
        "callGasLimit": "0x100000",
        "verificationGasLimit": "0x100000",
        "preVerificationGas": "0x100000",
        "paymaster": paymaster,
        "paymasterVerificationGasLimit": "0x40000",
        "paymasterPostOpGasLimit": hex(POSTOP_GAS_FLOOR),
        "paymasterData": "0x" + paymaster_data.hex(),
        "signature": "0x" + "11" * 32 + "22" * 32 + "1c",
    }
    if not delegated:
        eoa_nonce = int(rpc("eth_getTransactionCount", [eoa, "latest"]), 16)
        auth = account.sign_authorization(
            {"chainId": chain_id, "address": delegate, "nonce": eoa_nonce})
        op["eip7702Auth"] = {
            "chainId": hex(chain_id), "address": delegate, "nonce": hex(eoa_nonce),
            "r": hex(auth.r), "s": hex(auth.s), "yParity": hex(auth.y_parity),
        }

    gas_price = bundler("pimlico_getUserOperationGasPrice", [])["standard"]
    op["maxFeePerGas"] = gas_price["maxFeePerGas"]
    op["maxPriorityFeePerGas"] = gas_price["maxPriorityFeePerGas"]

    def as_int(field):
        return int(op[field], 16)

    def sign_op():
        """EntryPoint v0.8 hashes the packed op as EIP-712 over its own domain."""
        packed_paymaster = (
            bytes.fromhex(paymaster[2:])
            + as_int("paymasterVerificationGasLimit").to_bytes(16, "big")
            + as_int("paymasterPostOpGasLimit").to_bytes(16, "big")
            + bytes.fromhex(op["paymasterData"][2:]))
        typehash = keccak(text=(
            "PackedUserOperation(address sender,uint256 nonce,bytes initCode,"
            "bytes callData,bytes32 accountGasLimits,uint256 preVerificationGas,"
            "bytes32 gasFees,bytes paymasterAndData)"))
        struct_hash = keccak(abi_encode(
            ["bytes32", "address", "uint256", "bytes32", "bytes32",
             "bytes32", "uint256", "bytes32", "bytes32"],
            [typehash, eoa, as_int("nonce"), keccak(b""),
             keccak(bytes.fromhex(call_data[2:])),
             pack_two(as_int("verificationGasLimit"), as_int("callGasLimit")),
             as_int("preVerificationGas"),
             pack_two(as_int("maxPriorityFeePerGas"), as_int("maxFeePerGas")),
             keccak(packed_paymaster)]))
        domain = bytes.fromhex(rpc("eth_call", [
            {"to": entrypoint, "data": "0x" + selector("getDomainSeparatorV4()").hex()},
            "latest"])[2:])
        digest = keccak(b"\x19\x01" + domain + struct_hash)
        signed = Account.unsafe_sign_hash(digest, private_key=key)
        op["signature"] = "0x" + signed.signature.hex().removeprefix("0x")

    # The paymaster validates the permit during estimation, so the op has to
    # carry a real signature before we can estimate, then be re-signed once the
    # estimated gas values are folded in.
    sign_op()
    estimate = bundler("eth_estimateUserOperationGas", [op, entrypoint])
    for field in ("callGasLimit", "verificationGasLimit", "preVerificationGas",
                  "paymasterVerificationGasLimit", "paymasterPostOpGasLimit"):
        if field in estimate:
            op[field] = estimate[field]
    if as_int("paymasterPostOpGasLimit") < POSTOP_GAS_FLOOR:
        op["paymasterPostOpGasLimit"] = hex(POSTOP_GAS_FLOOR)
    sign_op()
    print(f"estimated  {json.dumps(estimate)}")

    if args.dry_run:
        print("\ndry run: validated against the bundler, nothing submitted")
        return 0

    op_hash = bundler("eth_sendUserOperation", [op, entrypoint])
    print(f"userOp     {op_hash}")

    deadline = time.time() + args.timeout
    receipt = None
    while time.time() < deadline:
        time.sleep(5)
        receipt = bundler("eth_getUserOperationReceipt", [op_hash])
        if receipt:
            break
    if not receipt:
        print(f"no receipt within {args.timeout}s; check {op_hash}", file=sys.stderr)
        return 1

    tx = receipt["receipt"]["transactionHash"]
    if not receipt.get("success"):
        print(f"UserOperation reverted, tx {tx}", file=sys.stderr)
        return 1

    eth_after = int(rpc("eth_getBalance", [eoa, "latest"]), 16)
    usdc_after = int(call(usdc, encode_call("balanceOf(address)", ["address"], [eoa])), 16)
    print(f"tx         {tx}")
    print(f"ETH        {eth_before / 1e18} -> {eth_after / 1e18} (+{(eth_after - eth_before) / 1e18})")
    print(f"USDC       {balance / 1e6} -> {usdc_after / 1e6} "
          f"(swap {swap_usdc / 1e6}, gas {(balance - usdc_after - swap_usdc) / 1e6})")
    return 0


if __name__ == "__main__":
    sys.exit(main())

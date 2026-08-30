#!/usr/bin/env python3
"""Mock of the NEAR Intents 1Click endpoints the coordinator uses.

Fakes the ZEC -> USDC leg for dry runs. The coordinator asks for a quote,
gets a made-up deposit address, and polls /v0/status until it says SUCCESS.
Nothing moves USDC here: the dry-run script transfers test USDC to the
GlueContract itself, then flips this server's status to SUCCESS so the
keeper picks it up.

Response shapes come from the published 1Click OpenAPI document
(https://1click.chaindefuser.com/docs/v0/openapi.yaml), not from our Rust
structs. Deriving them from the spec is the point: a mock written to match our
own types cannot catch a mismatch between our types and the API.

Two details this reproduces that a hand-written mock got wrong:
  - /v0/quote answers 201, not 200
  - settled amounts and chain hashes live inside `swapDetails`, and the chain
    hashes are arrays of {hash, explorerUrl} objects rather than bare strings

Endpoints:
  POST /v0/quote                      -> 201, quote with depositAddress
  GET  /v0/status?depositAddress=...  -> GetExecutionStatusResponse
                                         404 for an address never quoted
  POST /admin/status  {"status": "SUCCESS"}   set the status returned by /v0/status
  GET  /admin/state                   -> what the mock has seen

Usage: mock_near.py [--port 4101] [--rate 873.31]
  --rate is the fake USDC-per-ZEC price used to compute amountOut.
"""
import argparse
import json
import random
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

# The seven values in the 1Click GetExecutionStatusResponse status enum.
# There is no EXPIRED: the only EXPIRED in the OpenAPI document belongs to an
# unrelated order-status enum.
STATUSES = (
    "KNOWN_DEPOSIT_TX",
    "PENDING_DEPOSIT",
    "INCOMPLETE_DEPOSIT",
    "PROCESSING",
    "SUCCESS",
    "REFUNDED",
    "FAILED",
)

# Smallest deposit 1Click will quote. Below this the live API answers 400
# "Amount is too low for bridge, try at least 52000".
MIN_ZEC_ZATOSHI = 52000

# Fixed Base-side delivery fee the live API reports, in USDC base units.
WITHDRAW_FEE = 2400

def _now():
    return _iso()


def _iso(**delta):
    return (datetime.now(timezone.utc) + timedelta(**delta)).isoformat().replace("+00:00", "Z")


STATE = {
    "status": "PENDING_DEPOSIT",
    "quotes": [],
    "status_polls": 0,
}
LOCK = threading.Lock()
# Measured 2026-08-30 from the API's own token registry. The old default of 30
# was off by a factor of 29, so dry runs reasoned about USDC amounts and rate
# thresholds from a badly wrong number.
RATE = 873.31


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # quieter than the default
        print("[mock-near] " + fmt % args)

    def _json(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/v0/quote":
            req = self._body()
            zatoshi = int(req.get("amount", "0") or 0)

            if zatoshi < MIN_ZEC_ZATOSHI:
                return self._json(400, {
                    "message": "Amount is too low for bridge, try at least %d" % MIN_ZEC_ZATOSHI,
                    "correlationId": "mock-%08x" % random.getrandbits(32),
                    "timestamp": _now(),
                    "path": "/v0/quote",
                })

            gross = int(zatoshi / 1e8 * RATE * 1e6)
            usdc_out = max(gross - WITHDRAW_FEE, 0)
            slippage = int(req.get("slippageTolerance") or 50)
            deposit_address = "t1MockNearDeposit%08x" % random.getrandbits(32)
            # The live service keeps a deposit address open for about three days
            # regardless of the deadline in the request.
            deadline = _iso(days=3)
            with LOCK:
                STATE["quotes"].append({"request": req, "depositAddress": deposit_address, "amountOut": usdc_out})
            # 201, matching the live endpoint.
            return self._json(201, {
                "correlationId": "mock-%08x" % random.getrandbits(32),
                "timestamp": _now(),
                "signature": "ed25519:mock",
                "quoteRequest": req,
                "quote": {
                    "amountIn": str(zatoshi),
                    "amountInFormatted": "%.8f" % (zatoshi / 1e8),
                    "minAmountIn": str(zatoshi),
                    "amountOut": str(usdc_out),
                    "amountOutFormatted": "%.6f" % (usdc_out / 1e6),
                    "minAmountOut": str(usdc_out * (10000 - slippage) // 10000),
                    "timeEstimate": 107,
                    "depositAddress": deposit_address,
                    "deadline": deadline,
                    "timeWhenInactive": deadline,
                    "refundFee": "47000",
                    "withdrawFee": str(WITHDRAW_FEE),
                },
            })
        if path == "/admin/status":
            req = self._body()
            want = req.get("status", "SUCCESS")
            if want not in STATUSES:
                return self._json(400, {
                    "error": "%s is not a 1Click status; expected one of %s"
                             % (want, ", ".join(STATUSES)),
                })
            with LOCK:
                STATE["status"] = want
            return self._json(200, {"ok": True, "status": STATE["status"]})
        return self._json(404, {"error": "not found"})

    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/v0/status":
            qs = parse_qs(url.query)
            addr = qs.get("depositAddress", [""])[0]
            with LOCK:
                STATE["status_polls"] += 1
                status = STATE["status"]
                known = next((q for q in STATE["quotes"] if q["depositAddress"] == addr), None)

            # The live service answers 404 for an address it has not issued.
            if known is None:
                print("[mock-near] status for %s -> 404 (never quoted)" % (addr or "?"))
                return self._json(404, {
                    "message": "Deposit address %s not found" % addr,
                    "error": "Not Found",
                    "statusCode": 404,
                    "timestamp": _now(),
                    "path": self.path,
                })

            # Settled amounts and chain hashes belong inside swapDetails, and the
            # chain hashes are arrays of {hash, explorerUrl} objects.
            details = {"intentHashes": [], "nearTxHashes": [],
                       "originChainTxHashes": [], "destinationChainTxHashes": []}

            if status in ("KNOWN_DEPOSIT_TX", "INCOMPLETE_DEPOSIT", "PROCESSING", "SUCCESS", "REFUNDED"):
                details["originChainTxHashes"] = [{
                    "hash": "mock-zec-txid",
                    "explorerUrl": "https://example.invalid/tx/mock-zec-txid",
                }]

            if status == "SUCCESS":
                out = str(known["amountOut"])
                details.update({
                    "intentHashes": ["mock-intent"],
                    "nearTxHashes": ["mock-near-tx"],
                    "amountIn": known["request"].get("amount"),
                    "amountOut": out,
                    "amountOutFormatted": "%.6f" % (int(out) / 1e6),
                    "slippage": int(known["request"].get("slippageTolerance") or 50),
                    "destinationChainTxHashes": [{
                        "hash": "0x" + "00" * 32,
                        "explorerUrl": "https://basescan.org/tx/0x" + "00" * 32,
                    }],
                })

            if status == "REFUNDED":
                # 1Click charges the refund fee out of the returned principal.
                refunded = max(int(known["request"].get("amount", "0") or 0) - 47000, 0)
                details["refundedAmount"] = str(refunded)
                details["refundedAmountFormatted"] = "%.8f" % (refunded / 1e8)

            body = {
                "correlationId": "mock-%08x" % random.getrandbits(32),
                "status": status,
                "updatedAt": _now(),
                "quoteResponse": {"quote": {"depositAddress": addr}},
                "swapDetails": details,
            }
            print("[mock-near] status for %s -> %s" % (addr, status))
            return self._json(200, body)
        if url.path == "/admin/state":
            with LOCK:
                return self._json(200, STATE)
        return self._json(404, {"error": "not found"})


def main():
    global RATE
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=4101)
    ap.add_argument("--rate", type=float, default=RATE, help="fake USDC per ZEC")
    args = ap.parse_args()
    RATE = args.rate
    server = HTTPServer(("127.0.0.1", args.port), Handler)
    print("[mock-near] listening on http://127.0.0.1:%d (rate %.2f USDC/ZEC)" % (args.port, RATE))
    server.serve_forever()


if __name__ == "__main__":
    main()

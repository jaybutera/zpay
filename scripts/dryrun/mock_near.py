#!/usr/bin/env python3
"""Mock of the NEAR Intents 1Click endpoints the coordinator uses.

Fakes the ZEC -> USDC leg for dry runs. The coordinator asks for a quote,
gets a made-up deposit address, and polls /v0/status until it says SUCCESS.
Nothing moves USDC here: the dry-run script transfers test USDC to the
GlueContract itself, then flips this server's status to SUCCESS so the
keeper picks it up.

Endpoints (shapes match crates/zecp2p-coordinator/src/near.rs):
  POST /v0/quote                      -> quote with depositAddress
  GET  /v0/status?depositAddress=...  -> {"status": ...}
  POST /admin/status  {"status": "SUCCESS"}   set the status returned by /v0/status
  GET  /admin/state                   -> what the mock has seen

Usage: mock_near.py [--port 4101] [--rate 30]
  --rate is the fake USDC-per-ZEC price used to compute amountOut.
"""
import argparse
import json
import random
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

STATE = {
    "status": "PENDING_DEPOSIT",
    "quotes": [],
    "status_polls": 0,
}
LOCK = threading.Lock()
RATE = 30.0


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
            usdc_out = int(zatoshi / 1e8 * RATE * 1e6)
            deposit_address = "t1MockNearDeposit%08x" % random.getrandbits(32)
            deadline = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat().replace("+00:00", "Z")
            with LOCK:
                STATE["quotes"].append({"request": req, "depositAddress": deposit_address, "amountOut": usdc_out})
            return self._json(200, {
                "correlationId": "mock-%08x" % random.getrandbits(32),
                "quote": {
                    "amountOut": str(usdc_out),
                    "minAmountOut": str(usdc_out * 99 // 100),
                    "timeEstimate": 60,
                    "depositAddress": deposit_address,
                    "deadline": deadline,
                },
            })
        if path == "/admin/status":
            req = self._body()
            with LOCK:
                STATE["status"] = req.get("status", "SUCCESS")
            return self._json(200, {"ok": True, "status": STATE["status"]})
        return self._json(404, {"error": "not found"})

    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/v0/status":
            qs = parse_qs(url.query)
            with LOCK:
                STATE["status_polls"] += 1
                status = STATE["status"]
            body = {"status": status}
            if status == "SUCCESS":
                body.update({
                    "sourceTransactionHash": "mock-zec-txid",
                    "destinationTransactionHash": "0x" + "00" * 32,
                    "amountOut": "0",
                })
            if status in ("FAILED", "EXPIRED", "REFUNDED"):
                body["error"] = "mock: " + status.lower()
            print("[mock-near] status for %s -> %s" % (qs.get("depositAddress", ["?"])[0], status))
            return self._json(200, body)
        if url.path == "/admin/state":
            with LOCK:
                return self._json(200, STATE)
        return self._json(404, {"error": "not found"})


def main():
    global RATE
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=4101)
    ap.add_argument("--rate", type=float, default=30.0, help="fake USDC per ZEC")
    args = ap.parse_args()
    RATE = args.rate
    server = HTTPServer(("127.0.0.1", args.port), Handler)
    print("[mock-near] listening on http://127.0.0.1:%d (rate %.2f USDC/ZEC)" % (args.port, RATE))
    server.serve_forever()


if __name__ == "__main__":
    main()

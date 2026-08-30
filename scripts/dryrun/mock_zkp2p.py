#!/usr/bin/env python3
"""Mock of the zk-p2p curator endpoints the coordinator uses.

The real curator (https://api.zkp2p.xyz) checks the Venmo account and issues
an opaque hashedOnchainId. This mock accepts any username without an '@' and
issues a deterministic sha256-based bytes32 so a dry run can proceed without
registering anything with zk-p2p. Deposits created with a mock hash can never
be fulfilled by a real taker; that is fine for a dry run whose last step is
withdrawFromZkp2p.

Endpoints (shapes match crates/zecp2p-coordinator/src/zkp2p.rs):
  POST /v2/makers/validate {"processorName": "venmo", "offchainId": "..."} -> responseObject: bool
  POST /v2/makers/create   {"processorName": "venmo", "offchainId": "..."} -> responseObject.hashedOnchainId
  GET  /admin/state

Usage: mock_zkp2p.py [--port 4102] [--reject]
"""
import argparse
import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

STATE = {"registered": [], "reject": False}
LOCK = threading.Lock()


def mock_hash(offchain_id: str) -> str:
    return "0x" + hashlib.sha256(("mock-zkp2p-payee:" + offchain_id).encode()).hexdigest()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print("[mock-zkp2p] " + fmt % args)

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
        req = self._body()
        processor = req.get("processorName")
        offchain_id = req.get("offchainId") or ""
        ok = processor == "venmo" and offchain_id != "" and not offchain_id.startswith("@")
        with LOCK:
            ok = ok and not STATE["reject"]
        if path == "/v2/makers/validate":
            return self._json(200, {
                "success": True,
                "message": "Maker data is valid" if ok else "Maker data is invalid",
                "responseObject": ok,
                "statusCode": 200,
            })
        if path == "/v2/makers/create":
            if not ok:
                return self._json(400, {
                    "success": False,
                    "message": "Invalid maker data",
                    "responseObject": None,
                    "statusCode": 400,
                    "errorCode": "invalid_maker_data",
                })
            with LOCK:
                STATE["registered"].append(offchain_id)
            hashed = mock_hash(offchain_id)
            print("[mock-zkp2p] registered %s -> %s" % (offchain_id, hashed))
            return self._json(200, {
                "success": True,
                "message": "Maker created",
                "responseObject": {
                    "id": len(STATE["registered"]),
                    "processorName": "venmo",
                    "offchainId": offchain_id,
                    "hashedOnchainId": hashed,
                    "createdAt": "2026-01-01T00:00:00.000Z",
                },
                "statusCode": 200,
            })
        return self._json(404, {"error": "not found"})

    def do_GET(self):
        if urlparse(self.path).path == "/admin/state":
            with LOCK:
                return self._json(200, STATE)
        return self._json(404, {"error": "not found"})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=4102)
    ap.add_argument("--reject", action="store_true", help="answer every username as invalid")
    args = ap.parse_args()
    STATE["reject"] = args.reject
    server = HTTPServer(("127.0.0.1", args.port), Handler)
    print("[mock-zkp2p] listening on http://127.0.0.1:%d" % args.port)
    server.serve_forever()


if __name__ == "__main__":
    main()

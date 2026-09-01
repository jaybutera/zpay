#!/usr/bin/env python3
"""Measure how zk-p2p intents on Base mainnet actually clear, by size.

Read-only. Sends no transaction, needs no key, and never touches a deposit.
Everything here comes from eth_getLogs against OrchestratorV3 and EscrowV2.

Invoked by scripts/analysis/market_fill_rates.sh, which supplies the RPC and
the addresses from the same environment the deploy steps use.

WHAT IS MEASURED

An intent is a taker claiming part of a deposit. Its life shows up as:

    IntentSignaled(intentHash, escrow, depositId, ...)   OrchestratorV3
        the claim opens; data carries amount and the signal timestamp
    IntentFulfilled(intentHash, fundsTransferredTo, ...) OrchestratorV3
        the payment proved out and the USDC moved: this is a fill
    IntentPruned(intentHash)                             OrchestratorV3
        the intent slot was released

IntentPruned is NOT a failure marker. It fires on fulfilled intents too, in the
same transaction as the fulfilment, so counting prunes as misses would report a
near-total failure rate on a market that is working. Fill rate here is
fulfilled / signaled, and an intent that was signaled but never fulfilled is
the miss. That reading is cross-checked against EscrowV2, which splits the two
outcomes into separate events:

    FundsLocked(depositId, intentHash, ...)                 == signaled
    FundsUnlockedAndTransferred(depositId, intentHash, ...)  == fulfilled
    FundsUnlocked(depositId, intentHash, ...)                == released unfilled

Over a sample window the transferred set matched the fulfilled set exactly and
the unlocked set was disjoint from it, which is what makes the fills/misses
split above trustworthy rather than assumed.

CENSORING

An intent signaled near the end of the window may still be in flight. Counting
it as a miss understates the fill rate. Intents whose signal falls within
--settle-secs of the window's end are excluded from the rate and reported
separately as still-open.
"""

import argparse
import json
import os
import statistics
import sys
import time
import urllib.error
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone

# Topic hashes. Every one of these is keccak of the signature in the comment;
# scripts/analysis/market_fill_rates.sh re-derives them with `cast keccak` and
# refuses to run if any disagrees, so a wrong constant here cannot go unnoticed.
T_SIGNALED = "0xf8c114f83581b2cf0b9f130782a93024aa8933e7d188901156bd68bdd558a20a"
# IntentSignaled(bytes32,address,uint256,bytes32,address,address,uint256,bytes32,uint256,uint256)
T_FULFILLED = "0xd50b3b21bc45b85ddfaec58dbf56fe9b88754d08f47dcf5143b63258a57ad944"
# IntentFulfilled(bytes32,address,uint256,bool)
T_PRUNED = "0x95eadd9e42ccacb548c6389441b53e6eebec39e11adaea9029a25fe1222483e0"
# IntentPruned(bytes32)
T_LOCKED = "0xb40d75557428cec6806c7ebb58634796f8a5870a0874bcd0d299328b5518665b"
# FundsLocked(uint256,bytes32,uint256,uint256)
T_TRANSFERRED = "0x45625e0810f65b3c601b5c91bdacdf9e8f9ec7098fce927c57a8a65a823fd617"
# FundsUnlockedAndTransferred(uint256,bytes32,uint256,uint256,address)
T_UNLOCKED = "0x683f6606eec92f04a68f1797d32d15f840b9b3d410a8ec9b4fdab4c30813796d"
# FundsUnlocked(uint256,bytes32,uint256)
T_DEPOSIT = "0x1236dbdc184b6c8721974cce53dabb6018679bca9a43784ab2ad71bcdb1d7dd1"
# DepositReceived(uint256,address,address,uint256,(uint256,uint256),address,address)

# The public Base RPC rejects any eth_getLogs spanning more than 10,000 blocks
# with error -32614, so every scan is paged at or below this.
MAX_RANGE = 10_000

# Buckets in whole USDC. The small end is split finely because that is the
# question: a ~$5 sell is the first bucket, not lost inside "under $100".
BUCKETS = [
    ("$0-2",     0.0,      2.0),
    ("$2-5",     2.0,      5.0),
    ("$5-10",    5.0,     10.0),
    ("$10-25",  10.0,     25.0),
    ("$25-100", 25.0,    100.0),
    ("$100-500", 100.0,  500.0),
    ("$500+",   500.0, float("inf")),
]


class Rpc:
    """JSON-RPC client that survives the public endpoint's rate limiting.

    Mirrors the retry stance of call_retry() in scripts/deploy/00_preflight.sh:
    a 429 or an empty answer is rate limiting, not a real result, so back off
    and ask again rather than believing it.
    """

    # The public Base RPC answers Python's default urllib User-Agent with a
    # flat HTTP 403, before any rate limiting is involved. Presenting a plain
    # client string is what makes the endpoint answer at all.
    HEADERS = {"Content-Type": "application/json", "User-Agent": "curl/8.5.0"}

    def __init__(self, url, tries=6, pace=0.12):
        self.url = url
        self.tries = tries
        self.pace = pace
        self.calls = 0
        self.retries = 0

    def call(self, method, params):
        payload = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        ).encode()
        delay = 1.0
        last = None
        for attempt in range(self.tries):
            if self.pace:
                time.sleep(self.pace)
            try:
                req = urllib.request.Request(self.url, data=payload, headers=self.HEADERS)
                with urllib.request.urlopen(req, timeout=90) as resp:
                    body = json.load(resp)
                self.calls += 1
                if "error" in body:
                    code = body["error"].get("code")
                    msg = body["error"].get("message", "")
                    # -32614 is the range cap and is our bug, not congestion:
                    # fail loudly instead of retrying a request that cannot work.
                    if code == -32614 or "limited to a" in msg:
                        raise SystemExit(f"RPC range error: {msg}")
                    last = msg
                else:
                    return body["result"]
            except urllib.error.HTTPError as exc:
                if exc.code == 403:
                    raise SystemExit(
                        "RPC refused with HTTP 403. The public Base endpoint "
                        "rejects some clients outright; this is not rate "
                        "limiting and retrying will not clear it."
                    )
                if exc.code not in (429, 500, 502, 503, 504):
                    raise
                last = f"HTTP {exc.code}"
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
                last = str(exc)
            self.retries += 1
            time.sleep(delay)
            delay = min(delay * 2, 16.0)
        raise SystemExit(f"RPC gave up after {self.tries} tries: {last}")

    def block_number(self):
        return int(self.call("eth_blockNumber", []), 16)

    def block_time(self, number):
        blk = self.call("eth_getBlockByNumber", [hex(number), False])
        return int(blk["timestamp"], 16)

    def logs(self, address, topic, start, end, progress=None):
        """Every log of one topic over [start, end], paged under the cap."""
        out = []
        lo = start
        while lo <= end:
            hi = min(lo + MAX_RANGE - 1, end)
            out.extend(
                self.call(
                    "eth_getLogs",
                    [{
                        "address": address,
                        "topics": [topic],
                        "fromBlock": hex(lo),
                        "toBlock": hex(hi),
                    }],
                )
            )
            if progress:
                progress(hi - start + 1, end - start + 1, len(out))
            lo = hi + 1
        return out


def word(data, index):
    """Word `index` of an ABI-encoded log data blob, as an int."""
    raw = data[2:] if data.startswith("0x") else data
    chunk = raw[index * 64:(index + 1) * 64]
    return int(chunk, 16) if chunk else 0


def pct(part, whole):
    return 100.0 * part / whole if whole else 0.0


def quantile(values, q):
    """Nearest-rank quantile. Small buckets make interpolation dishonest."""
    if not values:
        return None
    ordered = sorted(values)
    idx = min(int(q * len(ordered)), len(ordered) - 1)
    return ordered[idx]


def human_secs(secs):
    if secs is None:
        return "     -"
    if secs < 90:
        return "%4.0fs" % secs
    if secs < 5400:
        return "%4.1fm" % (secs / 60)
    return "%4.1fh" % (secs / 3600)


def main():
    ap = argparse.ArgumentParser(
        description="Measure zk-p2p intent fill rate and time-to-fill by size."
    )
    ap.add_argument("--rpc", default=os.environ.get("BASE_RPC_URL", "https://mainnet.base.org"))
    ap.add_argument("--orchestrator", default=os.environ.get("ZKP2P_ORCHESTRATOR_ADDRESS"))
    ap.add_argument("--escrow", default=os.environ.get("ZKP2P_ESCROW_ADDRESS"))
    ap.add_argument("--blocks", type=int, default=250_000,
                    help="how many blocks back from head to scan (Base: 2s/block)")
    ap.add_argument("--from-block", type=int, default=None)
    ap.add_argument("--to-block", type=int, default=None)
    ap.add_argument("--settle-secs", type=int, default=3 * 3600,
                    help="intents signaled this close to the window end are "
                         "counted as still-open, not as misses")
    ap.add_argument("--json", metavar="PATH", help="also write the raw measurements here")
    args = ap.parse_args()

    if not args.orchestrator or not args.escrow:
        raise SystemExit("set ZKP2P_ORCHESTRATOR_ADDRESS and ZKP2P_ESCROW_ADDRESS")

    rpc = Rpc(args.rpc)
    head = rpc.block_number()
    to_block = args.to_block if args.to_block is not None else head
    from_block = args.from_block if args.from_block is not None else max(0, to_block - args.blocks)
    span = to_block - from_block + 1
    pages = -(-span // MAX_RANGE)

    t_start = rpc.block_time(from_block)
    t_end = rpc.block_time(to_block)

    print("zk-p2p Base mainnet fill-rate scan")
    print("  rpc          %s" % args.rpc)
    print("  orchestrator %s" % args.orchestrator)
    print("  escrow       %s" % args.escrow)
    print("  blocks       %d..%d  (%d blocks, %d pages of <=%d)"
          % (from_block, to_block, span, pages, MAX_RANGE))
    print("  window       %s .. %s UTC  (%.1f days)"
          % (datetime.fromtimestamp(t_start, timezone.utc).strftime("%Y-%m-%d %H:%M"),
             datetime.fromtimestamp(t_end, timezone.utc).strftime("%Y-%m-%d %H:%M"),
             (t_end - t_start) / 86400.0))
    print()

    def scan(label, address, topic):
        state = {"n": 0}

        def progress(done, total, found):
            state["n"] += 1
            sys.stderr.write("\r  scanning %-28s %3.0f%%  %d logs"
                             % (label, pct(done, total), found))
            sys.stderr.flush()

        logs = rpc.logs(address, topic, from_block, to_block, progress)
        sys.stderr.write("\r  scanned  %-28s 100%%  %d logs\n" % (label, len(logs)))
        return logs

    signaled_logs = scan("IntentSignaled", args.orchestrator, T_SIGNALED)
    fulfilled_logs = scan("IntentFulfilled", args.orchestrator, T_FULFILLED)
    pruned_logs = scan("IntentPruned", args.orchestrator, T_PRUNED)
    locked_logs = scan("FundsLocked", args.escrow, T_LOCKED)
    transferred_logs = scan("FundsUnlockedAndTransferred", args.escrow, T_TRANSFERRED)
    unlocked_logs = scan("FundsUnlocked", args.escrow, T_UNLOCKED)
    deposit_logs = scan("DepositReceived", args.escrow, T_DEPOSIT)
    print()

    # Block timestamps come back on the logs themselves on Base, which saves a
    # per-block round trip. Fall back to fetching if the endpoint omits them.
    block_ts = {}

    def log_time(log):
        if log.get("blockTimestamp"):
            return int(log["blockTimestamp"], 16)
        num = int(log["blockNumber"], 16)
        if num not in block_ts:
            block_ts[num] = rpc.block_time(num)
        return block_ts[num]

    intents = {}
    for log in signaled_logs:
        h = log["topics"][1]
        intents[h] = {
            "hash": h,
            "deposit": int(log["topics"][3], 16),
            "owner": "0x%040x" % word(log["data"], 1),  # who signaled it
            "amount": word(log["data"], 3) / 1e6,      # USDC, 6 decimals
            "rate": word(log["data"], 5) / 1e18,
            "signaled_at": word(log["data"], 6),        # the contract's own stamp
            "block": int(log["blockNumber"], 16),
        }

    filled_at = {}
    for log in fulfilled_logs:
        h = log["topics"][1]
        ts = log_time(log)
        if h not in filled_at or ts < filled_at[h]:
            filled_at[h] = ts

    pruned = {log["topics"][1] for log in pruned_logs}
    unlocked = {log["topics"][2] for log in unlocked_logs}
    transferred = {log["topics"][2] for log in transferred_logs}

    # Cross-check the reading of the events before trusting any rate built on
    # it. If these disagree, the fills/misses split below is not what it claims.
    fulfilled_set = set(filled_at)
    both = fulfilled_set & pruned
    print("event cross-checks")
    print("  fulfilled intents also pruned            %d/%d  %s"
          % (len(both), len(fulfilled_set),
             "(prune is slot-release, not failure)" if len(both) == len(fulfilled_set)
             else "(MIXED: prune does not track fulfilment)"))
    # Transferred can legitimately exceed fulfilled: an intent signaled before
    # the window opened still settles inside it. What would be wrong is a
    # fulfilled intent with no matching transfer.
    missing = fulfilled_set - transferred
    spill = transferred - fulfilled_set
    if not missing:
        print("  every fulfilled intent has an escrow transfer   yes"
              + ("  (+%d settled from before the window)" % len(spill) if spill else ""))
    else:
        print("  every fulfilled intent has an escrow transfer   NO (%d without)"
              % len(missing))
    print("  escrow FundsUnlocked disjoint from fills  %s"
          % ("yes" if not (unlocked & fulfilled_set) else
             "NO (%d overlap)" % len(unlocked & fulfilled_set)))
    print("  FundsLocked count vs IntentSignaled       %d vs %d"
          % (len(locked_logs), len(signaled_logs)))
    print()

    cutoff = t_end - args.settle_secs
    rows = []
    for h, it in intents.items():
        ts = it["signaled_at"] or None
        filled = h in filled_at
        rec = dict(it)
        rec["filled"] = filled
        rec["ttf"] = (filled_at[h] - ts) if (filled and ts) else None
        # An unfilled intent whose slot is already released is a settled miss.
        # One still holding its slot near the window edge may yet fill.
        rec["settled"] = filled or (h in pruned) or (h in unlocked)
        rec["open"] = (not filled) and (not rec["settled"]) and ts is not None and ts > cutoff
        rows.append(rec)

    scored = [r for r in rows if not r["open"]]
    still_open = [r for r in rows if r["open"]]

    def bucket_of(amount):
        for name, lo, hi in BUCKETS:
            if lo <= amount < hi:
                return name
        return BUCKETS[-1][0]

    by_bucket = defaultdict(list)
    for r in scored:
        r["bucket"] = bucket_of(r["amount"])
        by_bucket[r["bucket"]].append(r)

    total_n = len(scored)
    total_f = sum(1 for r in scored if r["filled"])

    print("intent outcomes by size            (%d intents scored, %d still open at window end)"
          % (total_n, len(still_open)))
    print()
    print("  bucket      n   filled   fill%   median    p90     slowest   median $")
    print("  " + "-" * 68)
    for name, _lo, _hi in BUCKETS:
        rs = by_bucket.get(name, [])
        if not rs:
            continue
        f = [r for r in rs if r["filled"]]
        ttfs = [r["ttf"] for r in f if r["ttf"] is not None and r["ttf"] >= 0]
        med_amt = statistics.median([r["amount"] for r in rs])
        print("  %-9s %4d   %4d   %5.1f%%  %6s  %6s   %6s   %8.2f"
              % (name, len(rs), len(f), pct(len(f), len(rs)),
                 human_secs(quantile(ttfs, 0.5)),
                 human_secs(quantile(ttfs, 0.9)),
                 human_secs(max(ttfs) if ttfs else None),
                 med_amt))
    print("  " + "-" * 68)
    all_ttf = [r["ttf"] for r in scored if r["filled"] and r["ttf"] is not None and r["ttf"] >= 0]
    print("  %-9s %4d   %4d   %5.1f%%  %6s  %6s   %6s"
          % ("all", total_n, total_f, pct(total_f, total_n),
             human_secs(quantile(all_ttf, 0.5)),
             human_secs(quantile(all_ttf, 0.9)),
             human_secs(max(all_ttf) if all_ttf else None)))
    print()

    # The question is a ~$5 sell, so report that end on its own terms rather
    # than leaving the reader to combine buckets.
    small = [r for r in scored if r["amount"] <= 10.0]
    tiny = [r for r in scored if r["amount"] <= 6.0]
    print("the small end")
    for label, rs in (("<= $10", small), ("<= $6", tiny)):
        if not rs:
            print("  %-7s no intents this size in the window" % label)
            continue
        f = [r for r in rs if r["filled"]]
        ttfs = [r["ttf"] for r in f if r["ttf"] is not None and r["ttf"] >= 0]
        print("  %-7s %d signaled, %d filled (%.0f%%), median %s, p90 %s"
              % (label, len(rs), len(f), pct(len(f), len(rs)),
                 human_secs(quantile(ttfs, 0.5)), human_secs(quantile(ttfs, 0.9))))
        amounts = sorted(r["amount"] for r in rs)
        print("          sizes seen: %s"
              % ", ".join("$%.2f" % a for a in amounts[:10])
              + (" ..." if len(amounts) > 10 else ""))
    print()

    # A rate built on one counterparty is not a market rate. If a single
    # address signals a large share of intents, its own behaviour sets the
    # headline number, so report the market with and without it. This is not
    # hypothetical: on the sampled windows one address signals about half of
    # all intents and almost never fills its own $2 ones, which on its own
    # drags the small-bucket fill rate down by tens of points.
    owners = defaultdict(list)
    for r in scored:
        owners[r["owner"]].append(r)
    ranked = sorted(owners.items(), key=lambda kv: len(kv[1]), reverse=True)

    print("who is signaling")
    print("  %d distinct signalers over %d intents" % (len(owners), total_n))
    for addr, rs in ranked[:3]:
        f = sum(1 for r in rs if r["filled"])
        sm = [r for r in rs if r["amount"] <= 10.0]
        smf = sum(1 for r in sm if r["filled"])
        print("  %s  %4d intents (%4.1f%% of all)  fills %5.1f%%  <=$10: %d/%d"
              % (addr, len(rs), pct(len(rs), total_n), pct(f, len(rs)), smf, len(sm)))
    print()

    dominant, dom_rows = (ranked[0] if ranked else (None, []))
    concentrated = bool(ranked) and pct(len(dom_rows), total_n) >= 20.0
    if concentrated:
        rest = [r for r in scored if r["owner"] != dominant]
        print("  %s alone is %.0f%% of this market." % (dominant, pct(len(dom_rows), total_n)))
        print("  Excluding it, so the numbers describe everyone else:")
        print()
        print("  bucket      n   filled   fill%   median    p90")
        print("  " + "-" * 48)
        for name, lo, hi in BUCKETS:
            rs = [r for r in rest if lo <= r["amount"] < hi]
            if not rs:
                continue
            f = [r for r in rs if r["filled"]]
            ttfs = [r["ttf"] for r in f if r["ttf"] is not None and r["ttf"] >= 0]
            print("  %-9s %4d   %4d   %5.1f%%  %6s  %6s"
                  % (name, len(rs), len(f), pct(len(f), len(rs)),
                     human_secs(quantile(ttfs, 0.5)), human_secs(quantile(ttfs, 0.9))))
        rsmall = [r for r in rest if r["amount"] <= 10.0]
        rf = [r for r in rsmall if r["filled"]]
        rttf = [r["ttf"] for r in rf if r["ttf"] is not None and r["ttf"] >= 0]
        print("  " + "-" * 48)
        print("  %-9s %4d   %4d   %5.1f%%  %6s  %6s"
              % ("<= $10", len(rsmall), len(rf), pct(len(rf), len(rsmall)),
                 human_secs(quantile(rttf, 0.5)), human_secs(quantile(rttf, 0.9))))
        print()
        print("  The excluding-it row is the better guide to what a fresh $5 sell")
        print("  from a new account should expect, unless we intend to price and")
        print("  behave like the dominant account does.")
        print()

    # Distinct deposits tell us whether the small fills are spread around or
    # concentrated in one place.
    if small:
        print("  small intents span %d distinct deposits" % len({r["deposit"] for r in small}))
        filled_small = [r for r in small if r["filled"]]
        if filled_small:
            print("  small fills span %d distinct deposits, %d distinct signalers"
                  % (len({r["deposit"] for r in filled_small}),
                     len({r["owner"] for r in filled_small})))
        print()

    print("deposit supply in window")
    print("  new deposits created      %d" % len(deposit_logs))
    print("  deposits taken against    %d" % len({r["deposit"] for r in rows}))
    print()

    print("scan cost: %d RPC calls, %d retries after rate limiting"
          % (rpc.calls, rpc.retries))
    print()
    print("window caveat: this is %.1f days ending %s UTC. The public Base RPC"
          % ((t_end - t_start) / 86400.0,
             datetime.fromtimestamp(t_end, timezone.utc).strftime("%Y-%m-%d %H:%M")))
    print("caps eth_getLogs at %s blocks and rate-limits, so a longer window costs"
          % format(MAX_RANGE, ","))
    print("proportionally more calls. An archive RPC (Alchemy, QuickNode, Ankr) lifts")
    print("the cap and would let this scan months in one pass, which matters most for")
    print("the small buckets: they are the thinnest here and the least certain.")

    if args.json:
        with open(args.json, "w") as fh:
            json.dump({
                "from_block": from_block, "to_block": to_block,
                "window_start": t_start, "window_end": t_end,
                "intents": rows,
            }, fh, indent=1, default=str)
        print("\nraw measurements written to %s" % args.json)


if __name__ == "__main__":
    main()

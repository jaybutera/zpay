"""One untouched end-to-end pass of zpay.cash, driven as a real user would.

Opens the live site in a browser, asks for a Venmo payout, reads the escrow
address the page shows, sends the ZEC to it from a wallet key this machine
holds, then leaves the page open until the page itself says the money landed.
The page's key never leaves it, so the tab has to stay open: the pre-signature
is made in the page when the escrow confirms, and a reload loses it.

Everything comes from the environment, so a run is one command and its
arguments are on the record:

    ZPAY_OUT=/tmp/run1 ZPAY_USD=1.50 ZPAY_HANDLE=jay-butera \
    ZPAY_FUND_LABEL=v2coord-lp-payout ZPAY_FUND_TXID=<txid> \
    ZPAY_FUND_VOUT=0 ZPAY_FUND_VALUE=<zat> \
    ZECP2P_KEYSTORE=$HOME/.zecp2p/mainnet-v2coord \
    ZECP2P_RPC_URL=https://zec.nownodes.io ZECP2P_RPC_NETWORK=main \
    ZECP2P_RPC_API_KEY_HEADER=api-key ZECP2P_RPC_API_KEY=... \
      python3 scripts/e2e/run_e2e.py

`ZPAY_FUND_TXID`, `ZPAY_FUND_VOUT` and `ZPAY_FUND_VALUE` each take a
comma-separated list of the same length when the funding has to spend more than
one output, which is what a key holding its balance as change from past releases
needs.

Exits 0 only when the page reached `done`. Every other ending, including a
refusal the page states in its own words, exits non-zero and says which.

One order per amount per handle: the coordinator refuses a second open order
to the same handle for the same dollars, because two identical payments cannot
be told apart in the Venmo feed. An abandoned order therefore blocks the next
run at that amount until its refund height, so do not open orders to rehearse.
"""
import json, os, subprocess, sys, time

from playwright.sync_api import sync_playwright

OUT = os.environ["ZPAY_OUT"]
USD = os.environ.get("ZPAY_USD", "1.50")
HANDLE = os.environ.get("ZPAY_HANDLE", "jay-butera")
REPO = os.environ.get("ZPAY_REPO", os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# The outpoint the funding spends, and the key that can spend it.
FUND_LABEL = os.environ["ZPAY_FUND_LABEL"]
FUND_TXID = os.environ["ZPAY_FUND_TXID"]
FUND_VOUT = os.environ["ZPAY_FUND_VOUT"]
FUND_VALUE = os.environ["ZPAY_FUND_VALUE"]

os.makedirs(OUT, exist_ok=True)
TRANSCRIPT = open(f"{OUT}/transcript.log", "a")


def log(*a):
    line = f"[{time.strftime('%H:%M:%SZ', time.gmtime())}] " + " ".join(str(x) for x in a)
    print(line, flush=True)
    TRANSCRIPT.write(line + "\n")
    TRANSCRIPT.flush()


def fund(escrow_address, amount_zat, u_pub, l_pub, refund_height):
    """Broadcast the funding transaction and return its txid.

    The escrow parameters ride along so the funder rebuilds the address from
    them and refuses to sign if what it derives is not what it was told to pay.
    """
    env = dict(os.environ)
    cmd = [
        "cargo", "run", "-q", "-p", "zecp2p-escrow",
        "--example", "fund_from_keystore", "--",
        FUND_LABEL, FUND_TXID, FUND_VOUT, FUND_VALUE, escrow_address, str(amount_zat),
        u_pub, l_pub, str(refund_height),
    ]
    log("funding:", " ".join(cmd[6:]))
    r = subprocess.run(cmd, cwd=REPO, env=env, capture_output=True, text=True, timeout=300)
    for line in (r.stdout + r.stderr).splitlines():
        if line.strip():
            log("  fund|", line[:160])
    if r.returncode != 0:
        raise RuntimeError(f"funding failed with {r.returncode}")
    for line in r.stdout.splitlines():
        if line.startswith("FUNDING TXID:"):
            return line.split(":", 1)[1].strip()
    raise RuntimeError("no FUNDING TXID in the tool's output")


with sync_playwright() as p:
    b = p.chromium.launch(headless=True)
    ctx = b.new_context(viewport={"width": 1280, "height": 1000})
    pg = ctx.new_page()
    pg.on("pageerror", lambda e: log("PAGEERROR:", str(e)[:300]))

    log("opening https://zpay.cash/app/")
    pg.goto("https://zpay.cash/app/", wait_until="networkidle", timeout=60000)
    pg.wait_for_timeout(1500)
    log("connection banner:", pg.inner_text("#conn-text").strip())

    # Read from a path that opens nothing, so the payer key the order will name
    # is known before any order exists to name it.
    caps = json.loads(pg.evaluate(
        "async () => { const r = await fetch('/escrow/capabilities'); return await r.text(); }"))
    caps_l_pub = caps["l_pub"]
    log("capabilities  :", caps["network"], "l_pub", caps_l_pub, "fee", caps["fee"]["bps"], "bps")

    pg.click("#unit-usd")
    pg.fill("#amount", USD)
    pg.fill("#handle", HANDLE)
    pg.wait_for_timeout(2500)
    pg.screenshot(path=f"{OUT}/01-quote.png", full_page=True)
    log("quote:", " | ".join(pg.inner_text("#q-out").split("\n"))[:220])
    log("lands in their Venmo:", pg.inner_text("#q-net").strip())

    # The page refuses some orders in its own words rather than by failing:
    # a duplicate open order to the same handle for the same amount is one.
    # Waiting only on #pay-addr turns that refusal into an opaque timeout, so
    # whichever lands first is read and reported.
    pg.click("#btn-pay")
    for _ in range(120):
        if pg.is_visible("#pay-addr") and pg.inner_text("#pay-addr").strip():
            break
        for sel in ("#q-note", "#order-msg"):
            try:
                said = pg.inner_text(sel).strip()
            except Exception:
                continue
            if said:
                pg.screenshot(path=f"{OUT}/02-refused.png", full_page=True)
                raise RuntimeError(f"the page refused the order ({sel}): {said}")
        pg.wait_for_timeout(500)
    else:
        pg.screenshot(path=f"{OUT}/02-timeout.png", full_page=True)
        raise RuntimeError("the page never showed an escrow address and never said why")
    pg.wait_for_timeout(2000)
    pg.screenshot(path=f"{OUT}/02-address.png", full_page=True)

    addr = pg.inner_text("#pay-addr").strip()
    asked = pg.inner_text("#pay-amount").strip()
    order_url = pg.url
    order_id = order_url.split("#order=")[1].split("&")[0]
    log("ESCROW ADDRESS:", addr)
    log("ASKED AMOUNT  :", asked)
    log("ORDER         :", order_id)
    log("ORDER URL     :", order_url)

    # The scriptPubKey and the exact zatoshi count come from the coordinator's
    # own view of the order, so the funding pays what the page asked for rather
    # than what this script rounded.
    view = json.loads(pg.evaluate(
        "async (id) => { const r = await fetch('/escrow/orders/' + id); return await r.text(); }",
        order_id))
    esc = view["escrow"]
    amount_zat = esc["amount_zat"]
    log("amount_zat    :", amount_zat)
    log("refund_height :", esc["refund_height"])
    if esc["address"] != addr:
        raise RuntimeError("the address on the page is not the address in the order")
    if esc["l_pub"] != caps_l_pub:
        raise RuntimeError("the order's payer key is not the one /escrow/capabilities published")
    json.dump({"order_id": order_id, "order_url": order_url, "address": addr,
               "asked": asked, "amount_zat": amount_zat, "usd": USD, "handle": HANDLE,
               "u_pub": esc["u_pub"], "l_pub": esc["l_pub"],
               "refund_height": esc["refund_height"]},
              open(f"{OUT}/order.json", "w"), indent=1)

    txid = fund(addr, amount_zat, esc["u_pub"], esc["l_pub"], esc["refund_height"])
    log("FUNDING TXID  :", txid)
    json.dump({"funding_txid": txid}, open(f"{OUT}/funding.json", "w"), indent=1)

    # From here the user does nothing but keep the tab open.
    log("tab stays open; waiting for the page to report the outcome")
    deadline = time.time() + float(os.environ.get("ZPAY_HOLD_SECONDS", "5400"))
    last = None
    result = "timeout"
    while time.time() < deadline:
        try:
            live = pg.inner_text("#order-live-text").strip().lower()
            head = pg.inner_text("#stage-headline").strip()
            sub = pg.inner_text("#stage-sub").strip()
            if (live, head, sub) != last:
                log(f"STAGE live={live!r} headline={head!r} sub={sub[:160]!r}")
                pg.screenshot(path=f"{OUT}/stage-{live.replace(' ', '_')}.png", full_page=True)
                last = (live, head, sub)
            if live == "done":
                log("RELEASED")
                pg.screenshot(path=f"{OUT}/99-released.png", full_page=True)
                try:
                    log("details:", " | ".join(pg.inner_text("#detail-kv").split("\n")))
                except Exception:
                    pass
                result = "released"
                break
            if live in ("nobody paid", "refundable", "stopped"):
                log("TERMINAL FAILURE:", live, "|", sub[:200])
                pg.screenshot(path=f"{OUT}/99-failed.png", full_page=True)
                result = live
                break
        except Exception as e:
            log("poll error:", str(e)[:200])
        pg.wait_for_timeout(5000)

    log("RESULT:", result)
    json.dump({"result": result}, open(f"{OUT}/result.json", "w"), indent=1)
    b.close()
    sys.exit(0 if result == "released" else 1)

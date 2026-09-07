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

The escrow's spending key lives in two places the browser owns and nowhere
else: the `k=` fragment of the status URL, and this profile's localStorage.
A throwaway profile therefore takes the key with it when the run ends, and an
escrow whose key is gone cannot be refunded by anyone. So the run keeps a
profile across runs under `ZPAY_PROFILE`, and it writes the fragment and the
page's own record to `key.json` and checks that file back off disk before it
funds anything. A run that cannot persist the key stops while the escrow is
still empty.

`ZPAY_DRY_RUN=1` opens the order, persists the key and stops there without
broadcasting a funding transaction. It still books an order at that amount
for its refund window, so use an amount and handle you are willing to lose a
slot on.

Exits 0 only when the page reached `done`. Every other ending, including a
refusal the page states in its own words, exits non-zero and says which.

One order per amount per handle: the coordinator refuses a second open order
to the same handle for the same dollars, because two identical payments cannot
be told apart in the Venmo feed. An abandoned order therefore blocks the next
run at that amount until its refund height, so do not open orders to rehearse.
"""
import json, os, re, subprocess, sys, time

from playwright.sync_api import sync_playwright

OUT = os.environ["ZPAY_OUT"]
USD = os.environ.get("ZPAY_USD", "1.50")
HANDLE = os.environ.get("ZPAY_HANDLE", "jay-butera")
REPO = os.environ.get("ZPAY_REPO", os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
# A profile that outlives the run, so localStorage is not the temp directory
# Playwright deletes on close.
PROFILE = os.environ.get("ZPAY_PROFILE", os.path.expanduser("~/.zecp2p/e2e-profile"))
DRY_RUN = os.environ.get("ZPAY_DRY_RUN", "") not in ("", "0", "no", "false")

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


def persist_key(pg, order_id, order_url):
    """Write the escrow's spending key to disk and prove it is readable there.

    The key exists in the tab and nowhere else: as the `k=` fragment of the
    status URL, and inside the page's own localStorage record. Both die with
    the browser profile. This copies each of them to `key.json`, flushes the
    file to the platter, and reads it back through a second file handle. It
    returns the 64 hex characters of the key, and raises if what came back off
    disk is not the key the page is holding.

    Called before any funding, so a failure here leaves an empty escrow.
    """
    fragment = order_url.split("#", 1)[1] if "#" in order_url else ""
    key_hex = ""
    for part in fragment.split("&"):
        if part.startswith("k="):
            key_hex = part[2:].strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", key_hex):
        raise RuntimeError(
            "the status URL carries no 64-hex k= fragment, so the escrow key was "
            f"never in this run's hands: {order_url!r}")

    # The page's record is the same key plus the terms a refund has to rebuild.
    record = pg.evaluate(
        "(id) => localStorage.getItem('zpay.escrow.' + id)", order_id)
    if not record:
        raise RuntimeError(
            f"the page kept no localStorage record for {order_id}, so a reload "
            "would lose the escrow terms")
    record = json.loads(record)
    if str(record.get("uPriv", "")).lower() != key_hex:
        raise RuntimeError(
            "the key in the status URL is not the key in the page's record; "
            "refusing to fund an escrow whose key is ambiguous")

    path = f"{OUT}/key.json"
    payload = {
        "order_id": order_id,
        "status_url": order_url,
        "u_priv": key_hex,
        "record": record,
        "written_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    with open(path, "w") as fh:
        json.dump(payload, fh, indent=1)
        fh.flush()
        os.fsync(fh.fileno())
    os.chmod(path, 0o600)

    back = json.load(open(path))
    if back.get("u_priv") != key_hex or "#" not in str(back.get("status_url", "")):
        raise RuntimeError(f"{path} did not read back as the key that was written")
    log("KEY PERSISTED :", path, "(u_priv", key_hex[:8] + "…" + key_hex[-8:] + ")")
    return key_hex


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


os.makedirs(PROFILE, exist_ok=True)
os.chmod(PROFILE, 0o700)

with sync_playwright() as p:
    # A persistent profile, so the localStorage record the page writes before it
    # shows the address is still there for the next run to refund from. The
    # default temp profile is deleted on close and takes the key with it.
    ctx = p.chromium.launch_persistent_context(
        PROFILE, headless=True, viewport={"width": 1280, "height": 1000})
    pg = ctx.pages[0] if ctx.pages else ctx.new_page()
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
    # Before a single zatoshi moves: the key that can refund this escrow has to
    # be somewhere that outlives the browser. If it is not, the run stops here
    # and the escrow stays empty.
    persist_key(pg, order_id, order_url)

    json.dump({"order_id": order_id, "order_url": order_url, "address": addr,
               "asked": asked, "amount_zat": amount_zat, "usd": USD, "handle": HANDLE,
               "u_pub": esc["u_pub"], "l_pub": esc["l_pub"],
               "refund_height": esc["refund_height"],
               "key_file": f"{OUT}/key.json", "profile": PROFILE},
              open(f"{OUT}/order.json", "w"), indent=1)

    if DRY_RUN:
        log("DRY RUN: key persisted, nothing funded; the order holds this amount "
            "until its refund height")
        json.dump({"result": "dry-run"}, open(f"{OUT}/result.json", "w"), indent=1)
        ctx.close()
        sys.exit(0)

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
    ctx.close()
    sys.exit(0 if result == "released" else 1)

//! One order, driven end to end, and the deliberate-failure variants of it.
//!
//! Every step goes through the coordinator's own HTTP surface rather than
//! through its internals: `GET /escrow/quote`, `POST /escrow/orders`,
//! `POST /escrow/orders/{id}/presign`, `GET /escrow/orders/{id}` and
//! `POST /escrow/orders/{id}/refund`. That is the seam the page uses, so a run
//! exercises the validation, the limits and the serialisation the page depends
//! on, not a private path that happens to agree with them.
//!
//! The wallet is the one thing simulated in place: instead of broadcasting a
//! funding transaction, the run tells the scanner and the node that an output
//! paying this escrow exists. Which is what a wallet does, minus the money.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use zecp2p_v2coordinator::funding::{FakeScanner, FoundOutput};
use zecp2p_v2coordinator::order::Stage;
use zecp2p_v2coordinator::state::AppState;

use crate::stack::{FakeNode, TestUser};

/// Which path an iteration should take.
///
/// The failure paths are not decoration. A soak run whose every order releases
/// leaves the refund branch, the unpaid branch and the attestation gap
/// unexercised, and those are where the live incidents happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Path {
    /// Fund, confirm, sign, pay, attest, release.
    Release,
    /// Fund and confirm, then let `T` pass without signing, and refund.
    Refund,
    /// Fund and confirm, but never sign. The order should reach the pay
    /// deadline and be marked unpaid rather than settled against.
    NeverSign,
    /// Open an order and never fund it. It must not consume the payment slot
    /// and must not be settled against.
    NeverFund,
}

impl Path {
    /// Whether this path reaches its end by moving the chain tip.
    ///
    /// The two that wait for `T` do. They need the tip past a height every
    /// other open order is still below, so they cannot run beside one.
    pub fn moves_the_tip(self) -> bool {
        matches!(self, Path::Refund | Path::NeverSign)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Path::Release => "release",
            Path::Refund => "refund",
            Path::NeverSign => "never_sign",
            Path::NeverFund => "never_fund",
        }
    }
}

/// Where an iteration got to, and how long each leg took.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub order_id: Option<String>,
    pub path: Path,
    pub address: Option<String>,
    /// The stage the order finished in.
    pub final_stage: Option<String>,
    /// Whether the iteration reached the end its path defines.
    pub ok: bool,
    /// Why not, when it did not.
    pub error: Option<String>,
    pub timings: Timings,
    pub release_txid: Option<String>,
    pub refund_txid: Option<String>,
}

/// Wall-clock for each leg, so a run can say where the time went rather than
/// only how long the whole thing took.
#[derive(Debug, Clone, Default)]
pub struct Timings {
    pub quote: Duration,
    pub open: Duration,
    pub fund_to_depth: Duration,
    pub presign: Duration,
    pub settle: Duration,
    pub total: Duration,
}

/// Everything one iteration needs.
pub struct Env {
    pub state: Arc<AppState>,
    pub app: axum::Router,
    pub scanner: Arc<FakeScanner>,
    pub node: Arc<FakeNode>,
    /// Where a refund is swept to. Testnet, and never a real wallet.
    pub refund_address: String,
    /// Who may move the chain tip.
    ///
    /// There is one chain, and the refund paths reach `T` by moving its tip
    /// past their own refund height. That is a global act: an order still
    /// waiting to be funded, or one mid-settlement, sees the same jump and is
    /// promoted to `refundable` under it. The first mixed run this harness ran
    /// did exactly that, and reported three failures against a coordinator that
    /// was behaving correctly.
    ///
    /// So the tip is leased. An ordinary order holds a read guard for as long
    /// as it needs the present; a time-travelling one takes the write guard,
    /// which cannot be granted until every present-tense order has finished.
    /// Concurrency across the ordinary paths is unaffected, and a mix that
    /// includes refunds serialises exactly where it has to.
    pub clock: Arc<tokio::sync::RwLock<()>>,
}

async fn get(app: &axum::Router, path: &str) -> Result<(StatusCode, serde_json::Value)> {
    let res = app
        .clone()
        .oneshot(Request::builder().uri(path).body(Body::empty())?)
        .await
        .map_err(|e| anyhow::anyhow!("the router failed on GET {path}: {e}"))?;
    let status = res.status();
    let bytes = res.into_body().collect().await?.to_bytes();
    Ok((
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    ))
}

async fn post(
    app: &axum::Router,
    path: &str,
    body: serde_json::Value,
) -> Result<(StatusCode, serde_json::Value)> {
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))?,
        )
        .await
        .map_err(|e| anyhow::anyhow!("the router failed on POST {path}: {e}"))?;
    let status = res.status();
    let bytes = res.into_body().collect().await?.to_bytes();
    Ok((
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    ))
}

/// A funding txid nobody else in the run will use.
///
/// Random rather than derived from the order id: two orders that shared a txid
/// would share an `event_id`, and the attestor draws one nonce per event, so
/// the second order's pre-signature would be made against the first's outcome
/// point and would never decrypt.
fn fresh_txid() -> [u8; 32] {
    let mut txid = [0u8; 32];
    rand::Rng::fill(&mut rand::thread_rng(), &mut txid);
    txid
}

/// A held lease on the chain tip, in either mode.
///
/// One type so the guard can be bound to a single variable and dropped at the
/// end of the iteration whichever kind it is.
enum ClockLease<'a> {
    Shared(tokio::sync::RwLockReadGuard<'a, ()>),
    Exclusive(tokio::sync::RwLockWriteGuard<'a, ()>),
}

/// Runs one order to the end of its path.
///
/// The `amount_zec` and `handle` are the caller's, because two open orders for
/// the same handle at the same cents are refused by design: the feed cannot
/// tell two identical payments apart. The generator varies them; this function
/// just uses what it is given.
pub async fn run_one(
    env: &Env,
    path: Path,
    amount_zec: f64,
    handle: &str,
    sweep_timeout: Duration,
) -> Outcome {
    let started = Instant::now();
    let mut timings = Timings::default();
    let mut outcome = Outcome {
        order_id: None,
        path,
        address: None,
        final_stage: None,
        ok: false,
        error: None,
        timings: timings.clone(),
        release_txid: None,
        refund_txid: None,
    };

    // The chain-tip lease. A path that moves the tip takes it exclusively; one
    // that assumes the present shares it. Held for the whole iteration, because
    // an order is sensitive to the tip from the moment it is opened - its
    // refund height is computed from the tip it saw - right through settlement.
    let _lease: ClockLease<'_> = if path.moves_the_tip() {
        ClockLease::Exclusive(env.clock.write().await)
    } else {
        ClockLease::Shared(env.clock.read().await)
    };

    match run_inner(env, path, amount_zec, handle, sweep_timeout, &mut timings, &mut outcome).await {
        Ok(()) => outcome.ok = true,
        Err(e) => outcome.error = Some(format!("{e:#}")),
    }
    timings.total = started.elapsed();
    outcome.timings = timings;
    outcome
}

async fn run_inner(
    env: &Env,
    path: Path,
    amount_zec: f64,
    handle: &str,
    sweep_timeout: Duration,
    timings: &mut Timings,
    outcome: &mut Outcome,
) -> Result<()> {
    let user = TestUser::new();

    // 1. Quote.
    let t = Instant::now();
    let (status, quote) = get(
        &env.app,
        &format!("/escrow/quote?amount={amount_zec}&unit=zec"),
    )
    .await?;
    timings.quote = t.elapsed();
    if status != StatusCode::OK {
        anyhow::bail!("the quote was refused with {status}: {quote}");
    }
    let quote_id = quote["quote_id"]
        .as_str()
        .context("the quote carried no quote_id")?
        .to_string();

    // 2. Open the order. The escrow address falls out of this: it is derived
    //    from the fresh `u_pub` above, so every order in a run has its own.
    let t = Instant::now();
    let (status, order) = post(
        &env.app,
        "/escrow/orders",
        serde_json::json!({
            "quote_id": quote_id,
            "u_pub": hex::encode(user.u_pub),
            "destination": { "rail": "venmo", "handle": handle },
        }),
    )
    .await?;
    timings.open = t.elapsed();
    if status != StatusCode::OK {
        anyhow::bail!("the order was refused with {status}: {order}");
    }
    let order_id = order["order_id"]
        .as_str()
        .context("the order carried no order_id")?
        .to_string();
    outcome.order_id = Some(order_id.clone());
    let address = order["escrow"]["address"].as_str().map(str::to_string);
    outcome.address = address.clone();
    let amount_zat = order["escrow"]["amount_zat"]
        .as_u64()
        .context("the order carried no amount_zat")?;

    // The unfunded path stops here: the assertion is about what the coordinator
    // does *not* do to an order nobody paid.
    if path == Path::NeverFund {
        zecp2p_v2coordinator::driver::advance(&env.state, &order_id)
            .await
            .context("advancing an unfunded order")?;
        let stored = env
            .state
            .store
            .get(&order_id)
            .context("the order vanished from the store")?;
        outcome.final_stage = Some(stored.stage.as_str().to_string());
        if stored.stage != Stage::AwaitingZec {
            anyhow::bail!(
                "an unfunded order should still be awaiting_zec, and it is {}",
                stored.stage.as_str()
            );
        }
        return Ok(());
    }

    // 3. The wallet pays. The scanner sees the output and the node reports it
    //    at a depth the escrow's size requires.
    let t = Instant::now();
    let funding_txid = fresh_txid();
    let stored = env
        .state
        .store
        .get(&order_id)
        .context("the order vanished from the store")?;
    env.scanner.pay(
        &stored.script_pubkey,
        FoundOutput {
            txid: funding_txid,
            vout: 0,
            amount_zat,
        },
    );
    env.node
        .add_utxo(
            funding_txid,
            0,
            stored.script_pubkey.clone(),
            amount_zat,
            30,
        )
        .await;

    zecp2p_v2coordinator::driver::advance(&env.state, &order_id)
        .await
        .context("advancing a funded order to its announcement")?;
    timings.fund_to_depth = t.elapsed();

    let (_, view) = get(&env.app, &format!("/escrow/orders/{order_id}")).await?;
    let stage = view["stage"].as_str().unwrap_or_default();
    if stage != "needs_presignature" {
        anyhow::bail!("a funded escrow should need a pre-signature, and it is {stage}: {view}");
    }

    // The refund path never signs, and reaches `T` instead.
    if path == Path::Refund || path == Path::NeverSign {
        return finish_without_signing(env, path, &order_id, &user, &funding_txid, outcome).await;
    }

    // 4. The page pre-signs: the digest is rebuilt from the order's own terms
    //    and split, and encrypted under the announced outcome point.
    let t = Instant::now();
    let stored = env
        .state
        .store
        .get(&order_id)
        .context("the order vanished before the pre-signature")?;
    let announced = view["announcement"].clone();
    let pre_sig = user
        .pre_sign(&stored, &announced)
        .context("the page could not pre-sign")?;
    let terms_hash = announced["terms_hash"]
        .as_str()
        .context("the announcement carried no terms_hash")?
        .to_string();

    let (status, body) = post(
        &env.app,
        &format!("/escrow/orders/{order_id}/presign"),
        serde_json::json!({
            "pre_signature": hex::encode(pre_sig.as_ref()),
            "terms_hash": terms_hash,
            "u_pub": hex::encode(user.u_pub),
        }),
    )
    .await?;
    timings.presign = t.elapsed();
    if status != StatusCode::OK {
        anyhow::bail!("the pre-signature was refused with {status}: {body}");
    }

    // 5. The fiat leg and the release.
    //
    // `presign` spawns a settlement task of its own, so this order may already
    // be paying. Sweeping it as well is safe - the slot refuses a second
    // payment - and is what a real deployment does every tick.
    let t = Instant::now();
    let deadline = Instant::now() + sweep_timeout;
    let final_stage = loop {
        let stored = env
            .state
            .store
            .get(&order_id)
            .context("the order vanished during settlement")?;
        if matches!(
            stored.stage,
            Stage::Released | Stage::Failed | Stage::Refunded | Stage::Unpaid
        ) {
            break stored.stage;
        }
        if Instant::now() > deadline {
            break stored.stage;
        }
        // The sweep the daemon runs. Errors here are the driver refusing, which
        // is frequently correct - another order holds the slot - so they are
        // not fatal to the iteration.
        let _ = zecp2p_v2coordinator::driver::advance(&env.state, &order_id).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    timings.settle = t.elapsed();
    outcome.final_stage = Some(final_stage.as_str().to_string());

    let stored = env
        .state
        .store
        .get(&order_id)
        .context("the order vanished after settlement")?;
    outcome.release_txid = stored.release_txid.clone();

    if final_stage != Stage::Released {
        anyhow::bail!(
            "the paid path should end released, and it ended {}{}",
            final_stage.as_str(),
            stored
                .reason
                .as_deref()
                .map(|r| format!(": {r}"))
                .unwrap_or_default()
        );
    }
    Ok(())
}

/// The two paths that never sign: one refunds at `T`, the other just waits for
/// the pay deadline to pass.
///
/// Both matter for the same reason. An escrow the LP cannot settle must still
/// give the user their coin back, and the coordinator must never settle against
/// one it was not authorised to spend.
async fn finish_without_signing(
    env: &Env,
    path: Path,
    order_id: &str,
    user: &TestUser,
    funding_txid: &[u8; 32],
    outcome: &mut Outcome,
) -> Result<()> {
    let stored = env
        .state
        .store
        .get(order_id)
        .context("the order vanished before the deadline")?;

    // Time passes: the tip moves past `T`, which is what makes the timeout
    // branch spendable and the order refundable.
    //
    // The caller holds the tip's exclusive lease, so no other order is watching
    // while this happens. The tip is put back before that lease is released:
    // an order opened against a tip 24 hours ahead would compute its own refund
    // height from it, and each refund path would push the chain further into
    // the future until a `u32` block height stopped being plausible.
    let was = env.node.height().await;
    let past_t = u32::try_from(stored.refund_height)
        .context("the refund height does not fit a block height")?
        + 1;
    env.node.set_height(past_t).await;

    let advanced = zecp2p_v2coordinator::driver::advance(&env.state, order_id).await;
    env.node.set_height(was).await;
    advanced.context("advancing an unsigned order past T")?;

    let stored = env
        .state
        .store
        .get(order_id)
        .context("the order vanished after T")?;
    outcome.final_stage = Some(stored.stage.as_str().to_string());

    if path == Path::NeverSign {
        // An escrow that was never signed for must not have been paid, and must
        // be recoverable by its owner.
        if stored.payment.is_some() {
            anyhow::bail!("an unsigned escrow was paid, which the pre-signature gate must prevent");
        }
        if !matches!(stored.stage, Stage::Refundable | Stage::Unpaid) {
            anyhow::bail!(
                "an unsigned escrow should be refundable or unpaid, and it is {}",
                stored.stage.as_str()
            );
        }
        return Ok(());
    }

    // The refund path goes further: the user signs the timeout branch and the
    // coordinator broadcasts it.
    if stored.stage != Stage::Refundable {
        anyhow::bail!(
            "an escrow past T should be refundable, and it is {}",
            stored.stage.as_str()
        );
    }

    let raw = user
        .sign_refund(&stored, funding_txid, 0, &env.refund_address)
        .context("the user could not sign the refund")?;

    let (status, body) = post(
        &env.app,
        &format!("/escrow/orders/{order_id}/refund"),
        serde_json::json!({ "raw_tx": hex::encode(raw) }),
    )
    .await?;
    if status != StatusCode::OK {
        anyhow::bail!("the refund was refused with {status}: {body}");
    }

    let stored = env
        .state
        .store
        .get(order_id)
        .context("the order vanished after the refund")?;
    outcome.final_stage = Some(stored.stage.as_str().to_string());
    outcome.refund_txid = stored.refund_txid.clone();
    if stored.stage != Stage::Refunded {
        anyhow::bail!(
            "a broadcast refund should end refunded, and it ended {}",
            stored.stage.as_str()
        );
    }
    Ok(())
}

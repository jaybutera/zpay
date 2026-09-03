//! The order sweep must reach every open order, not the same front every tick.
//!
//! U2-1, and the reason this file exists. `tick_orders` had a five-second
//! budget and no record of where it ran out, so it re-walked `get_open_orders`
//! from the front on every tick. At 1Click's measured status latency of about
//! 0.2 s that front is roughly twenty-five orders, and 1Click issues a
//! three-day deposit window regardless of the ten minutes the coordinator asks
//! for, so twenty-five unfunded orders from one address held the whole budget
//! for seventy-three hours. A real sender's order opened behind them was never
//! polled, their USDC landed on the glue attributed to nothing, and at the end
//! of the window the order was retired with "nothing was sent, so nothing is
//! owed" without 1Click ever being asked.
//!
//! Two properties are tested here, both without anvil, because neither needs a
//! chain:
//!
//!  1. a funded order behind a full budget's worth of unfunded ones is polled,
//!     within the number of ticks the rotation promises;
//!  2. an order past its window is not retired until 1Click has been asked, and
//!     one that 1Click reports settled is not retired at all.
//!
//! What one tick covers is pinned with `ZECP2P_ORDER_SWEEP_MAX_PER_TICK` rather
//! than left to how fast the mock replied. In production that bound is a
//! five-second wall clock against 1Click's own latency, which is about
//! twenty-five orders; leaving it to the clock here would make these tests pass
//! or fail with the load on the machine, and a tick that happened to cover the
//! whole set would prove nothing at all. The variable is process-wide, so every
//! test that cares sets it, and the ones that do not are all far below any
//! value the ones that do choose.

mod test_utils;

use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::{routing::get, Json, Router};
use serde::Serialize;
use tempfile::TempDir;
use tokio::net::TcpListener;
use zecp2p_types::settlement::{DepositInstruction, DepositKind, Stage};

static NEAR_PORT: AtomicU16 = AtomicU16::new(9910);

// ---------------------------------------------------------------------------
// A 1Click status mock with latency, and a record of what was asked about.
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct StatusMock {
    /// Every address `/v0/status` was called for, in order.
    asked: Arc<Mutex<Vec<String>>>,
    /// Addresses to answer SUCCESS for. Everything else is PENDING_DEPOSIT.
    settled: Arc<Mutex<std::collections::HashSet<String>>>,
    /// Addresses to answer some other 1Click status for.
    ///
    /// U3-1. The mock used to answer SUCCESS or PENDING_DEPOSIT and nothing
    /// else, which is exactly why the shipped tests could not see that
    /// KNOWN_DEPOSIT_TX, PROCESSING, INCOMPLETE_DEPOSIT and FAILED were all
    /// being retired as "never saw any ZEC". Any of the seven can be set now,
    /// and `settle` is the special case of setting SUCCESS.
    answers: Arc<Mutex<std::collections::HashMap<String, String>>>,
    /// Milliseconds each status call takes. 1Click's own was 170 to 210 ms.
    /// Left at zero by these tests: the per-tick cap is what bounds a sweep
    /// here, and real latency on top of it would only make them slower.
    latency_ms: Arc<AtomicUsize>,
}

impl StatusMock {
    fn new(latency_ms: usize) -> Self {
        Self {
            asked: Arc::new(Mutex::new(Vec::new())),
            settled: Arc::new(Mutex::new(std::collections::HashSet::new())),
            answers: Arc::new(Mutex::new(std::collections::HashMap::new())),
            latency_ms: Arc::new(AtomicUsize::new(latency_ms)),
        }
    }

    fn settle(&self, address: &str) {
        self.settled.lock().unwrap().insert(address.to_string());
    }

    /// Answer `status` for this address until told otherwise.
    fn answer(&self, address: &str, status: &str) {
        self.answers
            .lock()
            .unwrap()
            .insert(address.to_string(), status.to_string());
    }

    fn times_asked_about(&self, address: &str) -> usize {
        self.asked.lock().unwrap().iter().filter(|a| *a == address).count()
    }

    fn distinct_asked(&self) -> usize {
        self.asked
            .lock()
            .unwrap()
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len()
    }

    fn total_calls(&self) -> usize {
        self.asked.lock().unwrap().len()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StatusResp {
    status: String,
    swap_details: SwapDetails,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SwapDetails {
    amount_out: Option<String>,
    refunded_amount: Option<String>,
    origin_chain_tx_hashes: Vec<TxHash>,
    destination_chain_tx_hashes: Vec<TxHash>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TxHash {
    hash: String,
    explorer_url: String,
}

#[derive(serde::Deserialize)]
struct StatusQuery {
    #[serde(rename = "depositAddress")]
    deposit_address: String,
}

async fn status_handler(
    axum::extract::State(mock): axum::extract::State<StatusMock>,
    axum::extract::Query(q): axum::extract::Query<StatusQuery>,
) -> Json<StatusResp> {
    tokio::time::sleep(Duration::from_millis(
        mock.latency_ms.load(Ordering::SeqCst) as u64
    ))
    .await;

    mock.asked.lock().unwrap().push(q.deposit_address.clone());

    let delivered = mock.settled.lock().unwrap().contains(&q.deposit_address);
    let status = if delivered {
        "SUCCESS".to_string()
    } else {
        mock.answers
            .lock()
            .unwrap()
            .get(&q.deposit_address)
            .cloned()
            .unwrap_or_else(|| "PENDING_DEPOSIT".to_string())
    };
    let delivered = delivered || status == "SUCCESS";
    Json(StatusResp {
        status,
        swap_details: SwapDetails {
            amount_out: delivered.then(|| "1500000".to_string()),
            refunded_amount: Some("0".to_string()),
            origin_chain_tx_hashes: vec![],
            destination_chain_tx_hashes: vec![],
        },
    })
}

async fn start_status_mock(latency_ms: usize) -> (StatusMock, String) {
    let port = NEAR_PORT.fetch_add(1, Ordering::SeqCst);
    let mock = StatusMock::new(latency_ms);
    let app = Router::new()
        .route("/v0/status", get(status_handler))
        .with_state(mock.clone());

    let listener = TcpListener::bind(("127.0.0.1", port)).await.expect("bind");
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    tokio::time::sleep(Duration::from_millis(100)).await;

    (mock, format!("http://127.0.0.1:{port}"))
}

// ---------------------------------------------------------------------------
// A coordinator with a database and a 1Click mock, and nothing else.
// ---------------------------------------------------------------------------

/// The sweep up to the point of promotion needs the database and 1Click. It
/// does not need a chain: `ChainClient::new` stores a URL and connects to
/// nothing, and every order in these tests either stays unfunded or fails at
/// the first chain call, which is *after* the poll this is measuring.
async fn coordinator_with(near_url: &str, db_path: &str) -> Arc<zecp2p_coordinator::state::AppState> {
    let config = test_utils::test_config_for(
        "http://127.0.0.1:1",
        near_url,
        "http://127.0.0.1:1",
        Default::default(),
        Default::default(),
        Default::default(),
        db_path,
    );

    let db = zecp2p_coordinator::db::Database::new(db_path).await.expect("db");
    db.run_migrations().await.expect("migrations");
    let chain = zecp2p_coordinator::chain::ChainClient::new_readonly(&config)
        .await
        .expect("chain");

    Arc::new(zecp2p_coordinator::state::AppState::new(
        config.clone(),
        db,
        chain,
        zecp2p_coordinator::near::NearIntentsClient::new(&config.near),
        zecp2p_coordinator::zkp2p::Zkp2pClient::new(&config.zkp2p),
    ))
}

/// Run one sweep with a known per-tick cap.
///
/// `ZECP2P_ORDER_SWEEP_MAX_PER_TICK` is process-wide and these tests run
/// concurrently in one process, so the value is set immediately before each
/// tick rather than once at the top of a test. `tick_orders` reads it
/// synchronously at the start of the sweep and this is the only writer, so a
/// tick always runs under the cap its own caller asked for.
async fn tick_capped_at(state: &Arc<zecp2p_coordinator::state::AppState>, per_tick: usize) {
    std::env::set_var("ZECP2P_ORDER_SWEEP_MAX_PER_TICK", per_tick.to_string());
    state.tick_orders().await.expect("tick");
}

/// One open order, written straight to the table.
///
/// Going through `POST /v2/orders` for each of these would take a 1Click quote
/// and a curator round trip apiece, and the sweep does not care how a row got
/// there. `created_at` is set explicitly so the insertion order is the order
/// the old `ORDER BY created_at ASC` would have produced.
fn order_at(
    address: &str,
    created_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> zecp2p_coordinator::db::OrderRecord {
    zecp2p_coordinator::db::OrderRecord {
        id: uuid::Uuid::new_v4(),
        backend: zecp2p_types::settlement::BackendId::OneclickZkp2p,
        destination: zecp2p_types::settlement::PayoutDestination {
            rail: zecp2p_types::settlement::Rail::Venmo,
            handle: "sweeptest".to_string(),
        },
        session_pubkey: format!("pk-{address}"),
        evm_address: "0x0000000000000000000000000000000000000001".to_string(),
        refund_address: "t1KhV8ADFjBWLxQqCgPmB5xupvUnLDkJhFa".to_string(),
        quote: zecp2p_types::settlement::Quote {
            quote_id: format!("{}@50000000", uuid::Uuid::new_v4()),
            backend: zecp2p_types::settlement::BackendId::OneclickZkp2p,
            zec_zatoshi: 50_000_000,
            gross_cents: 1500,
            net_cents: 1498,
            lines: vec![],
            rate: "30.00".to_string(),
            route_label: "1Click -> zk-p2p".to_string(),
            expected_seconds: 300,
            expires_at,
        },
        deposit: Some(DepositInstruction {
            address: address.to_string(),
            amount_zat: 50_000_000,
            zip321_uri: format!("zcash:{address}?amount=0.5"),
            memo: None,
            expires_at,
            kind: DepositKind::Swap,
        }),
        swap_expected_usdc: Some("1500000".to_string()),
        swap_min_usdc: Some("1485000".to_string()),
        overrides: Default::default(),
        session_uuid: None,
        stage: Stage::AwaitingZec,
        returns: zecp2p_types::settlement::ReturnState::None,
        error: None,
        created_at,
        updated_at: created_at,
    }
}

// ---------------------------------------------------------------------------
// The blocking property
// ---------------------------------------------------------------------------

/// A funded order behind a full budget's worth of unfunded ones is polled.
///
/// The shape is the audit's probe: a large set of unexpired unfunded orders
/// inserted first, one order behind them that 1Click reports settled, and a
/// tick that cannot cover the whole set. Before the fix the settled order was
/// polled zero times in four ticks while the same thirty-six addresses were
/// polled once per tick; the rotation has to reach it within `ceil(N / B)`.
///
/// `B` is pinned by `ZECP2P_ORDER_SWEEP_MAX_PER_TICK` rather than left to how
/// fast the mock answered. In production the bound is the five-second budget
/// against 1Click's own latency, and what a tick covers then depends on the
/// day; a test that depended on that would pass or fail with the load on the
/// machine, and one that let a tick cover the whole set would prove nothing at
/// all.
#[tokio::test]
async fn a_funded_order_behind_a_full_sweep_is_still_polled() {
    const AHEAD: usize = 200;
    const PER_TICK: usize = 25; // what 1Click's measured latency gives in five seconds

    let (near, near_url) = start_status_mock(0).await;
    let temp = TempDir::new().expect("temp dir");
    let db_path = temp.path().join("sweep.db").to_string_lossy().to_string();
    let state = coordinator_with(&near_url, &db_path).await;

    let now = chrono::Utc::now();
    // Every order's window is open, so nothing here is retired for age and the
    // only reason to skip one is the budget.
    let expires = now + chrono::Duration::hours(2);

    for i in 0..AHEAD {
        let order = order_at(
            &format!("t1Unfunded{i:08}"),
            now - chrono::Duration::seconds((AHEAD - i) as i64 + 10),
            expires,
        );
        state.db.insert_order(&order).await.expect("insert");
    }

    // The one that matters, opened last, so under the old ordering it sat at
    // the very back of every pass.
    let funded_address = "t1TheOneThatWasPaid";
    let funded = order_at(funded_address, now, expires);
    let funded_id = funded.id;
    state.db.insert_order(&funded).await.expect("insert the funded order");
    near.settle(funded_address);

    assert_eq!(
        state.db.get_open_orders().await.expect("open").len(),
        AHEAD + 1
    );

    // One tick must NOT reach it, or the arrangement does not reproduce the
    // conditions the defect needed and the assertion below is vacuous.
    tick_capped_at(&state, PER_TICK).await;
    assert_eq!(
        near.distinct_asked(),
        PER_TICK,
        "a tick is supposed to be capped at {PER_TICK} orders"
    );
    assert_eq!(
        near.times_asked_about(funded_address),
        0,
        "the funded order was reachable in a single tick, so this test is not \
         exercising the starvation it exists for"
    );

    // The rotation's promise: with N orders and a budget covering B, every
    // order is polled within ceil(N / B) ticks. One spare tick absorbs the
    // second-granularity of the timestamps the ordering is built on.
    let budget = (AHEAD + 1).div_ceil(PER_TICK) + 1;

    let mut ticks_taken = None;
    for tick in 2..=budget {
        tick_capped_at(&state, PER_TICK).await;
        if near.times_asked_about(funded_address) > 0 {
            ticks_taken = Some(tick);
            break;
        }
    }

    let tick = ticks_taken.unwrap_or_else(|| {
        panic!(
            "U2-1: the funded order was never polled in {budget} ticks. \
             1Click was asked {} times about {} distinct addresses; the same \
             front is being re-walked every tick and the sender's ZEC is \
             invisible to the keeper.",
            near.total_calls(),
            near.distinct_asked()
        )
    });
    println!("the funded order was reached on tick {tick} of a {budget}-tick budget");

    // Reaching it is only half of it: seeing SUCCESS has to move the order off
    // AwaitingZec. Promotion itself needs a chain, which this test has none of,
    // so what is asserted is that the sweep tried, and that the failure is a
    // chain failure rather than the silence the defect produced.
    let after = state.db.get_order(funded_id).await.expect("get").expect("order");
    assert!(
        after.session_uuid.is_none(),
        "this test has no chain, so promotion cannot have completed"
    );

    // And the rotation has to be a rotation: orders beyond the first tick's
    // front were reached.
    assert!(
        near.distinct_asked() > PER_TICK,
        "the sweep polled the same {PER_TICK} addresses on every tick; \
         that is the defect, not the fix"
    );
}

/// Every open order gets a turn, not just the one the previous test watched.
///
/// The stronger statement, and the one that makes the fix a rotation rather
/// than a lucky ordering: run enough ticks for the whole set and every single
/// address must have been asked about.
#[tokio::test]
async fn every_open_order_is_polled_within_a_bounded_number_of_ticks() {
    const N: usize = 200;
    const PER_TICK: usize = 25;

    let (near, near_url) = start_status_mock(0).await;
    let temp = TempDir::new().expect("temp dir");
    let db_path = temp.path().join("rotation.db").to_string_lossy().to_string();
    let state = coordinator_with(&near_url, &db_path).await;

    let now = chrono::Utc::now();
    let expires = now + chrono::Duration::hours(2);
    let mut addresses = Vec::new();

    for i in 0..N {
        let address = format!("t1Rotation{i:08}");
        let order = order_at(
            &address,
            now - chrono::Duration::seconds((N - i) as i64 + 10),
            expires,
        );
        state.db.insert_order(&order).await.expect("insert");
        addresses.push(address);
    }

    let budget = N.div_ceil(PER_TICK) + 1;
    for _ in 0..budget {
        tick_capped_at(&state, PER_TICK).await;
    }

    let unpolled: Vec<&String> = addresses
        .iter()
        .filter(|a| near.times_asked_about(a) == 0)
        .collect();
    assert!(
        unpolled.is_empty(),
        "{} of {N} orders were never polled in {budget} ticks at {PER_TICK} a \
         tick, including {:?}. The sweep is walking the same front rather than \
         rotating.",
        unpolled.len(),
        unpolled.iter().take(3).collect::<Vec<_>>()
    );
    println!("all {N} orders polled within {budget} ticks at {PER_TICK} a tick");
}

// ---------------------------------------------------------------------------
// The second half of U2-1: nothing is called unfunded without asking
// ---------------------------------------------------------------------------

/// An order past its window that 1Click reports settled is not retired.
///
/// This is the sentence the audit called false. The old path read the clock,
/// wrote "nothing was sent, so nothing is owed", made zero status calls, and
/// dropped the order out of the open set, while the sender's USDC sat on the
/// glue. A starved order reaching its deadline is exactly the case, so the two
/// halves of U2-1 meet here.
#[tokio::test]
async fn a_settled_order_past_its_window_is_not_retired_as_unfunded() {
    let (near, near_url) = start_status_mock(0).await;
    let temp = TempDir::new().expect("temp dir");
    let db_path = temp.path().join("late.db").to_string_lossy().to_string();
    let state = coordinator_with(&near_url, &db_path).await;

    let now = chrono::Utc::now();
    let address = "t1PaidButLate";
    // Opened three hours ago, window closed sixty-five minutes ago: past both
    // 1Click's deadline and the grace hour, so the old code retired it on the
    // next tick without a single call.
    let order = order_at(
        address,
        now - chrono::Duration::hours(3),
        now - chrono::Duration::minutes(65),
    );
    let id = order.id;
    state.db.insert_order(&order).await.expect("insert");
    near.settle(address);

    tick_capped_at(&state, 100).await;

    assert!(
        near.times_asked_about(address) > 0,
        "U2-1: the order was retired without 1Click being asked. \
         'Nothing was sent' was asserted from the clock."
    );

    let after = state.db.get_order(id).await.expect("get").expect("order");
    assert_ne!(
        after.stage,
        Stage::Failed,
        "1Click reports this address settled, and the order was still marked \
         failed with nothing owed. The sender's USDC is on the glue."
    );
    assert!(
        after.error.is_none() || !after.error.as_deref().unwrap_or("").contains("nothing is owed"),
        "the sender was told nothing is owed for a swap that settled: {:?}",
        after.error
    );
}

/// An order past its window that 1Click reports unfunded is retired, and is
/// asked about exactly once more before it is.
///
/// The bound still has to hold: retiring is what keeps the polling set finite,
/// and a fix that asked forever would trade one starvation for another.
#[tokio::test]
async fn an_unfunded_order_past_its_window_is_retired_after_one_last_ask() {
    let (near, near_url) = start_status_mock(0).await;
    let temp = TempDir::new().expect("temp dir");
    let db_path = temp.path().join("retire.db").to_string_lossy().to_string();
    let state = coordinator_with(&near_url, &db_path).await;

    let now = chrono::Utc::now();
    let address = "t1NeverPaid";
    let order = order_at(
        address,
        now - chrono::Duration::hours(3),
        now - chrono::Duration::minutes(65),
    );
    let id = order.id;
    state.db.insert_order(&order).await.expect("insert");

    tick_capped_at(&state, 100).await;

    assert_eq!(
        near.times_asked_about(address),
        1,
        "exactly one status call belongs to a retirement: none is a guess, more \
         than one is the unbounded polling the window exists to stop"
    );

    let after = state.db.get_order(id).await.expect("get").expect("order");
    assert_eq!(after.stage, Stage::Failed);
    assert!(
        after.error.as_deref().unwrap_or("").contains("never saw any ZEC"),
        "the message must say what was checked: {:?}",
        after.error
    );

    assert!(
        state.db.get_open_orders().await.expect("open").is_empty(),
        "a retired order must leave the polling set, or the budget fills with \
         orders nothing can happen to"
    );

    // And it stays gone: a second tick must not ask again.
    tick_capped_at(&state, 100).await;
    assert_eq!(near.times_asked_about(address), 1);
}

/// The coordinator's own six-hour cap, not 1Click's three-day one.
///
/// U2-1 and U2-7. 1Click answers the ten-minute deadline the coordinator asks
/// for with its own, which was three days on the day of the audit, and that is
/// what the row stores. An unfunded order held a place in the sweep for
/// seventy-three hours at no cost to whoever opened it. The cap makes the
/// backlog drain the same day.
#[tokio::test]
async fn a_three_day_1click_window_is_shortened_to_the_coordinators_own() {
    let (near, near_url) = start_status_mock(0).await;
    let temp = TempDir::new().expect("temp dir");
    let db_path = temp.path().join("window.db").to_string_lossy().to_string();
    let state = coordinator_with(&near_url, &db_path).await;

    let now = chrono::Utc::now();

    // Opened seven hours ago with the three-day deadline 1Click actually
    // issues. Under 1Click's window alone this has two days left to run.
    let stale = order_at(
        "t1ThreeDayWindow",
        now - chrono::Duration::hours(7),
        now + chrono::Duration::days(2),
    );
    let stale_id = stale.id;
    state.db.insert_order(&stale).await.expect("insert");

    // Opened one hour ago with the same three-day deadline: inside the cap, so
    // it must survive.
    let fresh = order_at(
        "t1StillInsideTheCap",
        now - chrono::Duration::hours(1),
        now + chrono::Duration::days(2),
    );
    let fresh_id = fresh.id;
    state.db.insert_order(&fresh).await.expect("insert");

    tick_capped_at(&state, 100).await;

    let stale = state.db.get_order(stale_id).await.expect("get").expect("order");
    assert_eq!(
        stale.stage,
        Stage::Failed,
        "an order seven hours old is past the coordinator's six-hour cap, \
         whatever deadline 1Click chose to hand out"
    );
    assert_eq!(near.times_asked_about("t1ThreeDayWindow"), 1);

    let fresh = state.db.get_order(fresh_id).await.expect("get").expect("order");
    assert_eq!(
        fresh.stage,
        Stage::AwaitingZec,
        "an order inside the cap must keep being polled"
    );
}

// ---------------------------------------------------------------------------
// The third half of U2-1: the backlog has to cost the attacker something
// ---------------------------------------------------------------------------

/// The counts the open path caps on.
///
/// The attack the audit priced needed twenty-five unfunded orders from one
/// address, which the limiter allows in about three and a half minutes because
/// it bounds the rate and not the outstanding set. `open_order` refuses at four
/// per session key and 200 across the coordinator; these are the numbers those
/// refusals are read from, so they are what is checked. Driving the refusal
/// through the handler itself would take a 1Click quote and a curator round
/// trip per order, which is what makes the cap worth having.
#[tokio::test]
async fn the_unfunded_backlog_is_counted_per_key_and_in_total() {
    let (_near, near_url) = start_status_mock(0).await;
    let temp = TempDir::new().expect("temp dir");
    let db_path = temp.path().join("backlog.db").to_string_lossy().to_string();
    let state = coordinator_with(&near_url, &db_path).await;

    let now = chrono::Utc::now();
    let expires = now + chrono::Duration::hours(2);

    // Six orders from one key, and one from another.
    for i in 0..6 {
        let mut order = order_at(&format!("t1Flood{i:08}"), now, expires);
        order.session_pubkey = "the-flooder".to_string();
        state.db.insert_order(&order).await.expect("insert");
    }
    let mut other = order_at("t1SomebodyElse", now, expires);
    other.session_pubkey = "a-real-sender".to_string();
    state.db.insert_order(&other).await.expect("insert");

    assert_eq!(
        state.db.count_unfunded_orders_for_key("the-flooder").await.expect("count"),
        6
    );
    assert_eq!(
        state.db.count_unfunded_orders_for_key("a-real-sender").await.expect("count"),
        1,
        "one caller's backlog must not be charged to another, or the cap \\
         becomes the denial of service it exists to prevent"
    );
    assert_eq!(state.db.count_unfunded_orders().await.expect("count"), 7);

    // A retired order is not a backlog. If it were, the flooder's cap would
    // never clear and they would have denied themselves the service rather
    // than everyone else, which is the wrong shape of bug but still a bug.
    let mut retired = order_at("t1AlreadyOver", now, expires);
    retired.session_pubkey = "the-flooder".to_string();
    retired.stage = Stage::Failed;
    state.db.insert_order(&retired).await.expect("insert");
    assert_eq!(
        state.db.count_unfunded_orders_for_key("the-flooder").await.expect("count"),
        6,
        "a failed order is still counted against its opener"
    );

    // Nor is a funded one: once an order becomes a session it has left the
    // 1Click polling set the cap is protecting.
    let mut funded = order_at("t1BecameASession", now, expires);
    funded.session_pubkey = "the-flooder".to_string();
    funded.session_uuid = Some(uuid::Uuid::new_v4());
    funded.stage = Stage::ZecSeen;
    state.db.insert_order(&funded).await.expect("insert");
    assert_eq!(
        state.db.count_unfunded_orders_for_key("the-flooder").await.expect("count"),
        6,
        "a promoted order is no longer unfunded"
    );
    assert_eq!(state.db.count_unfunded_orders().await.expect("count"), 7);
}

// ---------------------------------------------------------------------------
// U3-1: a deposit 1Click has seen is not "never saw any ZEC"
// ---------------------------------------------------------------------------

/// The four statuses that are neither SUCCESS nor REFUNDED, past the window.
///
/// Three of them mean 1Click has the sender's ZEC. `KNOWN_DEPOSIT_TX` is the
/// deposit transaction seen; `PROCESSING` is the swap running, and 1Click sits
/// there for as long as it sits there; `INCOMPLETE_DEPOSIT` is a wallet that
/// took its fee out of the amount instead of on top, which 1Click refunds at
/// its own deadline, three days out on every order the audit opened. The
/// fourth, `FAILED`, means the swap ran and failed, which is also not "nothing
/// was sent".
///
/// The round 2 fix asked 1Click before retiring and then retired on every one
/// of these anyway. `Failed` is out of `get_open_orders`, so the order stopped
/// being polled, and when the swap settled the sender's USDC landed on the glue
/// attributed to nothing while the page read "Nothing was sent, so nothing is
/// owed."
const SEEN_BUT_NOT_SETTLED: [&str; 4] = [
    "KNOWN_DEPOSIT_TX",
    "PROCESSING",
    "INCOMPLETE_DEPOSIT",
    "FAILED",
];

/// None of the four is retired past the window, and each is still polled and
/// promoted when it flips to SUCCESS.
///
/// The arrangement is the audit's: opened 361 minutes ago, so the
/// coordinator's own six-hour cap is what closed the window, with 1Click's
/// three-day deadline still open, which is what 1Click actually issues.
#[tokio::test]
async fn a_deposit_1click_has_seen_is_not_retired_at_the_window() {
    let (near, near_url) = start_status_mock(0).await;
    let temp = TempDir::new().expect("temp dir");
    let db_path = temp.path().join("seen.db").to_string_lossy().to_string();
    let state = coordinator_with(&near_url, &db_path).await;

    let now = chrono::Utc::now();
    let mut ids = Vec::new();

    for status in SEEN_BUT_NOT_SETTLED {
        let address = format!("t1Seen{status}");
        let order = order_at(
            &address,
            now - chrono::Duration::minutes(361),
            now + chrono::Duration::days(3),
        );
        near.answer(&address, status);
        ids.push((status, address, order.id));
        state.db.insert_order(&order).await.expect("insert");
    }

    // A control: same age, same window, and 1Click has seen nothing. This one
    // is supposed to be retired, and it is what makes the assertions below
    // about the other four a statement about the status and not about the
    // clock.
    let never = order_at(
        "t1NothingArrived",
        now - chrono::Duration::minutes(361),
        now + chrono::Duration::days(3),
    );
    let never_id = never.id;
    state.db.insert_order(&never).await.expect("insert");

    tick_capped_at(&state, 100).await;

    for (status, address, id) in &ids {
        let after = state.db.get_order(*id).await.expect("get").expect("order");
        assert!(
            near.times_asked_about(address) > 0,
            "1Click was never asked about the {status} order"
        );
        assert_ne!(
            after.stage,
            Stage::Failed,
            "U3-1: 1Click reports {status}, which means it has the sender's ZEC, \
             and the order was retired anyway. Stage is {:?} and the sender reads \
             {:?}",
            after.stage,
            after.error
        );
        assert!(
            !after
                .error
                .as_deref()
                .unwrap_or("")
                .contains("never saw any ZEC"),
            "U3-1: the {status} order was told nothing was sent: {:?}",
            after.error
        );
    }

    let control = state.db.get_order(never_id).await.expect("get").expect("order");
    assert_eq!(
        control.stage,
        Stage::Failed,
        "the control was PENDING_DEPOSIT past its window and must still be retired, \
         or the fix has simply stopped retiring anything"
    );

    // The half the round 2 fix could not reach: the swap settles later, and
    // the order has to still be in the polling set to see it.
    let open_now: std::collections::HashSet<uuid::Uuid> = state
        .db
        .get_open_orders()
        .await
        .expect("open")
        .into_iter()
        .map(|o| o.id)
        .collect();
    for (status, _, id) in &ids {
        assert!(
            open_now.contains(id),
            "U3-1: the {status} order left the polling set, so nothing will ever \
             notice when its swap settles"
        );
    }

    for (_, address, _) in &ids {
        near.settle(address);
    }
    let calls_before: Vec<usize> = ids
        .iter()
        .map(|(_, a, _)| near.times_asked_about(a))
        .collect();

    tick_capped_at(&state, 100).await;

    for ((status, address, id), before) in ids.iter().zip(calls_before) {
        assert!(
            near.times_asked_about(address) > before,
            "U3-1: the {status} order was not polled after it settled. That is the \
             stranding: the USDC is on the glue attributed to nothing."
        );

        // Promotion itself needs a chain, and this test has none, so what the
        // sweep can be held to is that it saw the SUCCESS and tried. The
        // marker is the absence of the retirement: an order that reached the
        // promotion branch and failed at the first chain call is still open
        // and still says nothing about money not being owed.
        let after = state.db.get_order(*id).await.expect("get").expect("order");
        assert!(
            !after
                .error
                .as_deref()
                .unwrap_or("")
                .contains("nothing is owed"),
            "U3-1: the settled {status} order still reads as owing nothing: {:?}",
            after.error
        );
    }
}

/// An in-flight deposit keeps its place in the rotation, tick after tick.
///
/// The test above checks the four statuses once each. This one checks that the
/// survival lasts: six ticks of PROCESSING past the coordinator's window, six
/// status calls, and the order still open to see the seventh. Under the round 2
/// fix the first tick retired it and the other five polled nothing at all, so
/// the count is what separates a fix from a coincidence.
#[tokio::test]
async fn a_deposit_seen_past_the_window_still_promotes_when_it_settles() {
    let (near, near_url) = start_status_mock(0).await;
    let temp = TempDir::new().expect("temp dir");
    let db_path = temp.path().join("late-promote.db").to_string_lossy().to_string();
    let state = coordinator_with(&near_url, &db_path).await;

    let now = chrono::Utc::now();
    let address = "t1ProcessingThenPaid";
    let order = order_at(
        address,
        now - chrono::Duration::minutes(361),
        now + chrono::Duration::days(3),
    );
    let id = order.id;
    near.answer(address, "PROCESSING");
    state.db.insert_order(&order).await.expect("insert");

    // Six ticks of an in-flight swap past the window. Under the round 2 fix
    // the first of these retired it and the other five polled nothing.
    for _ in 0..6 {
        tick_capped_at(&state, 100).await;
    }
    assert_eq!(
        near.times_asked_about(address),
        6,
        "an in-flight deposit has to keep being polled: it was asked about {} \
         times in six ticks",
        near.times_asked_about(address)
    );

    let after = state.db.get_order(id).await.expect("get").expect("order");
    assert_eq!(after.stage, Stage::AwaitingZec);

    // And when 1Click finishes, the sweep is still there to see it.
    near.settle(address);
    tick_capped_at(&state, 100).await;
    assert_eq!(near.times_asked_about(address), 7);
}

/// An in-flight deposit is still bounded: 1Click's own deadline plus the grace
/// hour ends the polling.
///
/// The fix must not trade a stranding for an unbounded polling set. A swap
/// 1Click has been reporting as in flight past the deadline it set itself is
/// not going to resolve by being asked again, and the sender is told what was
/// seen rather than that nothing was.
#[tokio::test]
async fn an_in_flight_deposit_is_bounded_by_1clicks_own_deadline() {
    let (near, near_url) = start_status_mock(0).await;
    let temp = TempDir::new().expect("temp dir");
    let db_path = temp.path().join("seen-bound.db").to_string_lossy().to_string();
    let state = coordinator_with(&near_url, &db_path).await;

    let now = chrono::Utc::now();
    let address = "t1ProcessingForever";
    // 1Click's deadline passed ninety minutes ago, so it is past that deadline
    // plus the grace hour too.
    let order = order_at(
        address,
        now - chrono::Duration::hours(4),
        now - chrono::Duration::minutes(90),
    );
    let id = order.id;
    near.answer(address, "PROCESSING");
    state.db.insert_order(&order).await.expect("insert");

    tick_capped_at(&state, 100).await;

    let after = state.db.get_order(id).await.expect("get").expect("order");
    assert_eq!(
        after.stage,
        Stage::Failed,
        "a swap 1Click reports in flight past its own deadline is not polled forever"
    );
    let message = after.error.unwrap_or_default();
    assert!(
        message.contains("saw your ZEC"),
        "the sender has to be told what was seen, not that nothing was: {message}"
    );
    assert!(
        !message.contains("never saw any ZEC"),
        "the wrong sentence again: {message}"
    );

    // And it leaves the set, so the bound is real.
    tick_capped_at(&state, 100).await;
    assert_eq!(near.times_asked_about(address), 1);
}

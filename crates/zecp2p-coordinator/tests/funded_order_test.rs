//! The funded main-route order, end to end.
//!
//! This is the test the branch never had, and its absence is why U1-1 shipped.
//! Every check the build did stopped at "Continue produces a QR": nothing was
//! ever funded, so nothing ever exercised promotion, and promotion took a
//! second 1Click quote and pointed the session at an address nobody had paid.
//!
//! What makes the bug visible here is that the mock mints a *fresh* deposit
//! address on every quote, exactly as 1Click does. A promotion that re-quotes
//! gets an address the sender never saw, and the assertion below fails. Against
//! a mock that returned a fixed address, the bug would pass unnoticed, so that
//! property is asserted first and separately.
//!
//! Needs anvil and forge, and `contracts/lib/forge-std` present:
//!
//!     git submodule update --init contracts/lib/forge-std
//!     cargo test -p zecp2p-coordinator --test funded_order_test -- --ignored --nocapture

mod test_utils;

use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Duration;

use alloy::primitives::U256;
use alloy::providers::{Provider, ProviderBuilder};
use alloy::network::EthereumWallet;
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::SignerSync;
use axum::{routing::{get, post}, Json, Router};
use serde::{Deserialize, Serialize};
use tempfile::TempDir;
use test_utils::{MockZkp2pServer, ANVIL_PRIVATE_KEY, KEEPER_PRIVATE_KEY};
use tokio::net::TcpListener;
use zecp2p_types::settlement::{Stage, DepositKind};

static ANVIL_PORT: AtomicU16 = AtomicU16::new(8830);
static NEAR_PORT: AtomicU16 = AtomicU16::new(9830);

// ---------------------------------------------------------------------------
// A 1Click mock that behaves like 1Click: a new deposit address per quote.
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct NearMock {
    /// Every deposit address this mock has ever handed out, in order.
    minted: Arc<std::sync::Mutex<Vec<String>>>,
    /// Deposit address -> the status to report for it.
    statuses: Arc<std::sync::Mutex<std::collections::HashMap<String, String>>>,
    /// Deposit address -> what `swapDetails.amountOut` says once it settles.
    settled: Arc<std::sync::Mutex<std::collections::HashMap<String, String>>>,
    /// How many quotes have been asked for. The promotion path must add none.
    quotes: Arc<std::sync::atomic::AtomicUsize>,
    /// Deposit deadline handed out with each quote.
    deadline_minutes: Arc<std::sync::atomic::AtomicI64>,
}

impl NearMock {
    fn new() -> Self {
        Self {
            minted: Arc::new(std::sync::Mutex::new(Vec::new())),
            statuses: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            settled: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            quotes: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            deadline_minutes: Arc::new(std::sync::atomic::AtomicI64::new(10)),
        }
    }

    fn quote_count(&self) -> usize {
        self.quotes.load(Ordering::SeqCst)
    }

    fn minted_addresses(&self) -> Vec<String> {
        self.minted.lock().unwrap().clone()
    }

    /// Say the ZEC arrived and the swap settled, for one address only.
    fn settle(&self, address: &str, usdc_units: &str) {
        self.statuses
            .lock()
            .unwrap()
            .insert(address.to_string(), "SUCCESS".to_string());
        self.settled
            .lock()
            .unwrap()
            .insert(address.to_string(), usdc_units.to_string());
    }

    fn set_deadline_minutes(&self, m: i64) {
        self.deadline_minutes.store(m, Ordering::SeqCst);
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct QuoteReq {
    amount: String,
    dry: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct QuoteResp {
    correlation_id: String,
    quote: QuoteBody,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct QuoteBody {
    amount_out: String,
    min_amount_out: String,
    time_estimate: i64,
    deposit_address: Option<String>,
    deadline: String,
}

/// Thirty dollars a ZEC, so the arithmetic in the assertions is legible.
fn usdc_for(zatoshi: u64) -> u64 {
    (zatoshi as u128 * 30 * 1_000_000 / 100_000_000) as u64
}

async fn quote_handler(
    axum::extract::State(mock): axum::extract::State<NearMock>,
    Json(req): Json<QuoteReq>,
) -> Json<QuoteResp> {
    let zatoshi: u64 = req.amount.parse().unwrap_or(0);
    let out = usdc_for(zatoshi);
    let minutes = mock.deadline_minutes.load(Ordering::SeqCst);
    let deadline = chrono::Utc::now() + chrono::Duration::minutes(minutes);

    // A dry quote reserves nothing and returns no address, as the real API does.
    let address = if req.dry {
        None
    } else {
        mock.quotes.fetch_add(1, Ordering::SeqCst);
        let a = format!(
            "t1MockDeposit{:08x}",
            mock.minted.lock().unwrap().len() as u32 + 0x1000
        );
        mock.minted.lock().unwrap().push(a.clone());
        mock.statuses
            .lock()
            .unwrap()
            .insert(a.clone(), "PENDING_DEPOSIT".to_string());
        Some(a)
    };

    Json(QuoteResp {
        correlation_id: uuid::Uuid::new_v4().to_string(),
        quote: QuoteBody {
            amount_out: out.to_string(),
            min_amount_out: (out * 99 / 100).to_string(),
            time_estimate: 300,
            deposit_address: address,
            deadline: deadline.to_rfc3339(),
        },
    })
}

#[derive(Deserialize)]
struct StatusQuery {
    #[serde(rename = "depositAddress")]
    deposit_address: String,
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

fn tx(h: &str) -> TxHash {
    TxHash { hash: h.to_string(), explorer_url: String::new() }
}

async fn status_handler(
    axum::extract::State(mock): axum::extract::State<NearMock>,
    axum::extract::Query(q): axum::extract::Query<StatusQuery>,
) -> Json<StatusResp> {
    // Per address, which is the whole point: a session watching the wrong
    // address must see PENDING_DEPOSIT forever, exactly as it would live.
    let status = mock
        .statuses
        .lock()
        .unwrap()
        .get(&q.deposit_address)
        .cloned()
        .unwrap_or_else(|| "PENDING_DEPOSIT".to_string());

    let delivered = status == "SUCCESS";
    let settled = mock
        .settled
        .lock()
        .unwrap()
        .get(&q.deposit_address)
        .cloned()
        .unwrap_or_else(|| "0".to_string());

    Json(StatusResp {
        status,
        swap_details: SwapDetails {
            amount_out: delivered.then_some(settled),
            refunded_amount: Some("0".to_string()),
            origin_chain_tx_hashes: vec![tx("0xsource")],
            destination_chain_tx_hashes: if delivered { vec![tx("0xdest")] } else { vec![] },
        },
    })
}

async fn start_near_mock() -> (NearMock, String) {
    let port = NEAR_PORT.fetch_add(1, Ordering::SeqCst);
    let mock = NearMock::new();
    let app = Router::new()
        .route("/v0/quote", post(quote_handler))
        .route("/v0/status", get(status_handler))
        .with_state(mock.clone());

    let listener = TcpListener::bind(("127.0.0.1", port)).await.expect("bind");
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    tokio::time::sleep(Duration::from_millis(100)).await;

    (mock, format!("http://127.0.0.1:{port}"))
}

// ---------------------------------------------------------------------------
// Anvil and the contracts
// ---------------------------------------------------------------------------

struct Anvil {
    child: std::process::Child,
    url: String,
}

impl Anvil {
    fn start() -> Self {
        let port = ANVIL_PORT.fetch_add(1, Ordering::SeqCst);
        let child = std::process::Command::new("anvil")
            .args(["--port", &port.to_string()])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("anvil must be installed to run this test");
        std::thread::sleep(Duration::from_millis(2500));
        Self { child, url: format!("http://127.0.0.1:{port}") }
    }
}

impl Drop for Anvil {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn signing_provider(url: &str, key: &str) -> impl Provider {
    let signer: PrivateKeySigner = key.parse().expect("key");
    ProviderBuilder::new()
        .wallet(EthereumWallet::from(signer))
        .connect(url)
        .await
        .expect("connect")
}

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

/// The whole main route, with an order that actually gets funded.
///
/// The assertions in order:
///  1. the mock mints a new address per quote, or nothing below proves anything
///  2. opening produces a deposit address, no session, and no gas
///  3. the same signature cannot open a second order
///  4. a quote id the coordinator never issued is refused
///  5. funding *the address the sender was shown* promotes the order
///  6. the session watches that address, not a new one
///  7. no extra quote was taken at promotion
///  8. the session's expected and floor come from the sender's own quote
///  9. the order reaches ZecSeen and never reads AwaitingZec again
#[tokio::test]
#[ignore = "requires anvil and forge"]
async fn a_funded_order_credits_the_session_it_was_paid_into() {
    let anvil = Anvil::start();
    std::env::set_var("COORDINATOR_PRIVATE_KEY", KEEPER_PRIVATE_KEY);

    let (usdc_addr, escrow_addr, glue_addr) = test_utils::deploy_enhanced_contracts(&anvil.url);
    let (near, near_url) = start_near_mock().await;
    let zkp2p = MockZkp2pServer::start().await;

    let temp = TempDir::new().expect("temp dir");
    let db_path = temp.path().join("funded.db").to_string_lossy().to_string();

    let mut config = test_utils::test_config_for(
        &anvil.url, &near_url, &zkp2p.api_url(), usdc_addr, escrow_addr, glue_addr, &db_path,
    );
    // The order sweep is the path under test, so let it run often.
    config.keeper.poll_interval_seconds = 2;

    let db = zecp2p_coordinator::db::Database::new(&db_path).await.expect("db");
    db.run_migrations().await.expect("migrations");

    let chain = zecp2p_coordinator::chain::ChainClient::new(&config).await.expect("chain");
    let state = Arc::new(zecp2p_coordinator::state::AppState::new(
        config.clone(),
        db,
        chain,
        zecp2p_coordinator::near::NearIntentsClient::new(&config.near),
        zecp2p_coordinator::zkp2p::Zkp2pClient::new(&config.zkp2p),
    ));

    // --- 1. the mock must behave like 1Click, or this test proves nothing ---
    {
        let probe = zecp2p_coordinator::near::NearIntentsClient::new(&config.near);
        let req = || zecp2p_coordinator::near::NearIntentsClient::zec_to_usdc_base_request(
            50_000_000, &glue_addr.to_string(), "t1StbPM4X3j4FGM57HpGnb9BMbS7C1nFW1r", Some(50),
        );
        let a = probe.get_quote(req()).await.expect("probe quote a");
        let b = probe.get_quote(req()).await.expect("probe quote b");
        assert_ne!(
            a.deposit_address, b.deposit_address,
            "the mock must mint a new deposit address per quote, as 1Click does; \
             with a fixed address this test cannot see a re-quote at all"
        );
    }
    let quotes_before_open = near.quote_count();

    // --- the sender's session key ---
    let session_key = PrivateKeySigner::random();
    let pubkey_hex = {
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        let p = session_key.credential().verifying_key().as_affine().to_encoded_point(true);
        hex::encode(p.as_bytes())
    };

    // --- price it, exactly as the page does ---
    let zatoshi: u64 = 50_000_000;
    let quote = zecp2p_coordinator::api_v2::test_entry::quote(&state, zatoshi).await
        .expect("quote");
    println!("quoted {} zatoshi -> net {} cents", quote.zec_zatoshi, quote.net_cents);

    // --- 2. open it ---
    let handle = "fundedtest";
    let scope = format!("{}:venmo:{}", quote.quote_id, handle);
    let message = zecp2p_coordinator::auth::ownership_message(
        "open", session_key.address(), &scope,
    );
    let signature = session_key.sign_message_sync(message.as_bytes()).expect("sign").to_string();

    let open = zecp2p_types::settlement::OpenRequest {
        quote_id: quote.quote_id.clone(),
        destination: zecp2p_types::settlement::PayoutDestination {
            rail: zecp2p_types::settlement::Rail::Venmo,
            handle: handle.to_string(),
        },
        session_pubkey: pubkey_hex.clone(),
        overrides: Default::default(),
    };

    let opened = zecp2p_coordinator::api_v2::test_entry::open(&state, &signature, open.clone())
        .await
        .expect("open the order");

    let paid_address = opened.deposit.address.clone();
    println!("order {} -> deposit address {paid_address}", opened.order_id);
    assert_eq!(opened.deposit.kind, DepositKind::Swap);
    assert!(
        near.minted_addresses().contains(&paid_address),
        "the deposit address must be one 1Click actually minted"
    );

    let order = state.db.get_order(opened.order_id).await.expect("get").expect("order exists");
    assert_eq!(order.stage, Stage::AwaitingZec);
    assert!(order.session_uuid.is_none(), "opening must spend no gas and create no session");
    assert!(
        order.swap_expected_usdc.is_some() && order.swap_min_usdc.is_some(),
        "the order must record the outputs of the quote its address came from"
    );

    // --- 3. the same signature must not open a second order (U1-2) ---
    let replay = zecp2p_coordinator::api_v2::test_entry::open(&state, &signature, open.clone()).await;
    assert!(
        replay.is_err(),
        "one signature opened a second order; the audit got 31 this way"
    );

    // --- 4. an invented quote id must be refused (U1-2) ---
    {
        let fake_id = format!("{}@{}", uuid::Uuid::new_v4(), zatoshi);
        let fake_scope = format!("{fake_id}:venmo:{handle}");
        let fake_msg = zecp2p_coordinator::auth::ownership_message(
            "open", session_key.address(), &fake_scope,
        );
        let fake_sig = session_key.sign_message_sync(fake_msg.as_bytes()).expect("sign").to_string();
        let mut body = open.clone();
        body.quote_id = fake_id;

        let made_up = zecp2p_coordinator::api_v2::test_entry::open(&state, &fake_sig, body).await;
        assert!(
            made_up.is_err(),
            "a quote id the coordinator never issued was accepted"
        );
    }

    // --- 5. fund the address the sender was actually shown ---
    let expected_usdc: u64 = order.swap_expected_usdc.as_ref().unwrap().parse().unwrap();
    near.settle(&paid_address, &expected_usdc.to_string());
    // The swap delivers USDC to the glue, which is what the real bridge does.
    {
        let provider = signing_provider(&anvil.url, ANVIL_PRIVATE_KEY).await;
        zecp2p_types::abi::MockUSDC::new(usdc_addr, &provider)
            .mint(glue_addr, U256::from(expected_usdc))
            .send().await.expect("mint send")
            .get_receipt().await.expect("mint receipt");
    }
    println!("funded {paid_address} for {expected_usdc} USDC units");

    // --- run the keeper ---
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let keeper = state.clone();
    let keeper_handle = tokio::spawn(async move {
        keeper.run_keeper_loop_with_shutdown(shutdown_rx).await
    });

    // --- 9. watch the ladder, and check it never goes backwards ---
    let mut seen: Vec<Stage> = Vec::new();
    let mut promoted = None;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let o = state.db.get_order(opened.order_id).await.expect("get").expect("order");
        if seen.last() != Some(&o.stage) {
            println!("  stage -> {:?}", o.stage);
            seen.push(o.stage);
        }
        if let Some(sid) = o.session_uuid {
            promoted = Some(sid);
        }
        // Stop once the order is in escrow, which is several ticks past
        // promotion: long enough for the stage to have flickered back to
        // AwaitingZec if it were going to.
        if promoted.is_some() && o.stage == Stage::InEscrow {
            break;
        }
    }

    let _ = shutdown_tx.send(true);
    let _ = keeper_handle.await;

    let session_uuid = promoted.expect(
        "the funded order was never promoted into a session; \
         the keeper saw the ZEC settle and did nothing",
    );

    // --- 6. the session must watch the address the sender paid (U1-1) ---
    let session = state.db.get_session(session_uuid).await.expect("get session").expect("session");
    assert_eq!(
        session.near_deposit_address.as_deref(),
        Some(paid_address.as_str()),
        "the session is watching a different deposit address than the sender funded. \
         This is U1-1: the sender's USDC lands on the glue attributed to nothing, \
         creditSession is never sent, and the dead session holds the one-session \
         gate shut for the NEAR timeout."
    );

    // --- 7. promotion must take no new quote ---
    assert_eq!(
        near.quote_count(),
        quotes_before_open + 1,
        "promotion took another 1Click quote. Exactly one real quote belongs to \
         an order: the one whose address the sender was shown."
    );
    assert_eq!(
        near.minted_addresses().len(),
        quotes_before_open + 1,
        "a deposit address was minted that nothing will ever fund"
    );

    // --- 8. the money figures must be the sender's own ---
    assert_eq!(
        session.expected_usdc,
        Some(U256::from(expected_usdc)),
        "the session's expected USDC must come from the quote the sender was shown, \
         or CreditExceedsExpected is checked against the wrong number"
    );
    assert_eq!(
        session.min_output_usdc,
        Some(U256::from(order.swap_min_usdc.as_ref().unwrap().parse::<u64>().unwrap())),
    );

    // --- the credit actually landed ---
    assert!(
        session.received_usdc.is_some_and(|r| r > U256::ZERO),
        "the session was promoted but never credited; status was {:?}",
        session.status
    );
    println!("credited {:?} to session {}", session.received_usdc, session.id);

    // --- 9, concluded: no rung was ever given back ---
    let ranks: Vec<u8> = seen.iter().filter_map(|s| s.rank()).collect();
    let mut sorted = ranks.clone();
    sorted.sort_unstable();
    assert_eq!(
        ranks, sorted,
        "the status ladder went backwards: {seen:?}. A sender who has been told \
         'ZEC seen' must never be told 'waiting for your ZEC' again."
    );
    assert!(
        seen.contains(&Stage::ZecSeen) || seen.contains(&Stage::InEscrow),
        "the order never reported the ZEC arriving: {seen:?}"
    );

    println!("\nfunded order test passed: {seen:?}");
}

/// An order nobody funds stops being polled once its deposit window closes.
///
/// U1-2. 1Click answers PENDING_DEPOSIT for an address long past its deadline,
/// so before this nothing ever retired an order and every order ever opened was
/// polled on every tick, forever.
#[tokio::test]
#[ignore = "requires anvil and forge"]
async fn an_unfunded_order_expires_and_stops_being_polled() {
    let anvil = Anvil::start();
    std::env::set_var("COORDINATOR_PRIVATE_KEY", KEEPER_PRIVATE_KEY);

    let (usdc_addr, escrow_addr, glue_addr) = test_utils::deploy_enhanced_contracts(&anvil.url);
    let (near, near_url) = start_near_mock().await;
    let zkp2p = MockZkp2pServer::start().await;

    let temp = TempDir::new().expect("temp dir");
    let db_path = temp.path().join("expiry.db").to_string_lossy().to_string();
    let config = test_utils::test_config_for(
        &anvil.url, &near_url, &zkp2p.api_url(), usdc_addr, escrow_addr, glue_addr, &db_path,
    );

    let db = zecp2p_coordinator::db::Database::new(&db_path).await.expect("db");
    db.run_migrations().await.expect("migrations");
    let chain = zecp2p_coordinator::chain::ChainClient::new(&config).await.expect("chain");
    let state = Arc::new(zecp2p_coordinator::state::AppState::new(
        config.clone(), db, chain,
        zecp2p_coordinator::near::NearIntentsClient::new(&config.near),
        zecp2p_coordinator::zkp2p::Zkp2pClient::new(&config.zkp2p),
    ));

    let session_key = PrivateKeySigner::random();
    let pubkey_hex = {
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        let p = session_key.credential().verifying_key().as_affine().to_encoded_point(true);
        hex::encode(p.as_bytes())
    };

    // Price it against a live window, so the *quote* is valid, and only then
    // make the deposit window a closed one. The two deadlines are separate: a
    // price the sender can still act on, and a deposit address 1Click will no
    // longer settle. Collapsing them would test the quote registry instead of
    // the expiry this is about.
    let quote = zecp2p_coordinator::api_v2::test_entry::quote(&state, 50_000_000).await.expect("quote");
    near.set_deadline_minutes(-120);
    let handle = "expirytest";
    let scope = format!("{}:venmo:{}", quote.quote_id, handle);
    let msg = zecp2p_coordinator::auth::ownership_message("open", session_key.address(), &scope);
    let sig = session_key.sign_message_sync(msg.as_bytes()).expect("sign").to_string();

    let opened = zecp2p_coordinator::api_v2::test_entry::open(&state, &sig,
        zecp2p_types::settlement::OpenRequest {
            quote_id: quote.quote_id.clone(),
            destination: zecp2p_types::settlement::PayoutDestination {
                rail: zecp2p_types::settlement::Rail::Venmo,
                handle: handle.to_string(),
            },
            session_pubkey: pubkey_hex,
            overrides: Default::default(),
        }).await.expect("open");

    assert_eq!(
        state.db.get_open_orders().await.expect("open orders").len(), 1,
        "the order should be polled before its window closes"
    );

    state.tick_orders().await.expect("tick");

    let order = state.db.get_order(opened.order_id).await.expect("get").expect("order");
    assert_eq!(order.stage, Stage::Failed, "an expired unfunded order must be terminal");
    assert!(
        order.error.as_deref().is_some_and(|e| e.contains("deposit window")),
        "the sender should be told what happened, got {:?}",
        order.error
    );
    assert!(
        state.db.get_open_orders().await.expect("open orders").is_empty(),
        "an expired order must drop out of the keeper's polling set"
    );

    // And nothing about it is polled again.
    let calls_before = near.quote_count();
    state.tick_orders().await.expect("second tick");
    assert_eq!(near.quote_count(), calls_before);
}

/// A handle the curator rejects must not burn the price the sender is holding.
///
/// U2-4. `open_order` spent the quote id before asking the curator whether the
/// handle existed, so a typo answered "check the handle matches the account's
/// exact spelling" with the id already gone, and the corrected resubmission
/// answered "an order has already been opened at that price". No order existed
/// either time, and the only way out was to change the amount so a new quote
/// was taken. The two messages together tell a sender to do something that
/// cannot work.
#[tokio::test]
#[ignore = "requires anvil and forge"]
async fn a_rejected_handle_leaves_the_price_usable() {
    let anvil = Anvil::start();
    std::env::set_var("COORDINATOR_PRIVATE_KEY", KEEPER_PRIVATE_KEY);

    let (usdc_addr, escrow_addr, glue_addr) = test_utils::deploy_enhanced_contracts(&anvil.url);
    let (_near, near_url) = start_near_mock().await;
    let zkp2p = MockZkp2pServer::start().await;

    let temp = TempDir::new().expect("temp dir");
    let db_path = temp.path().join("typo.db").to_string_lossy().to_string();
    let config = test_utils::test_config_for(
        &anvil.url, &near_url, &zkp2p.api_url(), usdc_addr, escrow_addr, glue_addr, &db_path,
    );

    let db = zecp2p_coordinator::db::Database::new(&db_path).await.expect("db");
    db.run_migrations().await.expect("migrations");
    let chain = zecp2p_coordinator::chain::ChainClient::new(&config).await.expect("chain");
    let state = Arc::new(zecp2p_coordinator::state::AppState::new(
        config.clone(), db, chain,
        zecp2p_coordinator::near::NearIntentsClient::new(&config.near),
        zecp2p_coordinator::zkp2p::Zkp2pClient::new(&config.zkp2p),
    ));

    let session_key = PrivateKeySigner::random();
    let pubkey_hex = {
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        let p = session_key.credential().verifying_key().as_affine().to_encoded_point(true);
        hex::encode(p.as_bytes())
    };

    let quote = zecp2p_coordinator::api_v2::test_entry::quote(&state, 50_000_000).await
        .expect("quote");

    let sign = |handle: &str| {
        let scope = format!("{}:venmo:{handle}", quote.quote_id);
        let msg = zecp2p_coordinator::auth::ownership_message("open", session_key.address(), &scope);
        session_key.sign_message_sync(msg.as_bytes()).expect("sign").to_string()
    };
    let body = |handle: &str| zecp2p_types::settlement::OpenRequest {
        quote_id: quote.quote_id.clone(),
        destination: zecp2p_types::settlement::PayoutDestination {
            rail: zecp2p_types::settlement::Rail::Venmo,
            handle: handle.to_string(),
        },
        session_pubkey: pubkey_hex.clone(),
        overrides: Default::default(),
    };

    // The typo: the curator says no.
    zkp2p.set_reject(true);
    let typo = "mispelt";
    let refused = zecp2p_coordinator::api_v2::test_entry::open(&state, &sign(typo), body(typo))
        .await
        .expect_err("the curator rejected this handle, so the open must fail");
    let refused = refused.to_string();
    assert!(
        refused.contains("payment network") || refused.contains("spelling"),
        "the sender must be told the handle is the problem, not the price: {refused}"
    );

    // The sender fixes the handle and submits again against the same price.
    zkp2p.set_reject(false);
    let fixed = "speltright";
    let opened = zecp2p_coordinator::api_v2::test_entry::open(&state, &sign(fixed), body(fixed))
        .await
        .unwrap_or_else(|e| {
            panic!(
                "U2-4: the corrected handle was refused with {e:?}. The rejected open \
                 spent the quote, so the sender was told to fix the handle and then \
                 told the price was gone, with no order created either time."
            )
        });

    let order = state.db.get_order(opened.order_id).await.expect("get").expect("order");
    assert_eq!(order.destination.handle, fixed);
    assert_eq!(order.stage, Stage::AwaitingZec);

    // The single-use property still has to hold: the price is spent now, and a
    // third open against it is refused however good the handle is (U1-2).
    let replay = zecp2p_coordinator::api_v2::test_entry::open(&state, &sign(fixed), body(fixed)).await;
    assert!(
        replay.is_err(),
        "the quote opened a second order; single-use is what makes the signature \
         single-use, and reordering the checks must not have cost it"
    );
}

//! The first dollar ask after a restart has to name a dollar amount.
//!
//! U3-3. `quote_v2` sizes a dollar ask from a probe quote and then checks the
//! result against `observed_floor()`, which holds the last floor 1Click named
//! in a rejection. Nothing persists that number, so on a fresh process it is
//! the constant in `near.rs`, which is a guess and was 52,000 zatoshi against a
//! real floor of 132,000. The local check passes, 1Click refuses the real
//! quote, and the refusal came back with the zatoshi floor and no `min_cents`.
//! The page had asked in dollars, so it rendered "Send at least 0.00132 ZEC"
//! under a dollar sign. A reload fixed it, because by then the floor had been
//! learned; the sender who hit the deep link first did not get a reload.
//!
//! This lives in its own test binary because `observed_floor()` is one static
//! for the process. Sharing a binary with anything that provokes a rejection
//! would mean this test passes or fails on the order the runner picked, and the
//! whole point is what happens before any rejection has been seen.

mod test_utils;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::{routing::post, Json, Router};
use tempfile::TempDir;
use tokio::net::TcpListener;

/// 1Click's real floor on the day the audit ran, and its rate for one ZEC.
const FLOOR_ZATOSHI: u64 = 132_000;
const UNITS_PER_ZEC: u64 = 819_907_155;

/// A 1Click that prices a dry probe and refuses anything under its floor with
/// the message the parser reads.
async fn quote_handler(
    axum::extract::State(calls): axum::extract::State<Arc<AtomicUsize>>,
    Json(body): Json<serde_json::Value>,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    calls.fetch_add(1, Ordering::SeqCst);
    let amount: u64 = body["amount"].as_str().unwrap_or("0").parse().unwrap_or(0);

    if amount < FLOOR_ZATOSHI {
        // The exact shape `parse_floor_from_error` reads, which is how the
        // coordinator learns the floor at all.
        return (
            axum::http::StatusCode::BAD_REQUEST,
            format!("Amount is too low for bridge, try at least {FLOOR_ZATOSHI}"),
        )
            .into_response();
    }

    let out = (amount as u128 * UNITS_PER_ZEC as u128) / 100_000_000;
    Json(serde_json::json!({
        "correlationId": "cold-floor-test",
        "quote": {
            "depositAddress": "t1KhV8ADhTGvVvBpTiEcJGnhTvBBFWERZu7",
            "amountOut": out.to_string(),
            "minAmountOut": out.to_string(),
            "deadline": "2030-01-01T00:00:00Z",
            "timeEstimate": 300,
        }
    }))
    .into_response()
}

async fn start_1click() -> (Arc<AtomicUsize>, String) {
    let calls = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route("/v0/quote", post(quote_handler))
        .with_state(calls.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    (calls, format!("http://127.0.0.1:{port}"))
}

/// The very first dollar ask this process makes, and it has to name dollars.
#[tokio::test]
async fn the_first_dollar_ask_after_a_restart_names_a_dollar_amount() {
    // The guess this process starts with is well under 1Click's real floor,
    // which is the condition the defect needs. If they ever coincide the test
    // stops meaning anything, so it says so.
    assert!(
        zecp2p_coordinator::near::observed_floor() < FLOOR_ZATOSHI,
        "the starting guess is already at or above 1Click's floor, so nothing \
         here reaches the upstream refusal this test is about"
    );

    let (_calls, near_url) = start_1click().await;
    let temp = TempDir::new().expect("temp dir");
    let db_path = temp.path().join("cold.db").to_string_lossy().to_string();

    let config = test_utils::test_config_for(
        "http://127.0.0.1:1",
        &near_url,
        "http://127.0.0.1:1",
        Default::default(),
        Default::default(),
        "0x0000000000000000000000000000000000000099".parse().unwrap(),
        &db_path,
    );
    let db = zecp2p_coordinator::db::Database::new(&db_path).await.expect("db");
    db.run_migrations().await.expect("migrations");
    let chain = zecp2p_coordinator::chain::ChainClient::new_readonly(&config)
        .await
        .expect("chain");
    let state = Arc::new(zecp2p_coordinator::state::AppState::new(
        config.clone(),
        db,
        chain,
        zecp2p_coordinator::near::NearIntentsClient::new(&config.near),
        zecp2p_coordinator::zkp2p::Zkp2pClient::new(&config.zkp2p),
    ));

    // `?usd=1`, which is the deep link the launch page puts in front of people.
    let err = zecp2p_coordinator::api_v2::test_entry::quote_usd(&state, 100)
        .await
        .expect_err("a dollar is under 1Click's floor and has to be refused");

    match err {
        zecp2p_coordinator::error::AppError::BelowFloor { zatoshi, cents } => {
            assert_eq!(zatoshi, FLOOR_ZATOSHI, "the floor 1Click named is the floor reported");
            let cents = cents.expect(
                "U3-3: the first dollar ask of the process named no dollar amount, so the \
                 page prints a ZEC figure under a dollar sign",
            );
            assert_eq!(
                cents, 109,
                "the amount named has to be the first one that quotes at this rate"
            );

            // And the amount it names actually quotes, which is the whole
            // reason the coordinator owns the conversion (U2-3).
            zecp2p_coordinator::api_v2::test_entry::quote_usd(&state, cents)
                .await
                .expect("the amount the refusal named has to be quotable");
        }
        other => panic!("a dollar under the floor came back as {other:?}"),
    }
}

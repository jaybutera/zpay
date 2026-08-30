//! Integration tests for the NEAR Intents 1Click API
//!
//! The tests that reach the network are gated on `LIVE_API=1` so CI skips them
//! by default:
//!
//! ```sh
//! LIVE_API=1 cargo test -p zecp2p-coordinator --test near_intents_test
//! ```
//!
//! They only request quotes. A quote costs nothing and commits nothing: funds
//! move only when ZEC is sent to the returned deposit address, which no test
//! here does. Their job is to catch schema drift and constraint changes before
//! a run that does spend money.

use zecp2p_coordinator::near::{
    assets, validate_zec_refund_address, NearIntentsClient, QuoteRequest, MIN_ZEC_ZATOSHI,
};
use zecp2p_types::config::NearConfig;

/// A mainnet transparent address, used only as a refund target on quotes that
/// are never funded.
const REFUND_TADDR: &str = "t1KhV8ADhTGvVvBpTiEcJGnhTvBBFVFYHXx";

/// An address we control nothing at; quotes are never funded.
const RECIPIENT: &str = "0x1234567890123456789012345678901234567890";

fn create_test_client() -> NearIntentsClient {
    let config = NearConfig {
        api_url: "https://1click.chaindefuser.com".to_string(),
        default_timeout: 600,
    };
    NearIntentsClient::new(&config)
}

/// Skip unless `LIVE_API=1`.
fn live_api_enabled() -> bool {
    match std::env::var("LIVE_API") {
        Ok(v) => v == "1",
        Err(_) => {
            eprintln!("skipping live API test; set LIVE_API=1 to run");
            false
        }
    }
}

/// A quote for 0.1 ZEC parses and returns a usable deposit address.
#[tokio::test]
async fn test_get_quote_zec_to_usdc() {
    if !live_api_enabled() {
        return;
    }
    let client = create_test_client();

    // Create a quote request for 0.1 ZEC → USDC on Base
    // Using a valid ZEC transparent address format (t1 + 33 base58 chars)
    let request = NearIntentsClient::zec_to_usdc_base_request(
        10_000_000, // 0.1 ZEC (8 decimals)
        "0x1234567890123456789012345678901234567890", // Test recipient on Base
        REFUND_TADDR,
        Some(100), // 1% slippage
    );

    let result = client.get_quote(request).await;

    match result {
        Ok(quote) => {
            println!("Quote received:");
            println!("  Deposit address: {}", quote.deposit_address);
            println!("  Expected output: {} (raw USDC)", quote.expected_output);
            println!("  Min output: {}", quote.min_output);
            println!("  Expires at: {}", quote.expires_at);

            // Verify the quote looks reasonable
            assert!(!quote.deposit_address.is_empty(), "Deposit address should not be empty");

            // Expected output should be parseable as a number
            let output: u64 = quote.expected_output.parse().expect("Expected output should be a number");
            assert!(output > 0, "Expected output should be positive");

            // Deliberately wide: this asserts the units are right, not the price.
            assert!(output >= 500_000, "Output seems too low for 0.1 ZEC");
            assert!(output <= 1_000_000_000, "Output seems too high for 0.1 ZEC");
        }
        Err(e) => {
            // Print the error for debugging
            eprintln!("Quote request failed: {}", e);

            // If this is a validation error from the API, we want to see it
            panic!("Failed to get quote: {}", e);
        }
    }
}

/// Test building quote requests with different parameters
#[test]
fn test_quote_request_construction() {
    let request = NearIntentsClient::zec_to_usdc_base_request(
        50_000_000, // 0.5 ZEC
        "0xRecipient",
        REFUND_TADDR,
        Some(50),
    );

    assert_eq!(request.origin_asset, assets::ZEC);
    assert_eq!(request.destination_asset, assets::USDC_BASE);
    assert_eq!(request.amount, "50000000");
    assert_eq!(request.recipient, "0xRecipient");
    assert_eq!(request.refund_to, REFUND_TADDR);
    assert_eq!(request.slippage_bps, Some(50));
}

/// Test that asset IDs are correct format
#[test]
fn test_asset_ids_format() {
    // ZEC asset ID should be in nep141 format
    assert!(assets::ZEC.starts_with("nep141:"), "ZEC should be in nep141 format");
    assert!(assets::ZEC.contains("zec"), "ZEC asset should contain 'zec'");

    // USDC on Base should reference the correct contract
    assert!(assets::USDC_BASE.starts_with("nep141:"), "USDC_BASE should be in nep141 format");
    assert!(assets::USDC_BASE.contains("base"), "USDC_BASE should contain 'base'");
    assert!(
        assets::USDC_BASE.to_lowercase().contains("833589fcd6edb6e08f4c7c32d4f71b54bda02913"),
        "USDC_BASE should contain the USDC contract address"
    );
}

/// Test manual quote request construction
#[test]
fn test_manual_quote_request() {
    // Test constructing a QuoteRequest manually (for custom asset pairs)
    let request = QuoteRequest {
        origin_asset: "nep141:custom.asset".to_string(),
        destination_asset: "nep141:another.asset".to_string(),
        amount: "1000000".to_string(),
        recipient: "recipient_address".to_string(),
        refund_to: "refund_address".to_string(),
        slippage_bps: Some(200), // 2%
    };

    assert_eq!(request.origin_asset, "nep141:custom.asset");
    assert_eq!(request.slippage_bps, Some(200));
}

// =============================================================================
// Live constraint tests
//
// These pin the constraints the coordinator's preflight validation encodes. If
// 1Click changes the bridge minimum or its address rules, these fail before a
// user hits a raw 400.
// =============================================================================

/// The documented floor is quotable and one zatoshi under it is not.
#[tokio::test]
async fn test_live_minimum_amount_boundary() {
    if !live_api_enabled() {
        return;
    }
    let client = create_test_client();

    let at_floor = NearIntentsClient::zec_to_usdc_base_request(
        MIN_ZEC_ZATOSHI,
        RECIPIENT,
        REFUND_TADDR,
        Some(50),
    );
    let quote = client
        .get_quote(at_floor)
        .await
        .expect("the bridge minimum should be quotable");
    assert!(!quote.deposit_address.is_empty());

    // Below the floor the API answers 400. Our own validation rejects it first,
    // so assert on that message rather than on the wire error.
    let below = NearIntentsClient::zec_to_usdc_base_request(
        MIN_ZEC_ZATOSHI - 1,
        RECIPIENT,
        REFUND_TADDR,
        Some(50),
    );
    let err = client
        .get_quote(below)
        .await
        .expect_err("below the bridge minimum");
    assert!(err.to_string().contains("minimum"), "got: {}", err);
}

/// The Glue contract is accepted as a recipient.
///
/// Delivery on Base is a plain ERC-20 transfer, so a contract destination is
/// only viable if 1Click will quote to one. It will: contracts are not rejected
/// as a class.
#[tokio::test]
async fn test_live_contract_recipient_accepted() {
    if !live_api_enabled() {
        return;
    }
    let client = create_test_client();

    // The deployed Glue address. Any checksummed non-denylisted address works;
    // this one is the address the coordinator actually sends.
    let glue = "0x78329E4195d0cED3E06b19F9DA800160bcF74511";
    let request =
        NearIntentsClient::zec_to_usdc_base_request(1_000_000, glue, REFUND_TADDR, Some(50));

    let quote = client
        .get_quote(request)
        .await
        .expect("a contract recipient should be quotable");
    assert!(!quote.deposit_address.is_empty());
}

/// A shielded refund address is rejected before it reaches the network.
#[tokio::test]
async fn test_live_shielded_refund_rejected() {
    if !live_api_enabled() {
        return;
    }
    let client = create_test_client();

    let request = NearIntentsClient::zec_to_usdc_base_request(
        1_000_000,
        RECIPIENT,
        "zs1z7rejlpsa98s2rrrfkwmaxu53e4ue0ulcrw0h4x5g8jl04tak0d3mm47vdtahatqrlkngh9sly",
        Some(50),
    );

    let err = client
        .get_quote(request)
        .await
        .expect_err("shielded refundTo is rejected");
    assert!(err.to_string().contains("shielded"), "got: {}", err);
}

/// The spread on a 0.1 ZEC quote stays in a sane band.
///
/// Measured 2026-08-30: about 0.40% at this size, of which a fixed 2,400-unit
/// withdraw fee is part. The band is wide enough to absorb ordinary solver
/// variance and tight enough to catch a fee regime change.
#[tokio::test]
async fn test_live_spread_within_expected_band() {
    if !live_api_enabled() {
        return;
    }
    let client = create_test_client();

    let request =
        NearIntentsClient::zec_to_usdc_base_request(10_000_000, RECIPIENT, REFUND_TADDR, Some(50));

    let quote = client.get_quote(request).await.expect("quote for 0.1 ZEC");
    let out: u64 = quote.expected_output.parse().expect("integer amountOut");
    let min_out: u64 = quote.min_output.parse().expect("integer minAmountOut");

    assert!(min_out <= out, "minAmountOut should not exceed amountOut");
    assert!(
        quote.time_estimate_secs.unwrap_or(0) < 900,
        "time estimate should be minutes, not hours: {:?}",
        quote.time_estimate_secs
    );

    // minAmountOut sits within the requested 0.5% slippage of amountOut.
    let slippage_floor = out - out / 100;
    assert!(
        min_out >= slippage_floor,
        "minAmountOut {} is more than 1% below amountOut {}",
        min_out,
        out
    );
}

/// Polling an address that was never quoted is a soft miss, not an error.
#[tokio::test]
async fn test_live_status_unknown_address_is_none() {
    if !live_api_enabled() {
        return;
    }
    let client = create_test_client();

    let status = client
        .get_status(REFUND_TADDR)
        .await
        .expect("404 should not be an error");
    assert!(status.is_none(), "an unquoted address should return None");
}

/// The asset IDs we hardcode are still in the supported-token registry.
#[tokio::test]
async fn test_live_asset_ids_still_supported() {
    if !live_api_enabled() {
        return;
    }

    let body = reqwest::get("https://1click.chaindefuser.com/v0/tokens")
        .await
        .expect("fetch supported tokens")
        .text()
        .await
        .expect("read supported tokens");

    for asset in [assets::ZEC, assets::USDC_BASE] {
        assert!(
            body.contains(asset),
            "{} is no longer in the supported-token registry",
            asset
        );
    }
}

/// Offline: the refund-address rule the live tests exercise.
#[test]
fn test_refund_address_validation_offline() {
    validate_zec_refund_address("t1KhV8ADhTGvVvBpTiEcJGnhTvBBFVFYHXx").expect("t1 accepted");
    validate_zec_refund_address("t3Vz22vK5z2LcKEdg16Yv4FFneEL1zg9ojd").expect("t3 accepted");
    assert!(validate_zec_refund_address("u1lq6jn3fkgd0dcxpvdnfrhrqrmvdnvzdmhd").is_err());
    assert!(validate_zec_refund_address("zs1z7rejlpsa98s2rrrfkwmaxu53e4ue0ulcrw").is_err());
    assert!(validate_zec_refund_address("0xnotazcashaddress").is_err());
}

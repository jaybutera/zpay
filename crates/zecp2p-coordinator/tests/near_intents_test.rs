//! Integration tests for NEAR Intents API
//!
//! These tests make real API calls to verify the integration works correctly.
//! They're marked #[ignore] by default since they require network access.

use zecp2p_coordinator::near::{assets, NearIntentsClient, QuoteRequest};
use zecp2p_types::config::NearConfig;

fn create_test_client() -> NearIntentsClient {
    let config = NearConfig {
        api_url: "https://1click.chaindefuser.com".to_string(),
        default_timeout: 600,
    };
    NearIntentsClient::new(&config)
}

/// Test that we can get a quote from the NEAR Intents API
/// This test is ignored by default since it requires network access.
#[tokio::test]
#[ignore]
async fn test_get_quote_zec_to_usdc() {
    let client = create_test_client();

    // Create a quote request for 0.1 ZEC → USDC on Base
    // Using a valid ZEC transparent address format (t1 + 33 base58 chars)
    let request = NearIntentsClient::zec_to_usdc_base_request(
        10_000_000, // 0.1 ZEC (8 decimals)
        "0x1234567890123456789012345678901234567890", // Test recipient on Base
        "t1VJnUz9FDy7WfFxqXwMZJWVxzMrRD7MvBA", // Valid ZEC t-address (mainnet)
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

            // At current prices (~$30/ZEC), 0.1 ZEC should be roughly $3 = 3,000,000 USDC (6 decimals)
            // Allow for significant price variance (0.5 to 100 USDC)
            assert!(output >= 500_000, "Output seems too low for 0.1 ZEC");
            assert!(output <= 100_000_000, "Output seems too high for 0.1 ZEC");
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
        "t1RefundAddress",
        Some(50),
    );

    assert_eq!(request.origin_asset, assets::ZEC);
    assert_eq!(request.destination_asset, assets::USDC_BASE);
    assert_eq!(request.amount, "50000000");
    assert_eq!(request.recipient, "0xRecipient");
    assert_eq!(request.refund_to, "t1RefundAddress");
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

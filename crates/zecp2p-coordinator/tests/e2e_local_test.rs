//! End-to-end local testing with anvil and real contracts
//!
//! This test:
//! 1. Starts an anvil instance
//! 2. Deploys MockUSDC, MockEscrow, and OfframpGlue contracts using forge script
//! 3. Tests the full offramp flow: create session -> mint USDC -> process offramp
//! 4. Verifies the state machine transitions correctly
//!
//! Run with: cargo test --package zecp2p-coordinator --test e2e_local_test -- --ignored --nocapture

mod test_utils;

use alloy::primitives::{Address, Bytes, B256, U256};
use test_utils::{
    deploy_contracts, get_signing_provider, AnvilInstance, ANVIL_PRIVATE_KEY, TEST_USER,
    TEST_USER_PRIVATE_KEY,
};
use zecp2p_types::abi::{usd_currency_code, venmo_payment_method, MockUSDC, OfframpGlue};

#[tokio::test]
#[ignore = "requires anvil and forge to be installed"]
async fn test_full_offramp_flow_local() {
    // Start anvil
    let anvil = AnvilInstance::start();
    let rpc_url = anvil.rpc_url();

    println!("Anvil started at {}", rpc_url);

    // Deploy contracts
    let (usdc_addr, _escrow_addr, glue_addr) = deploy_contracts(rpc_url);

    println!("Contracts deployed:");
    println!("  MockUSDC: {}", usdc_addr);
    println!("  MockEscrow: {}", _escrow_addr);
    println!("  OfframpGlue: {}", glue_addr);

    // Get provider with owner wallet (anvil account[0])
    let provider = get_signing_provider(rpc_url, ANVIL_PRIVATE_KEY).await;

    // Initialize contracts
    let glue = OfframpGlue::new(glue_addr, &provider);
    let usdc = MockUSDC::new(usdc_addr, &provider);

    // Test data
    let session_id = B256::from([1u8; 32]);
    let user: Address = TEST_USER.parse().unwrap();
    let venmo_hash = alloy::primitives::keccak256(b"testuser");
    let min_rate = U256::from(1_000_000_000_000_000_000u128); // 1e18 = 1:1 rate
    let expected_amount = U256::from(100_000_000u64); // 100 USDC (6 decimals)

    // ============ Step 1: Create Session ============
    println!("\n=== Step 1: Create Session ===");

    let tx = glue
        .createSession(session_id, user, venmo_hash, min_rate, expected_amount)
        .send()
        .await
        .expect("Failed to send createSession");

    let receipt = tx.get_receipt().await.expect("Failed to get receipt");
    println!("createSession tx: {:?}", receipt.transaction_hash);

    // Verify session was created
    let session = glue
        .getSession(session_id)
        .call()
        .await
        .expect("Failed to get session");

    assert_eq!(session.user, user);
    assert_eq!(session.payeeDetailsHash, venmo_hash);
    assert_eq!(session.minConversionRate, min_rate);
    assert_eq!(session.expectedAmount, expected_amount);
    assert_eq!(session.depositId, U256::ZERO);
    assert!(!session.fulfilled);
    assert!(!session.rescued);

    println!("Session created successfully");

    // ============ Step 2: Simulate USDC Arrival (like NEAR Intent delivery) ============
    println!("\n=== Step 2: Simulate USDC Arrival ===");

    // Mint USDC to the GlueContract (simulating NEAR Intent delivery)
    let tx = usdc
        .mint(glue_addr, expected_amount)
        .send()
        .await
        .expect("Failed to send mint");

    let receipt = tx.get_receipt().await.expect("Failed to get receipt");
    println!("mint tx: {:?}", receipt.transaction_hash);

    // Verify USDC balance
    let balance = glue
        .getContractUsdcBalance()
        .call()
        .await
        .expect("Failed to get balance");

    assert_eq!(balance, expected_amount);
    println!("GlueContract USDC balance: {}", balance);

    // ============ Step 3: Process Offramp (route to zk-p2p) ============
    println!("\n=== Step 3: Process Offramp ===");

    let payment_methods = vec![venmo_payment_method()];
    let payment_method_data = vec![OfframpGlue::DepositPaymentMethodData {
        intentGatingService: Address::ZERO,
        payeeDetails: venmo_hash,
        data: Bytes::new(),
    }];
    let currencies = vec![vec![OfframpGlue::Currency {
        code: usd_currency_code(),
        minConversionRate: min_rate,
    }]];

    let tx = glue
        .processOfframp(session_id, payment_methods, payment_method_data, currencies)
        .send()
        .await
        .expect("Failed to send processOfframp");

    let receipt = tx.get_receipt().await.expect("Failed to get receipt");
    println!("processOfframp tx: {:?}", receipt.transaction_hash);

    // Verify session was updated with depositId
    let session = glue
        .getSession(session_id)
        .call()
        .await
        .expect("Failed to get session");

    assert_ne!(session.depositId, U256::ZERO);
    println!("zk-p2p deposit ID: {}", session.depositId);

    // Verify GlueContract balance is now 0 (transferred to escrow)
    let balance = glue
        .getContractUsdcBalance()
        .call()
        .await
        .expect("Failed to get balance");

    assert_eq!(balance, U256::ZERO);
    println!("GlueContract USDC balance after process: {}", balance);

    println!("\n=== Full offramp flow completed successfully! ===");
}

#[tokio::test]
#[ignore = "requires anvil and forge to be installed"]
async fn test_rescue_flow_local() {
    // Start anvil
    let anvil = AnvilInstance::start();
    let rpc_url = anvil.rpc_url();

    println!("Anvil started at {}", rpc_url);

    // Deploy contracts
    let (usdc_addr, _escrow_addr, glue_addr) = deploy_contracts(rpc_url);

    // Get provider with owner wallet
    let owner_provider = get_signing_provider(rpc_url, ANVIL_PRIVATE_KEY).await;

    // Get provider with user wallet
    let user_provider = get_signing_provider(rpc_url, TEST_USER_PRIVATE_KEY).await;

    // Initialize contracts
    let glue_owner = OfframpGlue::new(glue_addr, &owner_provider);
    let glue_user = OfframpGlue::new(glue_addr, &user_provider);
    let usdc = MockUSDC::new(usdc_addr, &owner_provider);

    // Test data
    let session_id = B256::from([2u8; 32]);
    let user: Address = TEST_USER.parse().unwrap();
    let venmo_hash = alloy::primitives::keccak256(b"testuser");
    let min_rate = U256::from(1_000_000_000_000_000_000u128);
    let expected_amount = U256::from(50_000_000u64); // 50 USDC

    // Step 1: Create session
    glue_owner
        .createSession(session_id, user, venmo_hash, min_rate, expected_amount)
        .send()
        .await
        .expect("Failed to createSession")
        .get_receipt()
        .await
        .expect("Failed to get receipt");

    // Step 2: Mint USDC to GlueContract
    usdc.mint(glue_addr, expected_amount)
        .send()
        .await
        .expect("Failed to mint")
        .get_receipt()
        .await
        .expect("Failed to get receipt");

    // Step 3: User rescues the funds (before processOfframp)
    println!("\n=== Testing Rescue Flow ===");

    // Check user balance before rescue
    let user_balance_before = usdc
        .balanceOf(user)
        .call()
        .await
        .expect("Failed to get balance");
    println!("User USDC balance before rescue: {}", user_balance_before);

    // Rescue as user
    glue_user
        .rescue(session_id)
        .send()
        .await
        .expect("Failed to rescue")
        .get_receipt()
        .await
        .expect("Failed to get receipt");

    // Verify user received the USDC
    let user_balance_after = usdc
        .balanceOf(user)
        .call()
        .await
        .expect("Failed to get balance");
    println!("User USDC balance after rescue: {}", user_balance_after);

    assert_eq!(user_balance_after - user_balance_before, expected_amount);

    // Verify session is marked as rescued
    let session = glue_owner
        .getSession(session_id)
        .call()
        .await
        .expect("Failed to get session");
    assert!(session.rescued);

    println!("Rescue flow completed successfully!");
}

#[tokio::test]
#[ignore = "requires anvil and forge to be installed"]
async fn test_withdraw_from_zkp2p_flow_local() {
    // Start anvil
    let anvil = AnvilInstance::start();
    let rpc_url = anvil.rpc_url();

    println!("Anvil started at {}", rpc_url);

    // Deploy contracts
    let (usdc_addr, _escrow_addr, glue_addr) = deploy_contracts(rpc_url);

    // Get providers
    let owner_provider = get_signing_provider(rpc_url, ANVIL_PRIVATE_KEY).await;
    let user_provider = get_signing_provider(rpc_url, TEST_USER_PRIVATE_KEY).await;

    // Initialize contracts
    let glue_owner = OfframpGlue::new(glue_addr, &owner_provider);
    let glue_user = OfframpGlue::new(glue_addr, &user_provider);
    let usdc_owner = MockUSDC::new(usdc_addr, &owner_provider);
    let usdc_user = MockUSDC::new(usdc_addr, &user_provider);

    // Test data
    let session_id = B256::from([3u8; 32]);
    let user: Address = TEST_USER.parse().unwrap();
    let venmo_hash = alloy::primitives::keccak256(b"testuser");
    let min_rate = U256::from(1_000_000_000_000_000_000u128);
    let expected_amount = U256::from(75_000_000u64); // 75 USDC

    // Step 1: Create session
    glue_owner
        .createSession(session_id, user, venmo_hash, min_rate, expected_amount)
        .send()
        .await
        .expect("Failed to createSession")
        .get_receipt()
        .await
        .expect("Failed to get receipt");

    // Step 2: Mint USDC to GlueContract
    usdc_owner
        .mint(glue_addr, expected_amount)
        .send()
        .await
        .expect("Failed to mint")
        .get_receipt()
        .await
        .expect("Failed to get receipt");

    // Step 3: Process offramp (move to zk-p2p escrow)
    let payment_methods = vec![venmo_payment_method()];
    let payment_method_data = vec![OfframpGlue::DepositPaymentMethodData {
        intentGatingService: Address::ZERO,
        payeeDetails: venmo_hash,
        data: Bytes::new(),
    }];
    let currencies = vec![vec![OfframpGlue::Currency {
        code: usd_currency_code(),
        minConversionRate: min_rate,
    }]];

    glue_owner
        .processOfframp(session_id, payment_methods, payment_method_data, currencies)
        .send()
        .await
        .expect("Failed to processOfframp")
        .get_receipt()
        .await
        .expect("Failed to get receipt");

    // Step 4: User withdraws from zk-p2p (simulating no taker scenario)
    println!("\n=== Testing Withdraw from zk-p2p Flow ===");

    let user_balance_before = usdc_user
        .balanceOf(user)
        .call()
        .await
        .expect("Failed to get balance");
    println!(
        "User USDC balance before withdraw: {}",
        user_balance_before
    );

    // Withdraw as user
    glue_user
        .withdrawFromZkp2p(session_id, expected_amount)
        .send()
        .await
        .expect("Failed to withdraw")
        .get_receipt()
        .await
        .expect("Failed to get receipt");

    // Verify user received the USDC
    let user_balance_after = usdc_user
        .balanceOf(user)
        .call()
        .await
        .expect("Failed to get balance");
    println!("User USDC balance after withdraw: {}", user_balance_after);

    assert_eq!(user_balance_after - user_balance_before, expected_amount);

    println!("Withdraw from zk-p2p flow completed successfully!");
}

#[tokio::test]
#[ignore = "requires anvil and forge to be installed"]
async fn test_session_cannot_process_twice() {
    // Start anvil
    let anvil = AnvilInstance::start();
    let rpc_url = anvil.rpc_url();

    // Deploy contracts
    let (usdc_addr, _, glue_addr) = deploy_contracts(rpc_url);

    let provider = get_signing_provider(rpc_url, ANVIL_PRIVATE_KEY).await;
    let glue = OfframpGlue::new(glue_addr, &provider);
    let usdc = MockUSDC::new(usdc_addr, &provider);

    let session_id = B256::from([4u8; 32]);
    let user: Address = TEST_USER.parse().unwrap();
    let venmo_hash = alloy::primitives::keccak256(b"testuser");
    let min_rate = U256::from(1_000_000_000_000_000_000u128);
    let expected_amount = U256::from(100_000_000u64);

    // Create session
    glue.createSession(session_id, user, venmo_hash, min_rate, expected_amount)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    // Mint USDC
    usdc.mint(glue_addr, expected_amount)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    // Process offramp
    let payment_methods = vec![venmo_payment_method()];
    let payment_method_data = vec![OfframpGlue::DepositPaymentMethodData {
        intentGatingService: Address::ZERO,
        payeeDetails: venmo_hash,
        data: Bytes::new(),
    }];
    let currencies = vec![vec![OfframpGlue::Currency {
        code: usd_currency_code(),
        minConversionRate: min_rate,
    }]];

    glue.processOfframp(
        session_id,
        payment_methods.clone(),
        payment_method_data.clone(),
        currencies.clone(),
    )
    .send()
    .await
    .unwrap()
    .get_receipt()
    .await
    .unwrap();

    // Try to process again - should fail
    usdc.mint(glue_addr, expected_amount)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    let result = glue
        .processOfframp(session_id, payment_methods, payment_method_data, currencies)
        .send()
        .await;

    assert!(result.is_err(), "Should not be able to process twice");
    println!("Correctly prevented double processing");
}

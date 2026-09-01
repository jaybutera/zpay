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
use zecp2p_types::abi::{usd_currency_code, venmo_payment_method, MockUSDC, OfframpGlue, fixed_rate_currency};

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
    assert!(!session.processed);
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

    // The keeper assigns the arrived USDC to this session. Nothing is spendable
    // until it does: the glue accounts per session, so a bare transfer is
    // unassigned balance that no session owns.
    glue
        .creditSession(session_id, expected_amount)
        .send()
        .await
        .expect("Failed to creditSession")
        .get_receipt()
        .await
        .expect("Failed to get receipt");

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
    let currencies = vec![vec![fixed_rate_currency(usd_currency_code(), min_rate)]];

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

    // EscrowV2-style ids start at 0, so `processed` is the flag, not a non-zero id
    assert!(session.processed);
    assert_eq!(session.depositId, U256::ZERO);
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

    // The keeper assigns the arrived USDC to this session. Nothing is spendable
    // until it does: the glue accounts per session, so a bare transfer is
    // unassigned balance that no session owns.
    glue_owner
        .creditSession(session_id, expected_amount)
        .send()
        .await
        .expect("Failed to creditSession")
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

    // The keeper assigns the arrived USDC to this session. Nothing is spendable
    // until it does: the glue accounts per session, so a bare transfer is
    // unassigned balance that no session owns.
    glue_owner
        .creditSession(session_id, expected_amount)
        .send()
        .await
        .expect("Failed to creditSession")
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
    let currencies = vec![vec![fixed_rate_currency(usd_currency_code(), min_rate)]];

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
        .withdrawFromZkp2p(session_id)
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

    glue
        .creditSession(session_id, expected_amount)
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
    let currencies = vec![vec![fixed_rate_currency(usd_currency_code(), min_rate)]];

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

/// HIGH-1, against real deployed bytecode: the user recovers their own funds
/// with their own key, with the keeper doing nothing.
///
/// This is the test the old harness could not have failed, because it signed
/// the user's rescue with the coordinator's key. Here the three roles are three
/// different Anvil accounts, and the keeper's key is never used after the
/// session is set up. If the contract still required msg.sender == session.user
/// while the coordinator sent with the keeper key, the keeper leg below would
/// revert and the user leg would be the only thing that worked; both are
/// asserted explicitly.
#[tokio::test]
#[ignore = "requires anvil and forge to be installed"]
async fn test_user_escape_hatch_without_the_keeper() {
    let anvil = AnvilInstance::start();
    let rpc_url = anvil.rpc_url();

    let (usdc_addr, _escrow_addr, glue_addr) = deploy_contracts(rpc_url);

    // Three distinct roles.
    let owner_provider = get_signing_provider(rpc_url, ANVIL_PRIVATE_KEY).await;
    let keeper_provider = get_signing_provider(rpc_url, test_utils::KEEPER_PRIVATE_KEY).await;
    let user_provider = get_signing_provider(rpc_url, TEST_USER_PRIVATE_KEY).await;

    let glue_keeper = OfframpGlue::new(glue_addr, &keeper_provider);
    let glue_user = OfframpGlue::new(glue_addr, &user_provider);
    let usdc = MockUSDC::new(usdc_addr, &owner_provider);

    let user: Address = TEST_USER.parse().unwrap();
    let keeper: Address = test_utils::KEEPER_ADDRESS.parse().unwrap();

    // The deploy really did separate them.
    let on_chain_keeper = glue_keeper.keeper().call().await.expect("read keeper");
    assert_eq!(on_chain_keeper, keeper, "DeployLocal must set a distinct keeper");
    assert_ne!(on_chain_keeper, user, "keeper must not be the user");

    let session_id = B256::from([9u8; 32]);
    let venmo_hash = alloy::primitives::keccak256(b"escapehatch");
    let min_rate = U256::from(1_000_000_000_000_000_000u128);
    let amount = U256::from(25_000_000u64); // 25 USDC

    // Keeper sets the session up and credits the delivery.
    glue_keeper
        .createSession(session_id, user, venmo_hash, min_rate, amount)
        .send()
        .await
        .expect("createSession as keeper")
        .get_receipt()
        .await
        .expect("receipt");

    usdc.mint(glue_addr, amount)
        .send()
        .await
        .expect("mint")
        .get_receipt()
        .await
        .expect("receipt");

    glue_keeper
        .creditSession(session_id, amount)
        .send()
        .await
        .expect("creditSession as keeper")
        .get_receipt()
        .await
        .expect("receipt");

    // From here the keeper is out of the picture: the user signs for themselves.
    let before = usdc.balanceOf(user).call().await.expect("balance");

    glue_user
        .rescue(session_id)
        .send()
        .await
        .expect("the user must be able to rescue with their own key")
        .get_receipt()
        .await
        .expect("receipt");

    let after = usdc.balanceOf(user).call().await.expect("balance");
    assert_eq!(after - before, amount, "the user got their own USDC back");

    let session = glue_user.getSession(session_id).call().await.expect("session");
    assert!(session.rescued);
    assert_eq!(session.credited, U256::ZERO);

    println!("User recovered {amount} USDC units with no keeper transaction.");
}

/// The other half of HIGH-1: the coordinator's keeper-signed rescue has to work
/// too, since that is the path `POST /offramp/{id}/rescue` takes. It used to
/// revert on mainnet for exactly the reason the user's path did not exist.
#[tokio::test]
#[ignore = "requires anvil and forge to be installed"]
async fn test_keeper_signed_rescue_pays_the_user() {
    let anvil = AnvilInstance::start();
    let rpc_url = anvil.rpc_url();

    let (usdc_addr, _escrow_addr, glue_addr) = deploy_contracts(rpc_url);

    let owner_provider = get_signing_provider(rpc_url, ANVIL_PRIVATE_KEY).await;
    let keeper_provider = get_signing_provider(rpc_url, test_utils::KEEPER_PRIVATE_KEY).await;

    let glue_keeper = OfframpGlue::new(glue_addr, &keeper_provider);
    let usdc = MockUSDC::new(usdc_addr, &owner_provider);

    let user: Address = TEST_USER.parse().unwrap();
    let keeper: Address = test_utils::KEEPER_ADDRESS.parse().unwrap();

    let session_id = B256::from([10u8; 32]);
    let amount = U256::from(12_000_000u64);

    glue_keeper
        .createSession(
            session_id,
            user,
            alloy::primitives::keccak256(b"keeperrescue"),
            U256::from(1_000_000_000_000_000_000u128),
            amount,
        )
        .send()
        .await
        .expect("createSession")
        .get_receipt()
        .await
        .expect("receipt");

    usdc.mint(glue_addr, amount)
        .send()
        .await
        .expect("mint")
        .get_receipt()
        .await
        .expect("receipt");

    glue_keeper
        .creditSession(session_id, amount)
        .send()
        .await
        .expect("creditSession")
        .get_receipt()
        .await
        .expect("receipt");

    let user_before = usdc.balanceOf(user).call().await.expect("balance");
    let keeper_before = usdc.balanceOf(keeper).call().await.expect("balance");

    // The keeper sends it, exactly as the coordinator does.
    glue_keeper
        .rescue(session_id)
        .send()
        .await
        .expect("keeper-signed rescue must not revert")
        .get_receipt()
        .await
        .expect("receipt");

    let user_after = usdc.balanceOf(user).call().await.expect("balance");
    let keeper_after = usdc.balanceOf(keeper).call().await.expect("balance");

    assert_eq!(user_after - user_before, amount, "the user is paid");
    assert_eq!(keeper_after, keeper_before, "the keeper takes nothing");
}

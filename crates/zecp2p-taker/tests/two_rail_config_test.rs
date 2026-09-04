//! The second settlement rail is opt-in, and its endpoints get the same
//! treatment as the first's.
//!
//! Both systems run live at once. That makes two things worth testing at the
//! config boundary rather than after a daemon has started:
//!
//! - a config written for the Base-only daemon must keep loading, with the
//!   second rail off. Anything else means the deployed route breaks on the day
//!   the native escrow ships, which is the one outcome this work must not have.
//! - a rail that reads a Zcash node over plaintext is a rail whose depth,
//!   branch id and escrow output are all answers an attacker can write, and the
//!   LP pays fiat on the strength of them.

use std::io::Write;

use zecp2p_taker::TakerConfig;

/// The config the deployed Base daemon runs today: no `[zec]` section at all.
const BASE_ONLY: &str = r#"
[network]
base_rpc_url = "https://mainnet.base.org"
chain_id = 8453

[contracts]
usdc = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
zkp2p_escrow = "0x777777779d229cdF3110e9de47943791c26300Ef"
zkp2p_orchestrator = "0x014025fDE093f8701d86e9f38e2C3a9b779cb5c7"
glue_contract = "0x0000000000000000000000000000000000000001"

[taker]
max_intent_amount = "100000000"
min_intent_amount = "1000000"

[zkp2p]
api_url = "https://api.zkp2p.xyz"
"#;

/// The same config with the native escrow rail turned on.
const BOTH_RAILS: &str = r#"
[network]
base_rpc_url = "https://mainnet.base.org"
chain_id = 8453

[contracts]
usdc = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
zkp2p_escrow = "0x777777779d229cdF3110e9de47943791c26300Ef"
zkp2p_orchestrator = "0x014025fDE093f8701d86e9f38e2C3a9b779cb5c7"
glue_contract = "0x0000000000000000000000000000000000000001"

[taker]
max_intent_amount = "100000000"
min_intent_amount = "1000000"

[zkp2p]
api_url = "https://api.zkp2p.xyz"

[zec]
rpc_url = "https://zec.rpc.example"
network = "main"
attestor_url = "https://attestor.example"
attestor_pubkey = "02aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
"#;

fn write_config(body: &str) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().expect("temp config");
    file.write_all(body.as_bytes()).expect("write config");
    file.flush().expect("flush");
    file
}

fn load(body: &str) -> anyhow::Result<TakerConfig> {
    let file = write_config(body);
    TakerConfig::load(file.path().to_str().unwrap())
}

/// The property the whole change rests on: the deployed route is untouched.
#[test]
fn a_config_from_before_the_second_rail_still_loads_with_it_off() {
    let config = load(BASE_ONLY).expect("the Base-only config must keep loading");
    assert!(
        config.zec.is_none(),
        "a silent config must not switch on a second settlement system"
    );
    // And the Base side is unchanged.
    assert_eq!(config.network.chain_id, 8453);
    assert!(config.taker.max_payment_cents > 0);
}

/// The shipped example is a Base-only config, and it must stay loadable for the
/// same reason.
#[test]
fn the_shipped_example_config_leaves_the_second_rail_off() {
    let config = TakerConfig::load("../../config.taker.example.toml")
        .expect("the shipped example must load");
    assert!(config.zec.is_none());
}

#[test]
fn both_rails_configured_together_load() {
    let config = load(BOTH_RAILS).expect("both rails must load");
    let zec = config.zec.expect("the zec rail is configured");
    assert_eq!(zec.network().unwrap(), zecp2p_escrow::rpc::Network::Main);
    // The deadlines are derived from wall-clock hours, not hard-coded blocks.
    let policy = zec.policy().unwrap();
    assert_eq!(policy.refund_delay_blocks, (24 * 3600) / 75);
    assert!(policy.pay_deadline_blocks > policy.broadcast_deadline_blocks);
}

/// The cap is the operator's ceiling on any single Venmo payment, and it does
/// not care which chain settles it. One value, both rails.
#[test]
fn one_payment_cap_governs_both_rails() {
    let config = load(BOTH_RAILS).unwrap();
    assert_eq!(
        config.taker.max_payment_cents, 2_500,
        "the default cap must still apply when the second rail is on"
    );
}

/// A plaintext Zcash RPC is the escrow rail's version of the `ZKP2P_API_URL`
/// hole: the LP pays real fiat on the strength of what that endpoint says about
/// depth and branch id, and over plaintext anyone on the path says it.
#[test]
fn a_plaintext_zcash_rpc_is_refused() {
    let err = load(&BOTH_RAILS.replace(
        r#"rpc_url = "https://zec.rpc.example""#,
        r#"rpc_url = "http://zec.rpc.attacker.example""#,
    ))
    .expect_err("must refuse");
    let msg = format!("{err:#}");
    assert!(msg.contains("zec.rpc_url"), "{msg}");
}

#[test]
fn a_plaintext_attestor_url_is_refused() {
    let err = load(&BOTH_RAILS.replace(
        r#"attestor_url = "https://attestor.example""#,
        r#"attestor_url = "http://attestor.attacker.example""#,
    ))
    .expect_err("must refuse");
    assert!(format!("{err:#}").contains("zec.attestor_url"));
}

/// Loopback stays allowed, because that is how the regtest run and the local
/// attestor are addressed.
#[test]
fn loopback_is_allowed_on_the_escrow_rail_too() {
    let config = load(&BOTH_RAILS
        .replace(
            r#"rpc_url = "https://zec.rpc.example""#,
            r#"rpc_url = "http://127.0.0.1:18232""#,
        )
        .replace(
            r#"attestor_url = "https://attestor.example""#,
            r#"attestor_url = "http://127.0.0.1:8480""#,
        )
        .replace(r#"network = "main""#, r#"network = "test""#))
        .expect("a local regtest rail must load");
    assert_eq!(
        config.zec.unwrap().network().unwrap(),
        zecp2p_escrow::rpc::Network::Test
    );
}

/// An unpinned attestor on mainnet is refused at load, which is earlier than
/// `paid_path`'s own refusal. A daemon that starts watching mainnet unpinned
/// has already taken on work it cannot safely finish.
#[test]
fn a_mainnet_rail_without_a_pinned_attestor_is_refused() {
    let err = load(&BOTH_RAILS
        .lines()
        .filter(|l| !l.starts_with("attestor_pubkey"))
        .collect::<Vec<_>>()
        .join("\n"))
    .expect_err("must refuse");
    let msg = format!("{err:#}");
    assert!(msg.contains("attestor_pubkey"), "{msg}");
    assert!(msg.contains("decrypted"), "{msg}");
}

/// Testnet may run unpinned, which is what the regtest runs did.
#[test]
fn a_testnet_rail_may_run_unpinned() {
    let body = BOTH_RAILS
        .lines()
        .filter(|l| !l.starts_with("attestor_pubkey"))
        .collect::<Vec<_>>()
        .join("\n")
        .replace(r#"network = "main""#, r#"network = "test""#);
    load(&body).expect("a testnet rail without a pin must load");
}

/// A network this build does not know must fail rather than pick one. Guessing
/// between mainnet and testnet picks between real coin and none.
#[test]
fn an_unknown_network_is_refused_rather_than_guessed() {
    let err = load(&BOTH_RAILS.replace(r#"network = "main""#, r#"network = "regtest""#))
        .expect_err("must refuse");
    let msg = format!("{err:#}");
    assert!(msg.contains("main"), "{msg}");
    assert!(msg.contains("test"), "{msg}");
}

/// The deadlines are wall-clock derived, so a chain whose block time changes
/// keeps the same real-world refund window. NU7 proposes 25 s.
#[test]
fn the_refund_window_survives_a_block_time_change() {
    let at_75 = load(BOTH_RAILS).unwrap().zec.unwrap().policy().unwrap();
    let at_25 = load(&BOTH_RAILS.replace(
        r#"network = "main""#,
        "network = \"main\"\nblock_seconds = 25",
    ))
    .unwrap()
    .zec
    .unwrap()
    .policy()
    .unwrap();

    // Three times the blocks for the same 24 hours.
    assert_eq!(at_25.refund_delay_blocks, at_75.refund_delay_blocks * 3);
    assert_eq!(
        at_25.refund_delay_blocks * at_25.block_seconds,
        at_75.refund_delay_blocks * at_75.block_seconds,
        "the wall-clock window must not move when the block time does"
    );
}

//! NEW-4: the taker binary applied env URL overrides with no scheme check.
//!
//! MEDIUM-3's fix added `zecp2p_types::Config::validate_urls` and wired it into
//! the coordinator's `load_with_env`. `TakerConfig::load` is a separate
//! implementation that called nothing, so `BASE_RPC_URL`, `ATTESTATION_URL` and
//! `ZKP2P_API_URL` went straight into the config from the environment, and
//! `dotenvy::dotenv()` runs unconditionally.
//!
//! `ZKP2P_API_URL` is the one that matters. NEW-2's payee cross-check asks that
//! endpoint what a username hashes to and refuses to pay unless it matches the
//! deposit. Over plaintext, anyone on the path answers with a hash of their own
//! choosing, the comparison passes, and the taker sends its own dollars to the
//! attacker's Venmo handle. The URL the earlier fix hardened was guarded; the
//! URL that fix's correctness rests on was not.
//!
//! These tests drive `TakerConfig::load` on a real file, because the gap was
//! between the file and the loader rather than in the validator.

use std::io::Write;

use zecp2p_taker::TakerConfig;

/// Env vars are process-global, so these tests take a lock rather than running
/// in parallel and clobbering each other.
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

const GOOD_CONFIG: &str = r#"
[network]
base_rpc_url = "https://mainnet.base.org"
chain_id = 8453

[contracts]
usdc = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
zkp2p_escrow = "0x777777779d229cdF3110e9de47943791c26300Ef"
zkp2p_orchestrator = "0x014025fDE093f8701d86e9f38e2C3a9b779cb5c7"
glue_contract = "0x0000000000000000000000000000000000000001"

[taker]
coordinator_url = "https://coordinator.example"
max_intent_amount = "100000000"
min_intent_amount = "1000000"

[zkp2p]
api_url = "https://api.zkp2p.xyz"
"#;

fn write_config(body: &str) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().expect("temp config");
    file.write_all(body.as_bytes()).expect("write config");
    file.flush().expect("flush");
    file
}

/// Run `f` with `vars` set, restoring whatever was there before.
fn with_env<T>(vars: &[(&str, Option<&str>)], f: impl FnOnce() -> T) -> T {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    // Every variable TakerConfig::load reads, so a stray one in the developer's
    // own environment cannot decide the result.
    const ALL: &[&str] = &[
        "BASE_RPC_URL",
        "GLUE_CONTRACT_ADDRESS",
        "VENMO_CDP_URL",
        "ATTESTATION_URL",
        "ZKP2P_API_URL",
        "COORDINATOR_TAKER_TOKEN",
        "ATTESTATION_VERIFIER_ADDRESS",
        "STAKE_VAULT_ADDRESS",
    ];

    let saved: Vec<(&str, Option<String>)> =
        ALL.iter().map(|k| (*k, std::env::var(k).ok())).collect();
    for key in ALL {
        std::env::remove_var(key);
    }
    for (key, value) in vars {
        match value {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }

    let out = f();

    for (key, value) in saved {
        match value {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }
    out
}

#[test]
fn the_shipped_example_config_passes_its_own_check() {
    with_env(&[], || {
        let config = TakerConfig::load("../../config.taker.example.toml")
            .expect("the config we ship must satisfy the check we added");
        config.validate_urls().expect("and again on its own");
    });
}

/// The cap and the session settings are what stand between a bad rate and a
/// wrong payment, so the shipped config has to actually carry them rather than
/// silently falling back to a default nobody chose.
#[test]
fn the_shipped_config_sets_the_payment_cap_and_the_session_limits() {
    with_env(&[], || {
        let config = TakerConfig::load("../../config.taker.example.toml").expect("loads");
        assert_eq!(
            config.taker.max_payment_cents, 2_500,
            "the shipped cap must be small enough that a $5 daemon cannot send $500"
        );
        assert!(config.taker.max_payment_cents > 0);
        assert!(!config.taker.journal_path.is_empty());
        assert!(config.session.max_age_hours > 0);
        assert!(!config.session.path.is_empty());
    });
}

/// The defaults have to hold on a config that predates these fields, because an
/// operator upgrading the binary should not silently get an uncapped daemon.
#[test]
fn a_config_without_the_new_fields_still_gets_a_cap() {
    let file = write_config(GOOD_CONFIG);
    let config = with_env(&[], || {
        TakerConfig::load(file.path().to_str().unwrap()).expect("loads")
    });
    assert_eq!(config.taker.max_payment_cents, 2_500);
    assert_eq!(config.session.max_age_hours, 12);
}

#[test]
fn a_clean_config_loads() {
    let file = write_config(GOOD_CONFIG);
    with_env(&[], || {
        TakerConfig::load(file.path().to_str().unwrap()).expect("https everywhere loads");
    });
}

/// The finding itself. This is the override the payee cross-check depends on.
#[test]
fn a_plaintext_zkp2p_api_url_from_the_environment_is_refused() {
    let file = write_config(GOOD_CONFIG);
    with_env(&[("ZKP2P_API_URL", Some("http://curator.attacker.example"))], || {
        let err = TakerConfig::load(file.path().to_str().unwrap())
            .expect_err("plain http to the curator must not be accepted");
        let message = err.to_string();
        assert!(message.contains("zkp2p.api_url"), "{message}");
        assert!(message.contains("https"), "{message}");
    });
}

#[test]
fn a_plaintext_base_rpc_url_from_the_environment_is_refused() {
    let file = write_config(GOOD_CONFIG);
    with_env(&[("BASE_RPC_URL", Some("http://rpc.attacker.example"))], || {
        let err = TakerConfig::load(file.path().to_str().unwrap())
            .expect_err("plain http RPC must not be accepted");
        assert!(err.to_string().contains("network.base_rpc_url"), "{err}");
    });
}

#[test]
fn a_plaintext_attestation_url_from_the_environment_is_refused() {
    let file = write_config(GOOD_CONFIG);
    with_env(&[("ATTESTATION_URL", Some("http://attest.attacker.example"))], || {
        let err = TakerConfig::load(file.path().to_str().unwrap())
            .expect_err("plain http attestation service must not be accepted");
        assert!(err.to_string().contains("attestation.service_url"), "{err}");
    });
}

/// A plaintext coordinator URL in the file, not just the environment. The agent
/// checked this one at the point of use (`require_secure_url`); refusing it at
/// load means the operator finds out at startup rather than mid-run.
#[test]
fn a_plaintext_coordinator_url_in_the_file_is_refused() {
    let file = write_config(
        &GOOD_CONFIG.replace("https://coordinator.example", "http://coordinator.example"),
    );
    with_env(&[], || {
        let err = TakerConfig::load(file.path().to_str().unwrap())
            .expect_err("plain http coordinator must not be accepted");
        assert!(err.to_string().contains("taker.coordinator_url"), "{err}");
    });
}

/// Loopback stays allowed. The local mocks and the fork rehearsal use it, and
/// nothing is on the wire.
#[test]
fn loopback_http_is_still_allowed_everywhere() {
    let file = write_config(GOOD_CONFIG);
    for host in ["http://127.0.0.1:4101", "http://localhost:4101", "http://[::1]:4101"] {
        with_env(
            &[
                ("ZKP2P_API_URL", Some(host)),
                ("BASE_RPC_URL", Some(host)),
                ("ATTESTATION_URL", Some(host)),
            ],
            || {
                TakerConfig::load(file.path().to_str().unwrap())
                    .unwrap_or_else(|e| panic!("{host} should be allowed: {e}"));
            },
        );
    }
}

/// Neither a non-http scheme nor a bare string is a service URL.
#[test]
fn other_schemes_and_non_urls_are_refused() {
    let file = write_config(GOOD_CONFIG);
    for bad in ["file:///etc/passwd", "ftp://curator.example", "api.zkp2p.xyz"] {
        with_env(&[("ZKP2P_API_URL", Some(bad))], || {
            assert!(
                TakerConfig::load(file.path().to_str().unwrap()).is_err(),
                "{bad:?} must be refused"
            );
        });
    }
}

/// A userinfo section must not be able to disguise the host: the check reads
/// what is after the `@`, not what is before it.
#[test]
fn userinfo_does_not_disguise_a_remote_host() {
    let file = write_config(GOOD_CONFIG);
    with_env(
        &[("ZKP2P_API_URL", Some("http://127.0.0.1@curator.attacker.example"))],
        || {
            assert!(
                TakerConfig::load(file.path().to_str().unwrap()).is_err(),
                "a loopback-looking userinfo must not make a remote host loopback"
            );
        },
    );
}

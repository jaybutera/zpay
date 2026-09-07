//! A traffic and soak harness for the v2 escrow coordinator.
//!
//! It stands up the real coordinator against a fake world and drives many
//! orders through the whole protocol: quote, order, fund, reach depth,
//! announce, pre-sign, the fiat leg, attest, release - and the refund and
//! never-paid branches, which are where the live incidents happened.
//!
//! # What is real and what is not
//!
//! Real: the coordinator, all of it. Its HTTP surface, its limits, its order
//! store and journal, the funding decision, `dlc::verify_pre_signature`, the
//! attestor's nonce and outcome scalar, the release assembly, and the
//! transaction that gets broadcast. A release this harness produces is a
//! transaction the escrow crate parses and whose signatures check out.
//!
//! Not real: the money, on either side. The chain is an in-process listener
//! that confirms an output as soon as it is told about one, and the fiat leg is
//! [`rail::ModelRail`], which reports payments nobody made. That is deliberate
//! and it is the only way this can run at volume: the alternative is real ZEC
//! into real escrows and real dollars out of one Venmo account.
//!
//! # It cannot touch anything real
//!
//! [`Harness::build`] refuses any configuration whose network is not `test`,
//! and every service URL it uses is a loopback listener this process owns. The
//! LP key is a constant, and the treasury is whatever the escrow crate pins for
//! testnet. There is no code path here that reads a mainnet configuration, the
//! production hub's address, or a stored Venmo session.

pub mod generator;
pub mod rail;
pub mod scenario;
pub mod stack;

use std::sync::Arc;

use anyhow::{Context, Result};

use zecp2p_v2coordinator::config::CoordinatorConfig;
use zecp2p_v2coordinator::funding::FakeScanner;
use zecp2p_v2coordinator::state::{AppStateBuilder, FiatRail};

use crate::rail::{ModelRail, RailCounters, RailProfile};
use crate::scenario::Env;
use crate::stack::{FakeCurator, FakeNode, TestAttestor};

/// The LP key the harness signs releases with.
///
/// A constant, and a published one. Every escrow this harness opens is on a
/// chain that exists only inside this process, so there is nothing for it to
/// protect; naming it here keeps it out of the operator's real keystore.
pub const HARNESS_LP_PRIV: [u8; 32] = [0x22u8; 32];

/// The testnet address refunds are swept to.
///
/// A well-formed testnet address and nothing else. No key in this repo spends
/// it, and no run sends anything real to it.
pub const HARNESS_REFUND_ADDRESS: &str = "tmVHejhMFq979Z7oRwseWMW7snYoQsj22yn";

/// The whole world for a run, kept together so the fakes outlive it.
pub struct Harness {
    pub env: Arc<Env>,
    pub attestor: Arc<TestAttestor>,
    pub rail_counters: Arc<RailCounters>,
    pub node: Arc<FakeNode>,
    /// The state directory. Dropping it removes the run's orders and journal.
    pub _dir: tempfile::TempDir,
    _curator: FakeCurator,
}

/// How to build the harness.
pub struct HarnessOptions {
    pub rail: RailProfile,
    /// Handles the coordinator will serve. Orders name these.
    pub handles: Vec<String>,
    /// How many orders may be open before the coordinator refuses. Raised well
    /// above the shipped default for a load run, because the shipped default
    /// exists to bound node calls against a paid provider and the harness's
    /// node is free.
    pub max_open_orders: usize,
    pub max_open_per_handle: usize,
    /// The largest payment the coordinator will make, in cents. A load run
    /// opens many escrows and the shipped cap is small.
    pub max_payment_cents: u64,
}

impl Default for HarnessOptions {
    fn default() -> Self {
        Self {
            rail: RailProfile::default(),
            handles: vec!["alice".into(), "bob".into(), "carol".into(), "dave".into()],
            max_open_orders: 512,
            max_open_per_handle: 128,
            max_payment_cents: 100_000,
        }
    }
}

impl Harness {
    /// Stands up a coordinator against a fake node, attestor, curator and rail.
    pub async fn build(options: HarnessOptions) -> Result<Self> {
        let dir = tempfile::tempdir().context("the harness needs a state directory")?;
        let node = Arc::new(FakeNode::spawn().await);
        let attestor = Arc::new(TestAttestor::new());
        let curator = FakeCurator::new();

        let rail = Arc::new(ModelRail::new(options.rail.clone()));
        let rail_counters = rail.counters();

        // The LP key. Set in this process's environment because that is how the
        // coordinator reads it; it is the published constant above.
        //
        // Once for the process, not once per harness. It is the same constant
        // every time, so a second write changes nothing - but the test binary
        // builds harnesses on parallel threads while `load_lp_key` reads the
        // variable, and a write racing a read is the pattern Rust 2024 makes
        // `unsafe`.
        static LP_KEY: std::sync::Once = std::sync::Once::new();
        LP_KEY.call_once(|| std::env::set_var("ZECP2P_LP_PRIV", hex::encode(HARNESS_LP_PRIV)));

        let config = harness_config(&options, dir.path(), &node.url, &attestor.url, &curator.url)?;

        // The one guard that matters. Everything above is loopback by
        // construction, but a future edit that made the network configurable
        // would otherwise be able to point this at mainnet.
        if config.zec.network != "test" {
            anyhow::bail!(
                "the load harness refuses any network but test, and this configuration \
                 says {:?}",
                config.zec.network
            );
        }

        let scanner = Arc::new(FakeScanner::new());
        let state = AppStateBuilder::new(config)
            .with_scanner(scanner.clone())
            .with_fiat(rail as Arc<dyn FiatRail>)
            .build()
            .context("the harness coordinator did not build")?;

        let app = zecp2p_v2coordinator::web::router(state.clone());

        Ok(Self {
            env: Arc::new(Env {
                state,
                app,
                scanner,
                node: node.clone(),
                refund_address: HARNESS_REFUND_ADDRESS.to_string(),
                clock: Arc::new(tokio::sync::RwLock::new(())),
            }),
            attestor,
            rail_counters,
            node,
            _dir: dir,
            _curator: curator,
        })
    }
}

/// The configuration a run uses.
///
/// Written as TOML and parsed rather than built field by field, so it goes
/// through the same deserialisation and the same `validate` the real binary
/// does. A configuration this harness accepts is one the coordinator would
/// accept.
fn harness_config(
    options: &HarnessOptions,
    state_dir: &std::path::Path,
    node_url: &str,
    attestor_url: &str,
    curator_url: &str,
) -> Result<CoordinatorConfig> {
    let handles = options
        .handles
        .iter()
        .map(|h| format!("{h:?}"))
        .collect::<Vec<_>>()
        .join(", ");

    let text = format!(
        r#"
[server]
host = "127.0.0.1"
port = 0
state_dir = "{state_dir}"

[zec]
rpc_url = "{node_url}"
network = "test"
refund_hours = 24
block_seconds = 75

[attestor]
url = "{attestor_url}"
token = "loadgen-token"

[lp]
payout_address = "{HARNESS_REFUND_ADDRESS}"
key_env = "ZECP2P_LP_PRIV"

[quote]
rate_usd_per_zec = 40.25
fee_bps = 20
min_zat = 120000
max_zat = 5000000000
max_payment_cents = {max_payment_cents}
max_open_orders = {max_open_orders}
max_open_per_handle = {max_open_per_handle}

[serve]
handles = [{handles}]
live_payments = true

[zkp2p]
api_url = "{curator_url}"
"#,
        state_dir = state_dir.display(),
        max_payment_cents = options.max_payment_cents,
        max_open_orders = options.max_open_orders,
        max_open_per_handle = options.max_open_per_handle,
    );

    toml::from_str(&text).context("the harness configuration does not parse")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_harness_configuration_is_testnet_and_parses() {
        let dir = tempfile::tempdir().unwrap();
        let config = harness_config(
            &HarnessOptions::default(),
            dir.path(),
            "http://127.0.0.1:1",
            "http://127.0.0.1:2",
            "http://127.0.0.1:3",
        )
        .expect("the harness configuration parses");

        assert_eq!(config.zec.network, "test");
        // The handles the generator names must be the ones the coordinator
        // serves, or every order is refused before it opens.
        assert!(config.serve.serves("alice"));
        assert!(config.serve.serves("dave"));
        assert!(!config.serve.serves("eve"));
        assert!(
            !config.serve.allow_any_handle,
            "a run should name who it serves, as a deployment must"
        );
    }
}

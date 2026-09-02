//! Driving the enclave attestation from the daemon.
//!
//! The prover is `scripts/proof/prove_payment_pinned.mjs` and it stays in
//! JavaScript, because it is the thing that encrypts a live Venmo cookie to a
//! Nitro-attested key and reimplementing that in Rust would mean reimplementing
//! the pin verification too. What this module does is build its environment
//! correctly, which is exactly where the 2026-09-01 fill nearly went wrong.
//!
//! # The two corrections this module exists to make unforgettable
//!
//! **`INTENT_RATE`.** The prover defaults `conversionRate` to `1e18` when it is
//! unset. Against deposit 4499's 0.990881148896019200 that produced a
//! `releaseAmount` of 4,840,000 rather than the intent's 4,875,437, and the
//! fulfilment would have reverted at
//! `UnifiedPaymentVerifierV3._validateSnapshotAgainstIntent` with
//! `UPV: Snapshot rate mismatch`. A human caught it by reading the attestation
//! before spending gas. [`AttestRequest`] has no default: the rate is a required
//! field taken from the intent the daemon itself created.
//!
//! **`INTENT_TIMESTAMP_MS`.** The prover falls back to the wall clock and prints
//! a warning nobody reads. The verifier compares the attested snapshot against
//! the intent stored on chain and reverts with
//! `UPV: Snapshot timestamp mismatch`. Also required here.
//!
//! # The pin
//!
//! The prover keeps every enclave check: chain-to-AWS-root, COSE ES384, nonce
//! binding, freshness, and PCR8 against the pinned production value, asserted
//! independently of the library's own comparison. One advisory is allowlisted,
//! `CERT_VALIDITY_NEAR_EXPIRY`, because Nitro leaf certificates rotate about
//! every three hours and the library warns on anything expiring within seven
//! days, so it fires on every healthy production enclave. A cert genuinely
//! outside its window raises `CERT_NOT_TIME_VALID` and a wrong enclave raises
//! `PCR8_PIN_MISMATCH`; both throw rather than warn, so neither can be
//! swallowed by that allowlist.
//!
//! This module does not weaken any of that. It refuses to run a prover that is
//! not the pinned one.

use alloy::primitives::{B256, U256};
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

use crate::auto::cookie::SessionMaterial;

/// The prover that keeps the PCR8 pin.
///
/// Named rather than configurable. `prove_payment.mjs` is the same script with
/// the pin guard rejecting every warning, which means it refuses to run against
/// a healthy production enclave; pointing this at it would look like a
/// configuration choice and behave like a downgrade.
pub const PINNED_PROVER: &str = "scripts/proof/prove_payment_pinned.mjs";

/// Everything the enclave needs to attest one payment against one intent.
#[derive(Debug, Clone)]
pub struct AttestRequest {
    /// The intent to bind the attestation to, from its `IntentSignaled` log.
    pub intent_hash: B256,
    /// Release amount in 6-decimal USDC units.
    pub amount: U256,
    /// The intent's conversion rate, scaled by 1e18. Required, never defaulted.
    pub conversion_rate: U256,
    /// The intent's on-chain signal time in milliseconds. Required.
    pub timestamp_ms: u64,
    /// The curator's `hashedOnchainId` for the payee, as the deposit carries it.
    pub payee_hash: B256,
    /// Which entry of the Venmo feed. 0 is the most recent.
    pub payment_index: u32,
}

/// What the enclave signed.
#[derive(Debug, Clone, Deserialize)]
pub struct Attestation {
    pub platform: String,
    #[serde(rename = "actionType")]
    pub action_type: String,
    pub signature: String,
    pub signer: String,
    #[serde(rename = "domainSeparator")]
    pub domain_separator: String,
    #[serde(rename = "typedDataValue")]
    pub typed_data_value: TypedDataValue,
    /// The `data` field of the on-chain `PaymentAttestation`. `dataHash` is its
    /// keccak256, which is what the enclave actually signed over.
    #[serde(rename = "encodedPaymentDetails", default)]
    pub encoded_payment_details: String,
    /// Carried through unsigned; the verifier reads it but the witnesses do not
    /// sign it.
    #[serde(default)]
    pub metadata: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct TypedDataValue {
    #[serde(rename = "intentHash")]
    pub intent_hash: String,
    #[serde(rename = "releaseAmount")]
    pub release_amount: String,
    #[serde(rename = "dataHash")]
    pub data_hash: String,
}

/// The prover's output file, as written to `OUT`.
#[derive(Debug, Clone, Deserialize)]
pub struct AttestationFile {
    pub attestation: Attestation,
    #[serde(rename = "chainId")]
    pub chain_id: u64,
    #[serde(rename = "verifyingContract")]
    pub verifying_contract: String,
}

impl AttestationFile {
    /// Check the attestation is bound to the intent we asked about.
    ///
    /// The enclave re-signs the same payment for whatever `intentHash` it is
    /// handed and does not check that intent against chain state, so this is
    /// the taker's own check that the attestation in hand belongs to the intent
    /// in hand rather than to a previous one left in the output file.
    pub fn check_binds(&self, request: &AttestRequest) -> Result<()> {
        let bound: B256 = self
            .attestation
            .typed_data_value
            .intent_hash
            .parse()
            .context("the attestation's intentHash is not a 32-byte hex value")?;
        if bound != request.intent_hash {
            bail!(
                "the attestation is bound to intent {bound}, not to {}. \
                 Refusing to use it: submitting it would revert, and it may be \
                 a stale file from an earlier run.",
                request.intent_hash
            );
        }

        let released: U256 = self
            .attestation
            .typed_data_value
            .release_amount
            .parse()
            .context("the attestation's releaseAmount is not a number")?;
        if released != request.amount {
            bail!(
                "the enclave attested a releaseAmount of {released} against an \
                 intent for {}. This is what an unset INTENT_RATE looks like: \
                 the snapshot was computed at a different conversion rate and \
                 fulfilment would revert with \"UPV: Snapshot rate mismatch\".",
                request.amount
            );
        }
        Ok(())
    }
}

/// Runs the pinned prover.
pub struct Attester {
    /// Repository root, so the prover path resolves the same from anywhere.
    root: PathBuf,
    service_url: String,
    verifier: String,
    chain_id: u64,
}

impl Attester {
    pub fn new(
        root: impl AsRef<Path>,
        service_url: impl Into<String>,
        verifier: impl Into<String>,
        chain_id: u64,
    ) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
            service_url: service_url.into(),
            verifier: verifier.into(),
            chain_id: chain_id,
        }
    }

    /// The environment the prover is run with.
    ///
    /// Built separately from the run so it can be asserted in tests without a
    /// cookie, an enclave, or a network. The two corrections above are what
    /// these tests are for.
    pub fn environment(
        &self,
        request: &AttestRequest,
        material: &SessionMaterial,
        out: &Path,
    ) -> Vec<(String, String)> {
        let mut env = vec![
            ("INTENT_HASH".into(), request.intent_hash.to_string()),
            ("INTENT_AMOUNT".into(), request.amount.to_string()),
            // Never defaulted. The prover's own default is 1e18 and it is wrong
            // for every deposit not priced at exactly 1.0.
            ("INTENT_RATE".into(), request.conversion_rate.to_string()),
            (
                "INTENT_TIMESTAMP_MS".into(),
                request.timestamp_ms.to_string(),
            ),
            ("PAYEE_HASH".into(), request.payee_hash.to_string()),
            ("PAYMENT_INDEX".into(), request.payment_index.to_string()),
            ("VENMO_COOKIE".into(), material.cookie.clone()),
            ("VENMO_SENDER_ID".into(), material.sender_id.clone()),
            ("CHAIN_ID".into(), self.chain_id.to_string()),
            ("VERIFIER".into(), self.verifier.clone()),
            ("ATTESTATION_URL".into(), self.service_url.clone()),
            ("OUT".into(), out.display().to_string()),
        ];
        if let Some(agent) = &material.user_agent {
            env.push(("VENMO_USER_AGENT".into(), agent.clone()));
        }
        env
    }

    /// Obtain an attestation for a payment already in the Venmo feed.
    ///
    /// Sends the cookie. Everything checkable without spending it has already
    /// been checked by the time this is called: see `auto::pipeline`, which
    /// runs the cookie health check before `signalIntent` rather than here.
    pub async fn attest(
        &self,
        request: &AttestRequest,
        material: &SessionMaterial,
        out: &Path,
    ) -> Result<AttestationFile> {
        let prover = self.root.join(PINNED_PROVER);
        if !prover.exists() {
            bail!(
                "the pinned prover is not at {}. This module will not fall back \
                 to prove_payment.mjs: that script treats every enclave warning \
                 as fatal, including the CERT_VALIDITY_NEAR_EXPIRY that every \
                 healthy production enclave raises.",
                prover.display()
            );
        }

        // A stale file from an earlier run must not be mistaken for this run's
        // output if the prover fails in a way that leaves the old one in place.
        if out.exists() {
            std::fs::remove_file(out)
                .with_context(|| format!("could not clear {}", out.display()))?;
        }

        let mut command = tokio::process::Command::new("node");
        command.arg(&prover).current_dir(&self.root);
        for (key, value) in self.environment(request, material, out) {
            command.env(key, value);
        }

        tracing::info!(
            intent_hash = %request.intent_hash,
            amount = %request.amount,
            rate = %request.conversion_rate,
            "asking the enclave to attest the payment"
        );

        let output = command
            .output()
            .await
            .context("could not run node; the prover needs node and its scripts/proof deps")?;

        // The prover's stdout carries the enclave signer, the PCR8 assertion and
        // the local verification result. It is the record of what was checked,
        // so it is surfaced rather than swallowed.
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            tracing::info!(target: "prover", "{line}");
        }

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!(
                "the prover failed ({}). The enclave did not attest the payment.\n{stderr}",
                output.status
            );
        }

        // The prover prints this only after `verifyBuyerTeePaymentAttestation`
        // returns, so its absence means the signature was not checked locally.
        if !stdout.contains("local verification: PASS") {
            bail!(
                "the prover exited zero but never reported a local verification \
                 pass. Refusing to treat its output as a verified attestation."
            );
        }

        let contents = std::fs::read_to_string(out)
            .with_context(|| format!("the prover wrote no attestation to {}", out.display()))?;
        let file: AttestationFile =
            serde_json::from_str(&contents).context("the prover's output is not an attestation")?;

        file.check_binds(request)?;
        Ok(file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> AttestRequest {
        AttestRequest {
            intent_hash: "0x0845a0cade347cd5a1453fdc7f927d91511c82736377d8897b9bde38458b9b98"
                .parse()
                .unwrap(),
            amount: U256::from(4_875_437u64),
            conversion_rate: U256::from(990_881_148_896_019_200u128),
            timestamp_ms: 1_788_315_013_000,
            payee_hash: "0x853410f0416f12611961e72ee5397ec6839a3f6475467f8a557bbdb3fc8555db"
                .parse()
                .unwrap(),
            payment_index: 0,
        }
    }

    fn material() -> SessionMaterial {
        SessionMaterial {
            cookie: "api_access_token=abc".into(),
            sender_id: "1234567890123456789".into(),
            user_agent: Some("Mozilla/5.0".into()),
            captured_at: chrono::Utc::now(),
        }
    }

    fn env_of(request: &AttestRequest) -> std::collections::BTreeMap<String, String> {
        Attester::new(
            ".",
            "https://attestation-service.zkp2p.xyz",
            "0xC6F4a193576C60892a47e111Bb5706c30162502B",
            8453,
        )
        .environment(request, &material(), Path::new("/tmp/out.json"))
        .into_iter()
        .collect()
    }

    /// The correction that would have cost the 2026-09-01 fill its margin: the
    /// rate is the intent's, and explicitly not the prover's 1e18 default.
    #[test]
    fn the_rate_is_the_intents_and_never_the_provers_default() {
        let env = env_of(&request());
        assert_eq!(env["INTENT_RATE"], "990881148896019200");
        assert_ne!(env["INTENT_RATE"], "1000000000000000000");
    }

    /// The other correction. Without it the prover uses the wall clock and the
    /// verifier reverts with "UPV: Snapshot timestamp mismatch".
    #[test]
    fn the_timestamp_is_the_intents_signal_time() {
        assert_eq!(env_of(&request())["INTENT_TIMESTAMP_MS"], "1788315013000");
    }

    /// Every field the prover requires has to be present, or it exits 2 after
    /// the daemon has already decided to spend the cookie.
    #[test]
    fn every_required_prover_variable_is_set() {
        let env = env_of(&request());
        for key in [
            "INTENT_HASH",
            "INTENT_AMOUNT",
            "INTENT_RATE",
            "INTENT_TIMESTAMP_MS",
            "PAYEE_HASH",
            "VENMO_COOKIE",
            "VENMO_SENDER_ID",
            "CHAIN_ID",
            "VERIFIER",
            "ATTESTATION_URL",
            "OUT",
        ] {
            assert!(env.contains_key(key), "missing {key}");
            assert!(!env[key].is_empty(), "{key} is empty");
        }
    }

    /// The pin lives in the prover, and the prover is named rather than
    /// configured so an unpinned one cannot be substituted from a config file.
    #[test]
    fn only_the_pinned_prover_is_named() {
        assert!(PINNED_PROVER.ends_with("prove_payment_pinned.mjs"));
    }

    fn attestation_file(intent: &str, release: &str) -> AttestationFile {
        serde_json::from_str(&format!(
            r#"{{
              "attestation": {{
                "platform": "venmo",
                "actionType": "transfer_venmo",
                "signature": "0xdead",
                "signer": "0xe078d93bfdd87a8c5c5cca5905dcba0dd7a1f0bd",
                "domainSeparator": "0xe27f",
                "typedDataValue": {{
                  "intentHash": "{intent}",
                  "releaseAmount": "{release}",
                  "dataHash": "0x42ed"
                }}
              }},
              "chainId": 8453,
              "verifyingContract": "0xC6F4a193576C60892a47e111Bb5706c30162502B"
            }}"#
        ))
        .unwrap()
    }

    #[test]
    fn an_attestation_bound_to_the_right_intent_is_accepted() {
        let file = attestation_file(
            "0x0845a0cade347cd5a1453fdc7f927d91511c82736377d8897b9bde38458b9b98",
            "4875437",
        );
        assert!(file.check_binds(&request()).is_ok());
    }

    /// A stale output file from an earlier run is the realistic way a wrong
    /// attestation gets submitted, and it is refused.
    #[test]
    fn an_attestation_bound_to_another_intent_is_refused() {
        let file = attestation_file(
            "0x1111111111111111111111111111111111111111111111111111111111111111",
            "4875437",
        );
        let err = file.check_binds(&request()).expect_err("must refuse");
        assert!(err.to_string().contains("not to"), "{err}");
    }

    /// This is exactly what an unset INTENT_RATE produced on 2026-09-01:
    /// 4,840,000 against an intent for 4,875,437.
    #[test]
    fn the_release_amount_from_a_wrong_rate_is_caught_before_submission() {
        let file = attestation_file(
            "0x0845a0cade347cd5a1453fdc7f927d91511c82736377d8897b9bde38458b9b98",
            "4840000",
        );
        let err = file.check_binds(&request()).expect_err("must refuse");
        assert!(err.to_string().contains("Snapshot rate mismatch"), "{err}");
    }
}

/// Finding which entry of the Venmo feed is the payment we just made.
///
/// The enclave selects `$.stories[INDEX]` by raw position and applies no filter
/// of its own: not on direction, not on amount, not on recipient. So a
/// hardcoded index 0 attests "the most recent thing that happened on this
/// account", which is only our payment if nothing else landed first. An
/// incoming transfer arriving between the send and the attestation silently
/// shifts our payment to index 1, and index 0 is then a real, correctly signed
/// attestation of somebody else's money.
///
/// `check_binds` does not catch that. It compares the attested `releaseAmount`
/// against the intent, and the enclave computes `releaseAmount` from the entry
/// it was pointed at, so a wrong entry with a coincidentally equal amount
/// passes. The defence has to be choosing the right index in the first place.
pub mod feed {
    use anyhow::{bail, Context, Result};
    use serde::Deserialize;

    use super::SessionMaterial;

    #[derive(Debug, Deserialize)]
    struct Stories {
        #[serde(default)]
        stories: Vec<Story>,
    }

    #[derive(Debug, Deserialize)]
    struct Story {
        /// Rendered with a sign and a currency symbol: "- $4.84", "+ $1.00".
        #[serde(default)]
        amount: String,
        /// ISO 8601, e.g. "2026-09-02T02:21:39". Local to Venmo, no zone.
        #[serde(default)]
        date: String,
        #[serde(default)]
        title: Title,
    }

    #[derive(Debug, Default, Deserialize)]
    struct Title {
        #[serde(default)]
        receiver: Party,
    }

    #[derive(Debug, Default, Deserialize)]
    struct Party {
        #[serde(default)]
        username: String,
    }

    /// The feed entry that is our payment: outgoing, for this amount, to this
    /// handle.
    ///
    /// Returns the index the enclave should be given. Refuses rather than
    /// guessing when nothing matches, because the alternative is attesting a
    /// stranger's transaction, and refuses when more than one entry matches,
    /// because then position alone cannot say which is ours.
    pub async fn locate_payment(
        http: &reqwest::Client,
        material: &SessionMaterial,
        recipient: &str,
        amount: &str,
        after: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<u32> {
        let url = format!(
            "https://account.venmo.com/api/stories?feedType=me&externalId={}",
            material.sender_id
        );
        let mut request = http
            .get(&url)
            .header("Cookie", &material.cookie)
            .header("accept", "application/json");
        if let Some(agent) = &material.user_agent {
            request = request.header("User-Agent", agent.clone());
        }

        let response = request
            .send()
            .await
            .context("could not read the Venmo feed to locate the payment")?;
        if !response.status().is_success() {
            bail!(
                "the Venmo feed answered {} when asked which entry the payment is. \
                 The cookie may have expired between the payment and the attestation.",
                response.status()
            );
        }
        let body: Stories = response
            .json()
            .await
            .context("the Venmo feed did not answer with the story list")?;

        // Amount and recipient are not enough on their own. The same account
        // pays the same handle the same dollar repeatedly: on 2026-09-02 the
        // live feed held three $1.00 payments to test-payee, and the run being
        // attested was about to add a fourth. What separates ours from the
        // others is that it is newer than the moment we signalled, so that
        // moment is the cut.
        let matches: Vec<usize> = body
            .stories
            .iter()
            .enumerate()
            .filter(|(_, s)| is_our_payment(s, recipient, amount))
            .filter(|(_, s)| after.is_none_or(|cut| is_after(s, cut)))
            .map(|(i, _)| i)
            .collect();

        match matches.as_slice() {
            [only] => u32::try_from(*only)
                .context("the matching feed entry is further down than an index can express"),
            [] => bail!(
                "no outgoing payment of ${amount} to @{recipient}{} is in the Venmo feed. \
                 The payment may not have registered yet, or it went to a different \
                 handle. Refusing to attest by position: index 0 is whatever happened \
                 most recently on this account, which may be someone else's money.",
                match after {
                    Some(cut) => format!(" after {cut}"),
                    None => String::new(),
                }
            ),
            many => bail!(
                "{} feed entries look like a ${amount} payment to @{recipient} (indices {:?}). \
                 Position alone cannot say which one this intent paid for, so this needs \
                 an operator and an explicit --index.",
                many.len(),
                many
            ),
        }
    }

    /// Whether this entry is newer than the cut.
    ///
    /// Venmo stamps stories with a naive local time ("2026-09-02T02:21:39"), so
    /// it is read as naive and compared in UTC. An unparseable date is treated
    /// as not matching: the cost of dropping a real entry is a refusal that asks
    /// for an operator, and the cost of keeping a wrong one is attesting the
    /// wrong payment.
    fn is_after(story: &Story, cut: chrono::DateTime<chrono::Utc>) -> bool {
        chrono::NaiveDateTime::parse_from_str(story.date.trim(), "%Y-%m-%dT%H:%M:%S")
            .map(|naive| naive.and_utc() >= cut)
            .unwrap_or(false)
    }

    /// Outgoing, right amount, right recipient.
    ///
    /// Venmo renders the amount with a sign and a symbol and the sign is the
    /// direction: "- $4.84" left the account, "+ $1.00" arrived. Matching on the
    /// digits alone would accept a payment *to* us of the same size.
    fn is_our_payment(story: &Story, recipient: &str, amount: &str) -> bool {
        let rendered = story.amount.trim();
        let Some(rest) = rendered.strip_prefix('-') else {
            return false;
        };
        let digits: String = rest
            .chars()
            .filter(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        digits == amount && story.title.receiver.username.eq_ignore_ascii_case(recipient)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn story(amount: &str, receiver: &str) -> Story {
            dated_story(amount, receiver, "2026-09-02T02:21:39")
        }

        fn dated_story(amount: &str, receiver: &str, date: &str) -> Story {
            Story {
                amount: amount.into(),
                date: date.into(),
                title: Title {
                    receiver: Party {
                        username: receiver.into(),
                    },
                },
            }
        }

        fn utc(s: &str) -> chrono::DateTime<chrono::Utc> {
            chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S")
                .unwrap()
                .and_utc()
        }

        /// The ambiguity this exists for, taken from the live feed: on
        /// 2026-09-02 three $1.00 payments to test-payee were already in it, and
        /// the run being attested was about to add a fourth. Only the cut
        /// separates them.
        #[test]
        fn the_signal_time_separates_todays_payment_from_last_weeks() {
            let old = dated_story("- $1.00", "test-payee", "2026-08-31T17:40:25");
            let ours = dated_story("- $1.00", "test-payee", "2026-09-02T16:00:00");
            let cut = utc("2026-09-02T15:55:00");

            assert!(is_our_payment(&old, "test-payee", "1.00"));
            assert!(is_our_payment(&ours, "test-payee", "1.00"));
            // but only one of them is after the cut
            assert!(!is_after(&old, cut));
            assert!(is_after(&ours, cut));
        }

        /// A date Venmo renders in a shape we do not expect must not be treated
        /// as recent. Dropping a real entry costs a refusal; keeping a wrong one
        /// costs the payment.
        #[test]
        fn an_unparseable_date_is_not_treated_as_ours() {
            let odd = dated_story("- $1.00", "test-payee", "yesterday");
            assert!(!is_after(&odd, utc("2020-01-01T00:00:00")));
        }

        /// The live feed on 2026-09-02, shape and all: index 0 was an *incoming*
        /// $1.00 and the outgoing $4.84 fill was at index 1.
        #[test]
        fn an_incoming_payment_at_index_zero_is_not_ours() {
            assert!(!is_our_payment(
                &story("+ $1.00", "test-payer"),
                "test-payee",
                "1.00"
            ));
            assert!(is_our_payment(
                &story("- $4.84", "test-payee"),
                "test-payee",
                "4.84"
            ));
        }

        /// The direction check is the point: a payment *to* us of the same size
        /// must not be mistaken for the one we sent.
        #[test]
        fn the_sign_decides_direction() {
            assert!(is_our_payment(&story("- $1.00", "test-payee"), "test-payee", "1.00"));
            assert!(!is_our_payment(&story("+ $1.00", "test-payee"), "test-payee", "1.00"));
        }

        #[test]
        fn the_recipient_must_match_and_case_does_not() {
            assert!(is_our_payment(&story("- $1.00", "test-payee"), "test-payee", "1.00"));
            assert!(!is_our_payment(&story("- $1.00", "someone-else"), "test-payee", "1.00"));
        }

        #[test]
        fn the_amount_must_match_exactly() {
            assert!(!is_our_payment(&story("- $10.00", "test-payee"), "test-payee", "1.00"));
            assert!(!is_our_payment(&story("- $1.01", "test-payee"), "test-payee", "1.00"));
        }
    }
}

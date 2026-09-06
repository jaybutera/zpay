//! The fiat leg, through the taker's shared Venmo code.
//!
//! Nothing about sending a payment is written here. `fiat::pay` drives the
//! browser and `fiat::attest` finds the payment in the feed and gets the
//! enclave to sign it; both are the same functions the Base rail uses, which is
//! the point of them being rail-agnostic.
//!
//! What this module does own is the conversion at the end: the enclave's
//! `AttestationFile` into the attestor's `WireAttestation`. That conversion did
//! not exist anywhere as a library function, and the one copy of it in the repo
//! is a private helper inside `paid_path.rs`. Its hex convention is the trap:
//! the escrow crate's `hex::encode` produces **unprefixed** hex, so a `0x` left
//! on any field is a 400 from the attestor, arriving after the dollars are
//! gone.

use anyhow::{Context, Result};

use zecp2p_escrow::lp_client::WireAttestation;
use zecp2p_taker::auto::attest::{AttestationFile, Attester};
use zecp2p_taker::auto::cookie::CookieStore;
use zecp2p_taker::auto::rail::FiatLeg;
use zecp2p_taker::venmo::{SendMode, VenmoBrowser};

use zecp2p_v2coordinator::config::{expand_home, CoordinatorConfig};
use zecp2p_v2coordinator::state::{FiatRail, PaidFiat, RailBalance};

pub struct VenmoRail {
    browser: VenmoBrowser,
    attester: Attester,
    cookies: CookieStore,
    http: reqwest::Client,
    note: String,
    mode: SendMode,
    out_dir: std::path::PathBuf,
}

impl VenmoRail {
    pub fn new(config: &CoordinatorConfig) -> Result<Self> {
        let browser = VenmoBrowser::new(
            config.venmo.cdp_url.clone(),
            config.venmo.timeout_seconds,
        );

        let repo_root = config
            .attestation
            .repo_root
            .clone()
            .map(|p| expand_home(&p))
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());

        let attester = Attester::new(
            &repo_root,
            config.attestation.service_url.clone(),
            config.attestation.verifier.clone(),
            config.attestation.chain_id,
        );

        let cookies = CookieStore::new(
            expand_home(&config.venmo.session_path),
            config.venmo.session_max_age_hours,
        )
        .with_identity(
            config.venmo.sender_id.clone(),
            config.venmo.user_agent.clone(),
        );

        Ok(Self {
            browser,
            attester,
            cookies,
            http: reqwest::Client::new(),
            note: config.venmo.note.clone(),
            // The one switch between driving the page and clicking send.
            mode: if config.serve.live_payments {
                SendMode::Live
            } else {
                SendMode::DryRun
            },
            out_dir: config.state_dir().join("attestations"),
        })
    }

    fn session(&self) -> Result<zecp2p_taker::auto::cookie::SessionMaterial> {
        let health = self
            .cookies
            .health()
            .context("could not read the stored Venmo session")?;
        if !health.is_usable() {
            anyhow::bail!(
                "the stored Venmo session is not usable: {}. The enclave replays it to \
                 prove the payment, so a payment sent without one cannot be attested.",
                health.explain()
            );
        }
        self.cookies
            .load()
            .context("could not load the Venmo session")?
            .ok_or_else(|| anyhow::anyhow!("no Venmo session material is stored"))
    }
}

#[async_trait::async_trait]
impl FiatRail for VenmoRail {
    /// Everything `pay` will refuse on, asked before anything is committed.
    ///
    /// All of it is operator state rather than trade state: a stale cookie, a
    /// closed browser, a tab sitting on the login page. Each means this
    /// coordinator cannot pay *yet*, and an escrow whose LP never started is
    /// one the user refunds at `T`.
    ///
    /// R1-4: this used to check that a Venmo tab existed but not that it was
    /// signed in, while `VenmoBrowser::pay` bails on exactly that
    /// (`session_looks_live`). So a tab bounced to `/signin` passed preflight,
    /// `Paying` was journaled, `pay` refused, and the order went terminal
    /// saying a payment may have left - when the browser had not been driven at
    /// all. The rule this now follows: **preflight must refuse on every
    /// condition `pay` refuses on, before the journal is written.**
    async fn preflight(&self) -> Result<()> {
        // The enclave replays this to prove the payment, so a payment sent
        // without one could never be recovered from the escrow.
        self.session()?;

        // `find_venmo_tab` is the payment path's own finder and deliberately
        // will not create a tab: a payment that opened its own tab would be
        // driving a page nobody had signed into.
        let tab = self
            .browser
            .find_venmo_tab()
            .await
            .context("no logged-in Venmo tab to pay from")?;

        // The same predicate `pay` uses, from the same place, so the two cannot
        // drift into disagreeing about what signed out looks like.
        if !VenmoBrowser::session_looks_live(&tab) {
            anyhow::bail!(
                "the Venmo tab is on {} and looks signed out; sign in again and the \
                 escrow will be paid on the next sweep",
                tab.url
            );
        }
        Ok(())
    }

    /// Sends the dollars.
    ///
    /// No session recheck here. It used to be, and it was on the wrong side of
    /// the line: a failure inside `pay` is treated as "money may have left",
    /// so a *cheap and certain* refusal placed here turns an operator problem
    /// into a terminal order. Every condition that can be checked without
    /// driving the browser belongs in `preflight`, before the journal claim.
    /// What remains here is the drive itself, whose failures really are
    /// ambiguous.
    async fn pay(&self, leg: &FiatLeg) -> Result<PaidFiat> {
        // The configured note is a prefix now, not the whole thing: the leg's
        // tag goes on the end so this payment can be told apart from any other
        // of the same amount to the same handle when the feed is read back.
        // `locate_payment` looks for the tag as a substring, so what leads it is
        // free text for whoever receives the money.
        let note = match &leg.tag {
            Some(tag) => format!("{} {tag}", self.note.trim()),
            None => self.note.clone(),
        };
        let sent = zecp2p_taker::auto::fiat::pay(&self.browser, leg, &note, self.mode).await?;
        Ok(PaidFiat {
            cents: u64::try_from(leg.payment.cents())
                .context("the payment does not fit a cent count")?,
            fiat_left: sent.fiat_left(),
            // What was typed, reported back so the attestation searches the
            // feed for the note this payment actually carries rather than the
            // one a later build would have written.
            note: Some(note),
        })
    }

    /// What the signed-in account has to spend. Finding 5.
    ///
    /// Everything that can go wrong here answers `Unknown` with the reason
    /// rather than an error: this is called on the reservation path, and a
    /// browser hiccup must not be read as an empty account. The coordinator's
    /// `float.pay_when_balance_unknown` is where an operator says what an
    /// unreadable balance should mean for *their* deployment.
    async fn balance_cents(&self) -> RailBalance {
        let tab = match self.browser.find_venmo_tab().await {
            Ok(t) => t,
            Err(e) => return RailBalance::Unknown(format!("no logged-in tab to read: {e}")),
        };
        match self.browser.available_balance_cents(&tab).await {
            Ok(Some(cents)) => RailBalance::Known(cents),
            Ok(None) => RailBalance::Unknown(
                "the account page answered without a balance field this build recognises"
                    .to_string(),
            ),
            Err(e) => RailBalance::Unknown(format!("{e:#}")),
        }
    }

    async fn attest(&self, leg: &FiatLeg) -> Result<WireAttestation> {
        let material = self.session()?;
        std::fs::create_dir_all(&self.out_dir)
            .with_context(|| format!("could not create {}", self.out_dir.display()))?;
        let out = self
            .out_dir
            .join(format!("{}.json", hex::encode(leg.intent_hash.0)));

        let file =
            zecp2p_taker::auto::fiat::attest(&self.http, &self.attester, &material, leg, &out)
                .await?;
        wire_attestation(&file)
    }
}

/// The enclave's export, as the attestor wants it.
///
/// Every field crosses unprefixed except `release_amount`, which is a decimal
/// string. `hex::decode` on the attestor side refuses a `0x`, and the refusal
/// arrives after the dollars have left.
pub fn wire_attestation(file: &AttestationFile) -> Result<WireAttestation> {
    let v = &file.attestation.typed_data_value;
    let strip = |s: &str| s.trim().trim_start_matches("0x").to_ascii_lowercase();

    let intent_hash = strip(&v.intent_hash);
    let data_hash = strip(&v.data_hash);
    let signature = strip(&file.attestation.signature);
    let encoded_payment_details = strip(&file.attestation.encoded_payment_details);

    // Shapes, checked here rather than at the attestor. A malformed field is a
    // 400 that costs an announcement, and the announcement is drawn once.
    if intent_hash.len() != 64 {
        anyhow::bail!("the attestation's intentHash is not 32 bytes");
    }
    if data_hash.len() != 64 {
        anyhow::bail!("the attestation's dataHash is not 32 bytes");
    }
    if signature.is_empty() || hex::decode(&signature).is_err() {
        anyhow::bail!("the attestation's signature is not hex");
    }
    if encoded_payment_details.is_empty() || hex::decode(&encoded_payment_details).is_err() {
        anyhow::bail!("the attestation's encodedPaymentDetails is not hex");
    }
    // `releaseAmount` is decimal, and the enclave prints it that way. A hex
    // string here would be read as a much larger number.
    let release_amount = v.release_amount.trim().to_string();
    if release_amount.is_empty() || !release_amount.chars().all(|c| c.is_ascii_digit()) {
        anyhow::bail!(
            "the attestation's releaseAmount is {:?}, which is not a decimal integer",
            v.release_amount
        );
    }

    Ok(WireAttestation {
        intent_hash,
        release_amount,
        data_hash,
        signature,
        encoded_payment_details,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use zecp2p_taker::auto::attest::{Attestation, TypedDataValue};

    fn file(intent: &str, release: &str, data: &str, sig: &str, details: &str) -> AttestationFile {
        AttestationFile {
            attestation: Attestation {
                platform: "venmo".into(),
                action_type: "transfer_venmo".into(),
                signature: sig.into(),
                signer: "0xe078d93bfdd87a8c5c5cca5905dcba0dd7a1f0bd".into(),
                domain_separator: "0x00".into(),
                typed_data_value: TypedDataValue {
                    intent_hash: intent.into(),
                    release_amount: release.into(),
                    data_hash: data.into(),
                },
                encoded_payment_details: details.into(),
                metadata: "{}".into(),
            },
            chain_id: 8453,
            verifying_contract: "0xc6f4a193576c60892a47e111bb5706c30162502b".into(),
        }
    }

    #[test]
    fn the_0x_prefix_is_stripped_from_every_field_but_the_amount() {
        // The attestor's `hex::decode` refuses a `0x`, and the refusal arrives
        // after the dollars have left.
        let f = file(
            &format!("0x{}", "11".repeat(32)),
            "5000000",
            &format!("0x{}", "22".repeat(32)),
            &format!("0x{}", "33".repeat(65)),
            &format!("0x{}", "44".repeat(448)),
        );
        let w = wire_attestation(&f).expect("this export is well formed");
        assert_eq!(w.intent_hash, "11".repeat(32));
        assert_eq!(w.data_hash, "22".repeat(32));
        assert_eq!(w.signature, "33".repeat(65));
        assert_eq!(w.encoded_payment_details, "44".repeat(448));
        assert_eq!(w.release_amount, "5000000", "the amount stays decimal");
    }

    #[test]
    fn an_unprefixed_export_converts_unchanged() {
        let f = file(
            &"aa".repeat(32),
            "1",
            &"bb".repeat(32),
            &"cc".repeat(65),
            &"dd".repeat(448),
        );
        let w = wire_attestation(&f).unwrap();
        assert_eq!(w.intent_hash, "aa".repeat(32));
    }

    #[test]
    fn a_hex_release_amount_is_refused_rather_than_sent() {
        // Read as decimal by the attestor, `0x4c4b40` is not 5,000,000. It is
        // not a number at all, and the escrow would refuse the attestation
        // after the payment.
        let f = file(
            &"11".repeat(32),
            "0x4c4b40",
            &"22".repeat(32),
            &"33".repeat(65),
            &"44".repeat(448),
        );
        let err = wire_attestation(&f).expect_err("a hex amount must be refused");
        assert!(err.to_string().contains("decimal"));
    }

    #[test]
    fn a_short_hash_is_refused_before_it_costs_an_announcement() {
        let f = file("0x1234", "1", &"22".repeat(32), &"33".repeat(65), &"44".repeat(448));
        assert!(wire_attestation(&f).is_err());
    }
}

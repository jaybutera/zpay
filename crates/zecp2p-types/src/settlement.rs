//! The backend-generic settlement interface.
//!
//! Two implementations exist and no more: `oneclick-zkp2p`, the route that runs
//! today, and `native-escrow`, the Zcash 2-of-2 CLTV escrow of
//! `specs/zec-native-escrow.md`. Everything the two routes disagree about is
//! carried here as data rather than as a method only one of them answers, so
//! the front end never grows a backend switch.
//!
//! The shapes here are what `/v2` serves and what both the main route and the
//! advanced route render. The advanced route fills [`Overrides`]; the main route
//! leaves it empty.

use serde::{Deserialize, Serialize};

/// Which settlement route an order runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BackendId {
    /// ZEC to USDC on Base through 1Click, then zk-p2p escrow, then a taker.
    OneclickZkp2p,
    /// ZEC locked in a 2-of-2 CLTV script, released to an LP by adaptor
    /// signature. The ZEC never leaves Zcash.
    NativeEscrow,
}

impl BackendId {
    pub fn as_str(&self) -> &'static str {
        match self {
            BackendId::OneclickZkp2p => "oneclick-zkp2p",
            BackendId::NativeEscrow => "native-escrow",
        }
    }

    /// The sentence the status page shows as the route label.
    pub fn route_label(&self) -> &'static str {
        match self {
            BackendId::OneclickZkp2p => "via 1Click and zk-p2p",
            BackendId::NativeEscrow => "direct escrow",
        }
    }
}

impl std::fmt::Display for BackendId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for BackendId {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "oneclick-zkp2p" => Ok(BackendId::OneclickZkp2p),
            "native-escrow" => Ok(BackendId::NativeEscrow),
            other => Err(format!("unknown settlement backend {other:?}")),
        }
    }
}

/// A payout rail. The rail owns the handle parser and the human label; the
/// front end shows whatever label the rail returns and never inspects the
/// handle string.
///
/// The list is zk-p2p's buyer platform enum, which is closed. Venmo is the one
/// the curator registers payees for today, so it is the one live rail on both
/// backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Rail {
    Venmo,
    CashApp,
    Paypal,
    Zelle,
    Wise,
    Revolut,
    Monzo,
    Chime,
    Monobank,
    Alipay,
    Upi,
}

impl Rail {
    pub fn as_str(&self) -> &'static str {
        match self {
            Rail::Venmo => "venmo",
            Rail::CashApp => "cashapp",
            Rail::Paypal => "paypal",
            Rail::Zelle => "zelle",
            Rail::Wise => "wise",
            Rail::Revolut => "revolut",
            Rail::Monzo => "monzo",
            Rail::Chime => "chime",
            Rail::Monobank => "monobank",
            Rail::Alipay => "alipay",
            Rail::Upi => "upi",
        }
    }

    /// The name shown next to the handle field.
    pub fn label(&self) -> &'static str {
        match self {
            Rail::Venmo => "Venmo",
            Rail::CashApp => "Cash App",
            Rail::Paypal => "PayPal",
            Rail::Zelle => "Zelle",
            Rail::Wise => "Wise",
            Rail::Revolut => "Revolut",
            Rail::Monzo => "Monzo",
            Rail::Chime => "Chime",
            Rail::Monobank => "Monobank",
            Rail::Alipay => "Alipay",
            Rail::Upi => "UPI",
        }
    }

    /// Whether an order can actually be opened on this rail today.
    ///
    /// The picker shows every rail the enclave enumerates so the product's
    /// reach is visible, and refuses the ones the curator cannot register a
    /// payee for.
    pub fn is_live(&self) -> bool {
        matches!(self, Rail::Venmo)
    }

    pub fn all() -> &'static [Rail] {
        &[
            Rail::Venmo,
            Rail::CashApp,
            Rail::Paypal,
            Rail::Zelle,
            Rail::Wise,
            Rail::Revolut,
            Rail::Monzo,
            Rail::Chime,
            Rail::Monobank,
            Rail::Alipay,
            Rail::Upi,
        ]
    }

    /// Check a handle against this rail's charset.
    ///
    /// Venmo's rule is the one the coordinator has always enforced: 2 to 30
    /// characters of letters, digits, underscore and hyphen. The other rails
    /// are not live, so they refuse rather than guess a rule they have never
    /// been tested against.
    pub fn validate_handle(&self, handle: &str) -> Result<(), String> {
        if !self.is_live() {
            return Err(format!(
                "{} is not live yet; Venmo is the only rail the curator registers payees for",
                self.label()
            ));
        }

        let handle = handle.trim().trim_start_matches('@');
        if handle.chars().count() < 2 {
            return Err(format!("{} handle is too short (minimum 2 characters)", self.label()));
        }
        if handle.chars().count() > 30 {
            return Err(format!("{} handle is too long (maximum 30 characters)", self.label()));
        }
        if !handle.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
            return Err(format!(
                "{} handle allows only letters, numbers, underscore and hyphen",
                self.label()
            ));
        }
        Ok(())
    }
}

impl std::str::FromStr for Rail {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim().to_ascii_lowercase();
        Rail::all()
            .iter()
            .copied()
            .find(|r| r.as_str() == s)
            .ok_or_else(|| format!("unknown rail {s:?}"))
    }
}

/// Who gets the dollars. One object on both backends, because both end in the
/// same enclave attestation over the same payment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayoutDestination {
    pub rail: Rail,
    /// The handle, without a leading `@`.
    pub handle: String,
}

impl PayoutDestination {
    pub fn new(rail: Rail, handle: impl Into<String>) -> Result<Self, String> {
        let handle = handle.into();
        let handle = handle.trim().trim_start_matches('@').to_string();
        rail.validate_handle(&handle)?;
        Ok(Self { rail, handle })
    }

    /// What the receipt line says: "@jane-doe's Venmo".
    pub fn describe(&self) -> String {
        format!("@{}'s {}", self.handle, self.rail.label())
    }
}

/// What the sender typed. The backend prices the other side.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "unit", rename_all = "lowercase")]
pub enum Amount {
    /// Zatoshi.
    Zec { zatoshi: u64 },
    /// Whole cents.
    Usd { cents: u64 },
}

/// One line of the net quote. Exactly one line per quote is the zpay fee, and
/// it is always labelled the same.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeLine {
    /// The label the sender reads, e.g. "zpay fee (0.15%)".
    pub label: String,
    /// Cents subtracted from the gross. Never negative: a line only ever takes.
    pub cents: u64,
    /// Whether this is the zpay fee itself, as opposed to a cost paid to
    /// someone else. The receipt highlights the zpay line.
    #[serde(default)]
    pub is_zpay_fee: bool,
}

/// The price the sender is shown, net.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Quote {
    pub quote_id: String,
    pub backend: BackendId,
    /// What the ZEC is worth before anything is taken, in cents.
    pub gross_cents: u64,
    /// Every deduction, one line each. One of them is the zpay fee.
    pub lines: Vec<FeeLine>,
    /// What lands in the recipient's account, in cents. This is the headline
    /// number and the only one the main route puts in large type.
    pub net_cents: u64,
    /// ZEC the sender sends, in zatoshi.
    pub zec_zatoshi: u64,
    /// Dollars per ZEC, for the details disclosure.
    pub rate: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// How long the whole thing normally takes.
    pub expected_seconds: u64,
    /// "via 1Click and zk-p2p" or "direct escrow".
    pub route_label: String,
}

impl Quote {
    /// The zpay fee line, which every quote carries.
    pub fn zpay_fee(&self) -> Option<&FeeLine> {
        self.lines.iter().find(|l| l.is_zpay_fee)
    }

    /// Check the arithmetic the sender is being shown actually adds up.
    ///
    /// A quote whose lines do not reconcile with its own net is a quote the
    /// contract and the page would disagree about, which is the failure the
    /// treasury spec's unit test exists to catch.
    pub fn reconciles(&self) -> bool {
        let deducted: u64 = self.lines.iter().map(|l| l.cents).sum();
        self.gross_cents.checked_sub(deducted) == Some(self.net_cents)
    }
}

/// Where the sender sends their ZEC, and how to render it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositInstruction {
    pub address: String,
    pub amount_zat: u64,
    /// A ZIP 321 `zcash:` URI with the address and amount filled in, so the
    /// sender's wallet opens with the payment prepared and no address is ever
    /// copied by hand.
    pub zip321_uri: String,
    /// A memo, when the backend needs one. 1Click's SIMPLE deposit mode does
    /// not, and a memo on a transparent output is not possible anyway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub kind: DepositKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DepositKind {
    /// A 1Click deposit address.
    Swap,
    /// A 2-of-2 CLTV P2SH escrow address.
    Escrow,
}

/// Something the sender's own client must do after funding.
///
/// Backend A returns an empty list. Backend B returns one step: the adaptor
/// pre-signature, which only the holder of `u_priv` can produce. Modelling the
/// leak explicitly is what keeps the front end from growing a backend switch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientStep {
    pub step_id: String,
    /// One plain sentence, shown only on the advanced route. The main route
    /// runs the step and shows a spinner.
    pub description: String,
    /// Opaque payload the client's WASM build needs to perform the step.
    pub payload: serde_json::Value,
}

/// What `POST /v2/orders` returns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Opened {
    pub order_id: uuid::Uuid,
    pub backend: BackendId,
    pub deposit: DepositInstruction,
    /// Hash over the terms the order was opened on, so a sender can check the
    /// order they are watching is the one they agreed to.
    pub terms_hash: String,
    #[serde(default)]
    pub client_steps: Vec<ClientStep>,
}

/// The canonical stages, in order. Backend-specific states map onto these, so
/// the ladder the sender reads is the same five steps on both routes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    AwaitingZec,
    ZecSeen,
    InEscrow,
    PaidOut,
    Done,
    Returning,
    Returned,
    Failed,
}

impl Stage {
    /// The plain words the main route shows. No session ids, no deposit ids, no
    /// transaction hashes: those live behind the details disclosure.
    pub fn plain(&self) -> &'static str {
        match self {
            Stage::AwaitingZec => "waiting for your ZEC",
            Stage::ZecSeen => "ZEC seen",
            Stage::InEscrow => "in escrow",
            Stage::PaidOut => "paid",
            Stage::Done => "done",
            Stage::Returning => "sending your ZEC back",
            Stage::Returned => "returned",
            Stage::Failed => "failed",
        }
    }

    /// The five rungs of the ladder, in the order they light up. The three
    /// return states are not rungs; they replace the ladder.
    pub fn ladder() -> &'static [Stage] {
        &[
            Stage::AwaitingZec,
            Stage::ZecSeen,
            Stage::InEscrow,
            Stage::PaidOut,
            Stage::Done,
        ]
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, Stage::Done | Stage::Returned | Stage::Failed)
    }

    /// How far up the ladder a stage sits.
    ///
    /// The keeper mirrors a session's status onto the order every tick, and the
    /// session spends one pass in `NearIntentPending` after promotion, which
    /// maps back to `AwaitingZec`. Without an ordering the status page would
    /// read "ZEC seen" and then "waiting for your ZEC" again, which tells a
    /// sender their money was un-received. Returns and failures are not rungs,
    /// so they carry no rank and replace the ladder outright.
    pub fn rank(&self) -> Option<u8> {
        match self {
            Stage::AwaitingZec => Some(0),
            Stage::ZecSeen => Some(1),
            Stage::InEscrow => Some(2),
            Stage::PaidOut => Some(3),
            Stage::Done => Some(4),
            Stage::Returning | Stage::Returned | Stage::Failed => None,
        }
    }

    /// The stage to show, given what the session reports and what the order has
    /// already shown. A rung never goes back down; anything off the ladder wins
    /// outright, because a return or a failure is news the sender needs.
    pub fn no_lower_than(self, already_shown: Stage) -> Stage {
        match (self.rank(), already_shown.rank()) {
            (Some(new), Some(old)) if new < old => already_shown,
            _ => self,
        }
    }
}

/// One stage with when it happened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub stage: Stage,
    pub at: chrono::DateTime<chrono::Utc>,
    /// An optional plain sentence for this stage, when there is something worth
    /// saying beyond the label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// The whole progress view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Timeline {
    pub stage: Stage,
    pub entries: Vec<TimelineEntry>,
    /// Raw identifiers, for the details disclosure and the advanced route only.
    #[serde(default)]
    pub details: Vec<(String, String)>,
}

/// What, if anything, is coming back, and in what form.
///
/// The failure screen is driven by this alone. `UsdcAt` is transient: the
/// page's only response to it is to sign the back-swap, and it is never shown
/// to the sender as something to collect. The states in which the screen asks a
/// question are `ZecAt` and `RefundableAtHeight`, and both answers are Zcash
/// addresses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ReturnState {
    /// Nothing is coming back.
    None,
    /// ZEC is sitting at an address the session key controls, waiting for the
    /// sender to name where it should go.
    ZecAt { address: String, zatoshi: u64 },
    /// USDC is at `session.user`. The page converts it before it asks anything.
    UsdcAt { address: String, units: String },
    /// A back-swap of returned USDC is in flight.
    ///
    /// Not built: nothing constructs this. See [`ClaimAuthorization`].
    SwappingBack {
        quote_id: String,
        expected_zat: u64,
        deadline: chrono::DateTime<chrono::Utc>,
    },
    /// The native escrow's CLTV refund is claimable at this height.
    RefundableAtHeight { height: u32 },
    /// The return already went where the sender asked.
    Settled { address: String, zatoshi: u64, txid: String },
}

impl ReturnState {
    /// Whether the failure screen should ask the sender for a Zcash address.
    pub fn asks_for_an_address(&self) -> bool {
        matches!(
            self,
            ReturnState::ZecAt { .. } | ReturnState::RefundableAtHeight { .. }
        )
    }
}

/// What the sender's key signs to claim a return. Which variant applies is
/// decided by [`ReturnState`], never by the caller.
///
/// Not built. Nothing in the coordinator constructs a value of this type and no
/// endpoint accepts one, so the failure screen's claim path cannot half-fire:
/// the page records the address the sender types and says the signing step is
/// still being built. The round 1 audit asked for that to be confirmed rather
/// than assumed, so it is stated here, next to the type, where the next person
/// to wire it up will read it.
///
/// Wiring it up means, at minimum: a `POST /v2/orders/{id}/claim` that verifies
/// the session key's signature over the claim scope, a `ReturnState` that
/// actually reaches `ZecAt` on a real refund, and a funded test of each variant
/// separately. `SwappingBack` and the `Eip3009` variant additionally depend on
/// the shielded refund path, which is proven only at the 1Click API and has
/// never been watched land on chain (U1-5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ClaimAuthorization {
    /// A fully signed transparent spend to the address the sender named.
    TransparentSpend { raw_tx_hex: String },
    /// A signed EIP-3009 authorization moving the returned USDC to a 1Click
    /// deposit address, for the keeper to relay. The authorization names the
    /// deposit address and the quote names the recipient, so a relay holding it
    /// cannot send the USDC anywhere else.
    Eip3009 {
        quote_id: String,
        from: String,
        to: String,
        value: String,
        valid_after: u64,
        valid_before: u64,
        nonce: String,
        signature: String,
    },
    /// A signed CLTV refund transaction for the native escrow.
    EscrowRefund { raw_tx_hex: String },
}

/// What a return claim produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    pub order_id: uuid::Uuid,
    /// Where the value ended up, in the sender's terms.
    pub destination: String,
    /// The transaction that put it there, when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub txid: Option<String>,
    pub at: chrono::DateTime<chrono::Utc>,
}

/// What a backend can do, so the front end can refuse impossible orders before
/// it spends a round trip on them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    pub backend: BackendId,
    pub rails: Vec<Rail>,
    /// Smallest and largest ZEC this backend will take, in zatoshi.
    pub min_zatoshi: u64,
    pub max_zatoshi: u64,
    /// How long a quote stays good.
    pub quote_ttl_seconds: u64,
    /// The time estimate shown next to the quote.
    pub expected_seconds: u64,
}

/// The advanced route's escape hatches. The main route leaves every field
/// unset; both routes go through the same `OpenRequest`, so an order opened on
/// either produces the same on-chain artefacts for the same inputs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Overrides {
    /// Name a backend instead of letting the coordinator pick.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<BackendId>,
    /// The sender's own Zcash address as the refund destination, rather than
    /// the session key's. Accepts anything 1Click accepts, which as of
    /// 2026-09-02 includes unified addresses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refund_address: Option<String>,
    /// zk-p2p `minConversionRate`, 18 decimals, as a decimal string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_rate: Option<String>,
    /// How long to wait for a fill before returning the funds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fill_budget_seconds: Option<u64>,
}

/// What `POST /v2/orders` takes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenRequest {
    pub quote_id: String,
    pub destination: PayoutDestination,
    /// 33 bytes of compressed secp256k1, hex. Backend A derives the EVM address
    /// from it and uses that as `session.user`; backend B uses it as `u_pub`.
    /// The advanced route passes the sender's own wallet key here instead.
    pub session_pubkey: String,
    #[serde(default)]
    pub overrides: Overrides,
}

/// What `GET /v2/orders/{id}` returns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderView {
    pub order_id: uuid::Uuid,
    pub backend: BackendId,
    pub destination: PayoutDestination,
    pub timeline: Timeline,
    pub returns: ReturnState,
    /// The quote the order was opened on, so the receipt can show the fee.
    pub quote: Quote,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deposit: Option<DepositInstruction>,
    #[serde(default)]
    pub client_steps: Vec<ClientStep>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_handle_keeps_no_leading_sigil() {
        let d = PayoutDestination::new(Rail::Venmo, "@jane-doe").unwrap();
        assert_eq!(d.handle, "jane-doe");
        assert_eq!(d.describe(), "@jane-doe's Venmo");
    }

    #[test]
    fn venmo_handles_follow_the_rule_the_coordinator_has_always_enforced() {
        assert!(Rail::Venmo.validate_handle("jane-doe").is_ok());
        assert!(Rail::Venmo.validate_handle("a").is_err());
        assert!(Rail::Venmo.validate_handle(&"a".repeat(31)).is_err());
        assert!(Rail::Venmo.validate_handle("jane doe").is_err());
        assert!(Rail::Venmo.validate_handle("jane.doe").is_err());
    }

    /// The picker shows eleven rails and opens orders on one. A rail the
    /// curator cannot register a payee for must refuse rather than guess.
    #[test]
    fn only_venmo_is_live() {
        assert_eq!(Rail::all().len(), 11);
        assert_eq!(Rail::all().iter().filter(|r| r.is_live()).count(), 1);
        assert!(Rail::CashApp.validate_handle("anything").is_err());
    }

    #[test]
    fn backend_ids_round_trip_through_their_wire_names() {
        for b in [BackendId::OneclickZkp2p, BackendId::NativeEscrow] {
            assert_eq!(b.as_str().parse::<BackendId>().unwrap(), b);
        }
        assert!("something-else".parse::<BackendId>().is_err());
    }

    #[test]
    fn rails_round_trip_through_their_wire_names() {
        for r in Rail::all() {
            assert_eq!(r.as_str().parse::<Rail>().unwrap(), *r);
        }
    }

    /// A quote the page and the contract would disagree about is the failure
    /// the fee arithmetic has to rule out.
    #[test]
    fn a_quote_has_to_reconcile() {
        let mut q = Quote {
            quote_id: "q1".into(),
            backend: BackendId::OneclickZkp2p,
            gross_cents: 2500,
            lines: vec![
                FeeLine { label: "zpay fee (0.15%)".into(), cents: 4, is_zpay_fee: true },
                FeeLine { label: "network and spread".into(), cents: 80, is_zpay_fee: false },
            ],
            net_cents: 2416,
            zec_zatoshi: 50_000_000,
            rate: "50.00".into(),
            expires_at: chrono::Utc::now(),
            expected_seconds: 1200,
            route_label: BackendId::OneclickZkp2p.route_label().into(),
        };
        assert!(q.reconciles());
        assert_eq!(q.zpay_fee().unwrap().cents, 4);

        q.net_cents = 2500;
        assert!(!q.reconciles(), "a net that ignores its own fee lines must not pass");
    }

    /// The failure screen asks a question in exactly two states, and both
    /// answers are Zcash addresses. USDC is never one of them.
    #[test]
    fn only_zec_states_ask_the_sender_anything() {
        assert!(ReturnState::ZecAt { address: "t1x".into(), zatoshi: 1 }.asks_for_an_address());
        assert!(ReturnState::RefundableAtHeight { height: 9 }.asks_for_an_address());

        assert!(!ReturnState::None.asks_for_an_address());
        assert!(
            !ReturnState::UsdcAt { address: "0x1".into(), units: "5".into() }.asks_for_an_address(),
            "USDC is converted, never offered to the sender to collect"
        );
        assert!(!ReturnState::SwappingBack {
            quote_id: "q".into(),
            expected_zat: 1,
            deadline: chrono::Utc::now()
        }
        .asks_for_an_address());
    }

    #[test]
    fn the_ladder_is_five_rungs_and_the_return_states_are_not_among_them() {
        assert_eq!(Stage::ladder().len(), 5);
        for s in [Stage::Returning, Stage::Returned, Stage::Failed] {
            assert!(!Stage::ladder().contains(&s));
        }
    }
}

#[cfg(test)]
mod stage_order_tests {
    use super::*;

    /// U1-1, second part. A session spends one pass in `NearIntentPending`
    /// after promotion, which maps back to `AwaitingZec`, while the order
    /// already reads `ZecSeen`. Mirroring that raw told the sender their ZEC
    /// had been un-received.
    #[test]
    fn a_rung_never_goes_back_down() {
        assert_eq!(
            Stage::AwaitingZec.no_lower_than(Stage::ZecSeen),
            Stage::ZecSeen
        );
        assert_eq!(Stage::ZecSeen.no_lower_than(Stage::PaidOut), Stage::PaidOut);
        assert_eq!(Stage::AwaitingZec.no_lower_than(Stage::Done), Stage::Done);
    }

    /// Forward movement is what the ladder is for.
    #[test]
    fn a_higher_rung_wins() {
        assert_eq!(Stage::ZecSeen.no_lower_than(Stage::AwaitingZec), Stage::ZecSeen);
        assert_eq!(Stage::Done.no_lower_than(Stage::PaidOut), Stage::Done);
        assert_eq!(Stage::InEscrow.no_lower_than(Stage::InEscrow), Stage::InEscrow);
    }

    /// A return or a failure is news, not a rung, so it replaces whatever was
    /// showing. Suppressing it would leave a sender watching a ladder while
    /// their money came back.
    #[test]
    fn leaving_the_ladder_always_wins() {
        for off in [Stage::Returning, Stage::Returned, Stage::Failed] {
            for shown in Stage::ladder() {
                assert_eq!(
                    off.no_lower_than(*shown),
                    off,
                    "{off:?} must replace {shown:?}"
                );
            }
        }
    }

    /// And once off the ladder, a rung does not put it back.
    #[test]
    fn a_rung_does_not_undo_a_failure() {
        assert_eq!(Stage::AwaitingZec.no_lower_than(Stage::Failed), Stage::AwaitingZec);
    }

    /// The five rungs are ordered, and the three off-ladder states are not.
    #[test]
    fn exactly_the_ladder_has_a_rank() {
        for s in Stage::ladder() {
            assert!(s.rank().is_some(), "{s:?} is a rung and needs a rank");
        }
        for s in [Stage::Returning, Stage::Returned, Stage::Failed] {
            assert!(s.rank().is_none(), "{s:?} is not a rung");
        }
    }
}

//! Offramp session types and state machine

use alloy::primitives::{Address, B256, U256};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Offramp session status state machine
///
/// ```text
/// Created → NearIntentPending → UsdcReceived → Zkp2pDeposited → IntentSignaled → Fulfilled
///                                    ↓                              ↓
///                                 Failed                         Failed
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OfframpStatus {
    /// Session created, waiting for NEAR Intent to be initiated
    Created,
    /// NEAR Intent initiated, waiting for ZEC deposit
    NearIntentPending,
    /// USDC received at GlueContract
    UsdcReceived,
    /// USDC deposited to zk-p2p escrow
    Zkp2pDeposited,
    /// Taker has signaled intent to fulfill
    IntentSignaled,
    /// Offramp complete - user received Venmo payment
    Fulfilled,
    /// Offramp failed at some stage
    Failed,
    /// User rescued funds from GlueContract
    Rescued,
    /// User withdrew from zk-p2p deposit
    Withdrawn,
}

impl std::fmt::Display for OfframpStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OfframpStatus::Created => write!(f, "created"),
            OfframpStatus::NearIntentPending => write!(f, "near_intent_pending"),
            OfframpStatus::UsdcReceived => write!(f, "usdc_received"),
            OfframpStatus::Zkp2pDeposited => write!(f, "zkp2p_deposited"),
            OfframpStatus::IntentSignaled => write!(f, "intent_signaled"),
            OfframpStatus::Fulfilled => write!(f, "fulfilled"),
            OfframpStatus::Failed => write!(f, "failed"),
            OfframpStatus::Rescued => write!(f, "rescued"),
            OfframpStatus::Withdrawn => write!(f, "withdrawn"),
        }
    }
}

/// Request to initiate a new offramp
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfframpRequest {
    /// Amount of ZEC to offramp (in zatoshi, 1 ZEC = 100_000_000 zatoshi)
    pub zec_amount: u64,
    /// Venmo username (without @)
    pub venmo_username: String,
    /// User's Base address for rescue/withdraw
    pub user_address: Address,
    /// Address the user expects to take this offramp, if they arranged one.
    ///
    /// Advisory only. The deposit is created with `intentGatingService`
    /// set to `address(0)`, so zk-p2p lets any staked taker signal on it and
    /// enforces nothing about this field. It is recorded so an offramp made
    /// with a taker in mind can still say who that was.
    #[serde(default)]
    pub taker_address: Option<Address>,
    /// User's Zcash address for refunds (t1/t3/zs prefix)
    /// If the NEAR Intent fails, ZEC is refunded here
    pub zec_refund_address: String,
    /// Minimum USD per USDC the zk-p2p taker must pay, 18-decimal precision
    /// (zk-p2p `Currency.minConversionRate`). 1e18 = 1 USD per USDC.
    /// The ZEC to USDC leg is priced by the NEAR Intents quote, not by this.
    pub min_rate: U256,
    /// The exact dollars the taker must send on Venmo, in whole cents.
    ///
    /// When set, the deposit's intent range is pinned to the size that prices to
    /// exactly this many cents at `min_rate`, and the taker's payment is that
    /// number rather than a function of whatever the swap delivered. The spread
    /// and the curator's fee are added on top of it by making the intent larger,
    /// never by paying less than this.
    ///
    /// The 2026-09-01 fill left this unset. Its intent was the whole swap output
    /// of 4,875,437 units, which at rate 0.990881148896019200 priced to $4.84
    /// against a $5.00 request.
    ///
    /// Unset keeps the old behaviour: one intent for the entire credited amount.
    #[serde(default)]
    pub target_payment_cents: Option<u64>,
    /// Timeout for NEAR settlement in seconds (default: 600)
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
}

fn default_timeout() -> u64 {
    600
}

/// Offramp session tracking all state for a single offramp operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfframpSession {
    /// Unique session identifier
    pub id: Uuid,
    /// On-chain session ID (keccak256 of UUID)
    pub session_id: B256,
    /// Current status
    pub status: OfframpStatus,
    /// Original request parameters
    pub request: OfframpRequest,
    /// zk-p2p payee details hash for the Venmo username.
    ///
    /// This is the `hashedOnchainId` issued by the zk-p2p curator API when the
    /// username is registered (`POST /v2/makers/create`). It is stored in
    /// `DepositPaymentMethodData.payeeDetails` and the attestation witness
    /// matches it against the taker's Venmo payment proof, so it cannot be
    /// computed locally.
    pub payee_details_hash: B256,
    /// Expected USDC amount from NEAR Intent (6 decimals)
    pub expected_usdc: Option<U256>,
    /// Floor 1Click guarantees for this swap (6 decimals), from the quote's
    /// `minAmountOut`. The keeper waits for at least this much unassigned USDC
    /// on the glue before it credits the session, so a session is never
    /// promoted on someone else's smaller delivery.
    #[serde(default)]
    pub min_output_usdc: Option<U256>,
    /// Actual USDC received
    pub received_usdc: Option<U256>,
    /// NEAR Intent deposit address (for ZEC)
    pub near_deposit_address: Option<String>,
    /// NEAR Intent transaction hash
    pub near_tx_hash: Option<String>,
    /// zk-p2p deposit ID (set after processOfframp)
    pub zkp2p_deposit_id: Option<U256>,
    /// zk-p2p intent hash (set after taker signals)
    pub zkp2p_intent_hash: Option<B256>,
    /// GlueContract transaction hash (createSession)
    pub create_session_tx: Option<B256>,
    /// GlueContract transaction hash (processOfframp)
    pub process_offramp_tx: Option<B256>,
    /// Error message if failed
    pub error: Option<String>,
    /// Session creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
}

impl OfframpSession {
    /// Create a new offramp session from a request and the curator-issued
    /// payee details hash for `request.venmo_username`
    pub fn new(request: OfframpRequest, payee_details_hash: B256) -> Self {
        let id = Uuid::new_v4();
        let session_id = Self::compute_session_id(&id);
        let now = Utc::now();

        Self {
            id,
            session_id,
            status: OfframpStatus::Created,
            request,
            payee_details_hash,
            expected_usdc: None,
            min_output_usdc: None,
            received_usdc: None,
            near_deposit_address: None,
            near_tx_hash: None,
            zkp2p_deposit_id: None,
            zkp2p_intent_hash: None,
            create_session_tx: None,
            process_offramp_tx: None,
            error: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Compute on-chain session ID from UUID
    pub fn compute_session_id(id: &Uuid) -> B256 {
        use alloy::primitives::keccak256;
        keccak256(id.as_bytes())
    }

    /// Update status and timestamp
    pub fn set_status(&mut self, status: OfframpStatus) {
        self.status = status;
        self.updated_at = Utc::now();
    }

    /// Mark as failed with error message
    pub fn fail(&mut self, error: impl Into<String>) {
        self.status = OfframpStatus::Failed;
        self.error = Some(error.into());
        self.updated_at = Utc::now();
    }

    /// Check if session is in a terminal state
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.status,
            OfframpStatus::Fulfilled
                | OfframpStatus::Failed
                | OfframpStatus::Rescued
                | OfframpStatus::Withdrawn
        )
    }
}

/// Response from coordinator for offramp initiation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfframpResponse {
    /// Session ID (UUID)
    pub session_id: Uuid,
    /// Current status
    pub status: OfframpStatus,
    /// NEAR deposit address for ZEC (if available)
    pub near_deposit_address: Option<String>,
    /// Expected USDC amount (if quoted)
    pub expected_usdc: Option<String>,
    /// Error message if any
    pub error: Option<String>,
}

impl From<&OfframpSession> for OfframpResponse {
    fn from(session: &OfframpSession) -> Self {
        Self {
            session_id: session.id,
            status: session.status,
            near_deposit_address: session.near_deposit_address.clone(),
            expected_usdc: session.expected_usdc.map(|u| u.to_string()),
            error: session.error.clone(),
        }
    }
}

/// Quote response for ZEC → Venmo conversion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteResponse {
    /// Input amount in ZEC
    pub zec_amount: String,
    /// Expected USDC output (after NEAR Intent)
    pub usdc_amount: String,
    /// Expected USD to Venmo (after fees)
    pub venmo_amount: String,
    /// Effective conversion rate (USDC per ZEC)
    pub rate: String,
    /// Quote expiry timestamp
    pub expires_at: DateTime<Utc>,
}

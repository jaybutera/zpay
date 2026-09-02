//! The enclave's `encodedPaymentDetails`, decoded and checked against the
//! escrow's terms.
//!
//! Phase 0 decoded this blob as 14 ABI words (spec 12.1). Until now the
//! attestor checked only that `keccak256` of it equalled the signed `dataHash`,
//! which proves the enclave signed *these bytes* and nothing about what the
//! bytes say. That is the whole hole: the enclave signs whatever payment the
//! caller proved, so an LP could prove a payment to its own Venmo, at a rate it
//! chose, made a month before the escrow existed, and every check still passed.
//!
//! The signed `intentHash` binds the *intent*, not the payment. These fields
//! bind the payment.

use sha3::{Digest, Keccak256};

/// `keccak256("venmo")`, the `paymentMethod` word. Matches the constant the
/// existing prover sends as `paymentMethod`.
pub const VENMO_PAYMENT_METHOD: [u8; 32] = [
    0x90, 0x26, 0x2a, 0x3d, 0xb0, 0xed, 0xd0, 0xbe, 0x23, 0x69, 0xc6, 0xb2, 0x8f, 0x9e, 0x85, 0x11,
    0xec, 0x0b, 0xac, 0x71, 0x36, 0xce, 0xfb, 0xad, 0xa0, 0x88, 0x06, 0x02, 0xf8, 0x7e, 0x72, 0x68,
];

/// The `fiatCurrency` word seen on both captured attestations.
pub const USD_FIAT_CURRENCY: [u8; 32] = [
    0xc4, 0xae, 0x21, 0xaa, 0xc0, 0xc6, 0x54, 0x9d, 0x71, 0xdd, 0x96, 0x03, 0x5b, 0x7e, 0x0b, 0xdb,
    0x6c, 0x79, 0xeb, 0xdb, 0xa8, 0x89, 0x1b, 0x66, 0x61, 0x15, 0xbc, 0x97, 0x6d, 0x16, 0xa2, 0x9e,
];

/// The number of 32-byte words in the blob.
pub const WORD_COUNT: usize = 14;

/// How far before the observed lock time a payment may be timestamped.
///
/// Ten minutes. Venmo's clock and the prover's snapshot are different clocks:
/// the captured 1.00 USD attestation carries a payment timestamped 155 seconds
/// before its own intent timestamp. This covers that skew with room to spare
/// and rejects anything older, including the month-old payment the review used
/// to demonstrate the hole.
pub const BACKDATE_TOLERANCE_MS: u64 = 10 * 60 * 1000;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PaymentDetailsError {
    #[error("encodedPaymentDetails is {0} bytes, expected {expected}", expected = WORD_COUNT * 32)]
    WrongLength(usize),
    #[error("payment method is not Venmo")]
    WrongPaymentMethod,
    #[error("fiat currency is not the expected one")]
    WrongFiatCurrency,
    #[error("the payment was sent to {got}, not the user's {expected}")]
    WrongPayee { got: String, expected: String },
    #[error("the signed intent hash in the payment details is {got}, expected {expected}")]
    IntentMismatch { got: String, expected: String },
    #[error("the payment details say {got} was released, the terms require {expected}")]
    AmountMismatch { got: u128, expected: u128 },
    #[error("conversion rate is {got}, the terms quoted {expected}")]
    RateMismatch { got: u128, expected: u128 },
    #[error(
        "the payment is timestamped {payment_ms} ms, more than {tolerance_ms} ms before the \
         escrow was confirmed at {lock_confirmed_ms} ms; a payment that predates the lock \
         cannot be for this escrow"
    )]
    PaymentPredatesLock {
        payment_ms: u64,
        lock_confirmed_ms: u64,
        tolerance_ms: u64,
    },
    #[error("the payment is timestamped {payment_ms} ms, more than {window_ms} ms after the lock")]
    PaymentTooLate { payment_ms: u64, window_ms: u64 },
    #[error("the two copies of {field} inside the payment details disagree")]
    InternalDisagreement { field: &'static str },
}

/// The 14 words of spec 12.1, named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentDetails {
    pub payment_method: [u8; 32],
    pub payee_details: [u8; 32],
    pub payment_index: u128,
    pub fiat_currency: [u8; 32],
    /// Word 4: when the payment happened, in milliseconds.
    pub payment_timestamp_ms: u64,
    pub payment_digest: [u8; 32],
    pub intent_hash: [u8; 32],
    pub release_amount: u128,
    /// Words 8 to 10 repeat the method, currency and payee.
    pub payment_method_2: [u8; 32],
    pub fiat_currency_2: [u8; 32],
    pub payee_details_2: [u8; 32],
    pub conversion_rate: u128,
    /// Word 12: the intent timestamp in seconds.
    pub intent_timestamp_s: u64,
    /// Word 13: a validity window in seconds; 1209600 (14 days) on both
    /// captured attestations.
    pub window_s: u64,
}

fn word(blob: &[u8], i: usize) -> [u8; 32] {
    let mut w = [0u8; 32];
    w.copy_from_slice(&blob[i * 32..(i + 1) * 32]);
    w
}

fn word_u128(blob: &[u8], i: usize) -> u128 {
    let w = word(blob, i);
    // The high 16 bytes must be zero for the value to fit; every quantity here
    // is an amount, a rate or a timestamp, none of which legitimately exceeds
    // 2^128.
    u128::from_be_bytes(w[16..].try_into().expect("16 bytes"))
}

impl PaymentDetails {
    pub fn decode(blob: &[u8]) -> Result<Self, PaymentDetailsError> {
        if blob.len() != WORD_COUNT * 32 {
            return Err(PaymentDetailsError::WrongLength(blob.len()));
        }
        Ok(Self {
            payment_method: word(blob, 0),
            payee_details: word(blob, 1),
            payment_index: word_u128(blob, 2),
            fiat_currency: word(blob, 3),
            payment_timestamp_ms: word_u128(blob, 4) as u64,
            payment_digest: word(blob, 5),
            intent_hash: word(blob, 6),
            release_amount: word_u128(blob, 7),
            payment_method_2: word(blob, 8),
            fiat_currency_2: word(blob, 9),
            payee_details_2: word(blob, 10),
            conversion_rate: word_u128(blob, 11),
            intent_timestamp_s: word_u128(blob, 12) as u64,
            window_s: word_u128(blob, 13) as u64,
        })
    }

    /// What the attestor requires of the payment before it will sign.
    ///
    /// `expected_rate` is optional because the semantics of word 11 are not yet
    /// settled: see `RatePolicy`.
    pub fn check_against_terms(
        &self,
        expected_intent_hash: &[u8; 32],
        expected_payee_hash: &[u8; 32],
        minimum_release_amount: u128,
        lock_confirmed_ms: u64,
        rate: &RatePolicy,
    ) -> Result<(), PaymentDetailsError> {
        // The blob repeats method, currency and payee. If the two copies ever
        // disagree, the blob is not one the enclave produced from a single
        // payment, and nothing further should be trusted.
        if self.payment_method != self.payment_method_2 {
            return Err(PaymentDetailsError::InternalDisagreement {
                field: "paymentMethod",
            });
        }
        if self.fiat_currency != self.fiat_currency_2 {
            return Err(PaymentDetailsError::InternalDisagreement {
                field: "fiatCurrency",
            });
        }
        if self.payee_details != self.payee_details_2 {
            return Err(PaymentDetailsError::InternalDisagreement {
                field: "payeeDetails",
            });
        }

        if self.payment_method != VENMO_PAYMENT_METHOD {
            return Err(PaymentDetailsError::WrongPaymentMethod);
        }
        if self.fiat_currency != USD_FIAT_CURRENCY {
            return Err(PaymentDetailsError::WrongFiatCurrency);
        }

        // The check that closes the hole: the money must have gone to the
        // user's Venmo, not to an account the LP controls.
        if &self.payee_details != expected_payee_hash {
            return Err(PaymentDetailsError::WrongPayee {
                got: hex::encode(self.payee_details),
                expected: hex::encode(expected_payee_hash),
            });
        }

        if &self.intent_hash != expected_intent_hash {
            return Err(PaymentDetailsError::IntentMismatch {
                got: hex::encode(self.intent_hash),
                expected: hex::encode(expected_intent_hash),
            });
        }
        if self.release_amount < minimum_release_amount {
            return Err(PaymentDetailsError::AmountMismatch {
                got: self.release_amount,
                expected: minimum_release_amount,
            });
        }

        // A payment made long before the escrow was confirmed cannot be a
        // payment for this escrow. The enclave only matches payments at or
        // after its snapshot, but the snapshot is a value the LP supplies, so
        // the attestor checks it against the lock time it observed itself.
        //
        // The tolerance is not slack for its own sake. On the captured 1.00 USD
        // attestation the payment is timestamped 155 s *before* the intent
        // timestamp, because Venmo's own clock and the prover's snapshot are
        // not the same clock. A strict comparison would reject genuine
        // attestations, so the window is wide enough to cover that skew and far
        // too narrow to admit the month-old payment of the review PoC.
        let earliest = lock_confirmed_ms.saturating_sub(BACKDATE_TOLERANCE_MS);
        if self.payment_timestamp_ms < earliest {
            return Err(PaymentDetailsError::PaymentPredatesLock {
                payment_ms: self.payment_timestamp_ms,
                lock_confirmed_ms,
                tolerance_ms: BACKDATE_TOLERANCE_MS,
            });
        }
        let window_ms = self.window_s.saturating_mul(1000);
        if window_ms > 0
            && self.payment_timestamp_ms.saturating_sub(lock_confirmed_ms) > window_ms
        {
            return Err(PaymentDetailsError::PaymentTooLate {
                payment_ms: self.payment_timestamp_ms,
                window_ms,
            });
        }

        rate.check(self.conversion_rate)?;
        Ok(())
    }
}

/// What word 11, `conversionRate`, must equal.
///
/// Finding 6 in review round 1: the LP passes `INTENT_RATE` to the prover as
/// USD per ZEC, and the enclave records it as `conversionRate` without
/// interpreting it. On the captured $4.87 attestation the value was
/// `990881148896019200`, which is 0.99 in 18 decimals - that is dollars per
/// *USDC-like unit*, not dollars per ZEC, because that fill was a USDC fill.
///
/// So the correct value for a ZEC escrow is not established by anything we have
/// captured, and guessing it would be worse than admitting it. The policy is
/// therefore explicit:
///
/// - `Exact` is what a production ZEC escrow must use once the semantics are
///   settled: the attestor requires the rate the terms quoted, so an LP cannot
///   claim a $100 escrow with a payment its own rate makes look sufficient.
/// - `Unenforced` is the development stance, and it is recorded in the spec as
///   an open item rather than left implicit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RatePolicy {
    Exact(u128),
    /// Requires the rate to be at least this, which is the direction that
    /// protects the user when higher means more dollars per ZEC.
    AtLeast(u128),
    Unenforced,
}

impl RatePolicy {
    fn check(&self, got: u128) -> Result<(), PaymentDetailsError> {
        match self {
            RatePolicy::Exact(expected) if got != *expected => {
                Err(PaymentDetailsError::RateMismatch {
                    got,
                    expected: *expected,
                })
            }
            RatePolicy::AtLeast(expected) if got < *expected => {
                Err(PaymentDetailsError::RateMismatch {
                    got,
                    expected: *expected,
                })
            }
            _ => Ok(()),
        }
    }
}

/// A payment's identity, for the nullifier set of finding 5.
///
/// One Venmo payment must release at most one escrow. The pair of the payment's
/// own digest and its index is what the enclave reports per payment; hashing
/// them together with the payee and timestamp gives a value that is stable for
/// one payment and different for any other.
pub fn payment_nullifier(details: &PaymentDetails) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(b"zecp2p-payment-nullifier-v1");
    h.update(details.payment_digest);
    h.update(details.payee_details);
    h.update(details.payment_index.to_be_bytes());
    h.update(details.payment_timestamp_ms.to_be_bytes());
    h.finalize().into()
}

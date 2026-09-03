//! The quote ids `/v2/quote` has issued, and which of them have been spent.
//!
//! U1-2. A quote id used to be nothing but an amount carrier: `open_order`
//! split the zatoshi off it and re-quoted, so a caller could invent one the
//! coordinator had never issued and it was accepted, and a caller could replay
//! one signature as many times as they liked. Thirty-one orders came out of one
//! signature during the audit.
//!
//! Making the id real fixes both. It is issued here, it is checked here, and it
//! is spent here. Because the signature's scope contains the quote id, a
//! single-use id makes the signature single-use too, which is the property the
//! audit found missing; no separate nonce is needed.
//!
//! This is in memory rather than in the database on purpose. A quote is valid
//! for `QUOTE_TTL_SECONDS`, which is shorter than any restart window worth
//! designing around, and a coordinator that has just restarted holding no
//! quotes refuses opens against pre-restart quotes. That is the safe direction
//! to fail: the sender re-prices and opens again, and nothing has been funded.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use tokio::sync::Mutex;

/// One issued quote, and whether an order has been opened against it.
#[derive(Debug, Clone)]
struct Issued {
    zatoshi: u64,
    expires_at: DateTime<Utc>,
    spent: bool,
}

/// Why an open was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuoteError {
    /// No such id was ever issued, or it has aged out of the registry.
    Unknown,
    /// The price it was issued at has expired.
    Expired,
    /// An order has already been opened against it.
    AlreadyUsed,
}

impl QuoteError {
    pub fn message(self) -> &'static str {
        match self {
            QuoteError::Unknown => {
                "that price is not one this coordinator issued. Ask for a new one."
            }
            QuoteError::Expired => "that price has expired. Ask for a new one.",
            QuoteError::AlreadyUsed => {
                "an order has already been opened at that price. Ask for a new one."
            }
        }
    }
}

/// How long a spent or expired id is kept after it stops being usable.
///
/// Forgetting it the moment it is spent would make a replay indistinguishable
/// from a made-up id, and "already used" is the more useful thing to tell a
/// caller than "unknown". Keeping it a while also means a retry from a flaky
/// client gets the true reason.
const REMEMBER_AFTER_EXPIRY: chrono::Duration = chrono::Duration::minutes(30);

/// Ids the coordinator has handed out, and their state.
#[derive(Default)]
pub struct QuoteRegistry {
    issued: Mutex<HashMap<String, Issued>>,
}

impl QuoteRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an id `/v2/quote` is about to return.
    pub async fn issue(&self, id: &str, zatoshi: u64, expires_at: DateTime<Utc>) {
        let mut issued = self.issued.lock().await;
        Self::forget_the_stale(&mut issued);
        issued.insert(
            id.to_string(),
            Issued {
                zatoshi,
                expires_at,
                spent: false,
            },
        );
    }

    /// Spend an id, returning the ZEC amount it was issued for.
    ///
    /// One caller wins: the check and the mark happen under the same lock, so
    /// two requests racing the same id cannot both open an order.
    pub async fn spend(&self, id: &str) -> Result<u64, QuoteError> {
        let mut issued = self.issued.lock().await;
        let entry = issued.get_mut(id).ok_or(QuoteError::Unknown)?;

        if entry.spent {
            return Err(QuoteError::AlreadyUsed);
        }
        if Utc::now() > entry.expires_at {
            return Err(QuoteError::Expired);
        }

        entry.spent = true;
        Ok(entry.zatoshi)
    }

    /// How many ids are being tracked. The registry is bounded by the quote
    /// rate times the TTL, and this is what a test asserts against.
    pub async fn tracked(&self) -> usize {
        self.issued.lock().await.len()
    }

    fn forget_the_stale(issued: &mut HashMap<String, Issued>) {
        let cutoff = Utc::now() - REMEMBER_AFTER_EXPIRY;
        issued.retain(|_, e| e.expires_at > cutoff);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn soon() -> DateTime<Utc> {
        Utc::now() + chrono::Duration::minutes(5)
    }

    #[tokio::test]
    async fn an_issued_id_can_be_spent_exactly_once() {
        let reg = QuoteRegistry::new();
        reg.issue("q1", 132_000, soon()).await;

        assert_eq!(reg.spend("q1").await.unwrap(), 132_000);
        assert_eq!(reg.spend("q1").await, Err(QuoteError::AlreadyUsed));
        assert_eq!(reg.spend("q1").await, Err(QuoteError::AlreadyUsed));
    }

    /// The audit opened 31 orders from one signature, and one from a `quote_id`
    /// the coordinator had never issued. Both are this test.
    #[test]
    fn a_quote_id_that_was_never_issued_is_refused() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let reg = QuoteRegistry::new();
            assert_eq!(
                reg.spend("00000000-0000-0000-0000-000000000000@132000").await,
                Err(QuoteError::Unknown)
            );
        });
    }

    #[tokio::test]
    async fn a_price_that_has_expired_cannot_be_opened_against() {
        let reg = QuoteRegistry::new();
        reg.issue("old", 132_000, Utc::now() - chrono::Duration::seconds(1))
            .await;
        assert_eq!(reg.spend("old").await, Err(QuoteError::Expired));
    }

    /// The registry must not grow without bound, or it is the same denial of
    /// service in a different place.
    #[tokio::test]
    async fn ids_far_past_their_expiry_are_forgotten() {
        let reg = QuoteRegistry::new();
        let long_ago = Utc::now() - chrono::Duration::hours(2);
        for i in 0..100 {
            reg.issue(&format!("stale{i}"), 132_000, long_ago).await;
        }
        assert_eq!(reg.tracked().await, 1, "each issue sweeps the previous ones");

        reg.issue("fresh", 132_000, soon()).await;
        assert!(reg.spend("fresh").await.is_ok());
    }

    /// Two requests racing the same id: exactly one may win, because otherwise
    /// the single-use property is only true when nobody tries.
    #[tokio::test]
    async fn two_racing_spends_produce_one_winner() {
        let reg = std::sync::Arc::new(QuoteRegistry::new());
        reg.issue("race", 132_000, soon()).await;

        let mut set = tokio::task::JoinSet::new();
        for _ in 0..16 {
            let reg = reg.clone();
            set.spawn(async move { reg.spend("race").await });
        }

        let mut winners = 0;
        while let Some(r) = set.join_next().await {
            if r.unwrap().is_ok() {
                winners += 1;
            }
        }
        assert_eq!(winners, 1);
    }
}

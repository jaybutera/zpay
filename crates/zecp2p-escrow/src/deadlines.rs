//! Heights and deadlines, spec section 3 and section 7.
//!
//! Criterion 13 requires that every height in a run be derived from
//! `BLOCK_SECONDS` and `REFUND_DELAY` rather than hard-coded, and that the same
//! binary pass on testnet with a different `REFUND_DELAY`. So the policy is a
//! value, not a constant, and the deadlines are computed from it.

/// Mainnet block time today. NU7 proposes 25 s, which is why this is a
/// parameter: at 25 s the same wall-clock refund window is three times the
/// block count.
pub const MAINNET_BLOCK_SECONDS: u32 = 75;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EscrowPolicy {
    pub block_seconds: u32,
    /// `T = lock_height + refund_delay_blocks`.
    pub refund_delay_blocks: u32,
    /// The LP must not send Venmo at or after `T - pay_deadline_blocks`.
    pub pay_deadline_blocks: u32,
    /// The release must be broadcast by `T - broadcast_deadline_blocks`.
    pub broadcast_deadline_blocks: u32,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("block_seconds must be greater than zero")]
    ZeroBlockTime,
    #[error("refund_delay_blocks ({delay}) must exceed pay_deadline_blocks ({pay})")]
    DelayTooShort { delay: u32, pay: u32 },
    #[error(
        "pay_deadline_blocks ({pay}) must be at least broadcast_deadline_blocks ({broadcast}), \
         or the LP would be told to pay after the point it must already have broadcast"
    )]
    DeadlinesInverted { pay: u32, broadcast: u32 },
}

impl EscrowPolicy {
    /// The mainnet defaults of spec section 3: 24 hours of refund delay, with
    /// the LP barred from paying inside the last 60 blocks and required to have
    /// broadcast by 40 blocks before `T`.
    pub fn mainnet_default() -> Self {
        Self {
            block_seconds: MAINNET_BLOCK_SECONDS,
            refund_delay_blocks: 1152,
            pay_deadline_blocks: 60,
            broadcast_deadline_blocks: 40,
        }
    }

    /// Derives a policy from a wall-clock refund window, so a chain whose block
    /// time changes keeps the same real-world timeout.
    pub fn from_refund_hours(block_seconds: u32, hours: u32) -> Result<Self, PolicyError> {
        if block_seconds == 0 {
            return Err(PolicyError::ZeroBlockTime);
        }
        let blocks = (hours * 3600) / block_seconds;
        let policy = Self {
            block_seconds,
            refund_delay_blocks: blocks,
            // The margins are wall-clock quantities too: 75 minutes of paying
            // room and 50 minutes of broadcast room at mainnet block time.
            pay_deadline_blocks: (75 * 60) / block_seconds,
            broadcast_deadline_blocks: (50 * 60) / block_seconds,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.block_seconds == 0 {
            return Err(PolicyError::ZeroBlockTime);
        }
        if self.refund_delay_blocks <= self.pay_deadline_blocks {
            return Err(PolicyError::DelayTooShort {
                delay: self.refund_delay_blocks,
                pay: self.pay_deadline_blocks,
            });
        }
        if self.pay_deadline_blocks < self.broadcast_deadline_blocks {
            return Err(PolicyError::DeadlinesInverted {
                pay: self.pay_deadline_blocks,
                broadcast: self.broadcast_deadline_blocks,
            });
        }
        Ok(())
    }

    /// `T`, the height at and after which the user can refund.
    pub fn refund_height(&self, lock_height: u32) -> u32 {
        lock_height + self.refund_delay_blocks
    }

    /// The LP must not send Venmo at or after this height (spec 7).
    pub fn pay_deadline(&self, lock_height: u32) -> u32 {
        self.refund_height(lock_height) - self.pay_deadline_blocks
    }

    /// The release must be broadcast by this height.
    pub fn broadcast_deadline(&self, lock_height: u32) -> u32 {
        self.refund_height(lock_height) - self.broadcast_deadline_blocks
    }

    /// Whether the LP may still start a payment at `current_height`.
    ///
    /// The comparison is `>=` because spec 7 says "does not send Venmo at or
    /// after `PAY_DEADLINE`".
    pub fn may_pay(&self, lock_height: u32, current_height: u32) -> bool {
        current_height < self.pay_deadline(lock_height)
    }

    /// Whether a release broadcast at `current_height` is still inside the
    /// margin. After this the release is still valid, but it races the refund
    /// and the loss is the LP's (spec 4.5).
    pub fn within_broadcast_margin(&self, lock_height: u32, current_height: u32) -> bool {
        current_height <= self.broadcast_deadline(lock_height)
    }

    /// Whether the user may broadcast the refund.
    pub fn may_refund(&self, lock_height: u32, current_height: u32) -> bool {
        current_height >= self.refund_height(lock_height)
    }
}

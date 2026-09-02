//! `AcceptedQuote::new`, round 4 finding 4.
//!
//! A client builds these, and every field is something the user is committing
//! to. Refusing a bad one here names the cause; letting it through means the
//! error surfaces several layers down, naming a consequence.

use zecp2p_escrow::client::{AcceptedQuote, QuoteError, MAX_REFUND_HEIGHT, MINIMUM_ESCROW_ZAT};
use zecp2p_escrow::payment_details::IDENTITY_RATE_18DEC;

const PAYEE: [u8; 32] = [0x85; 32];

fn l_pub() -> [u8; 33] {
    let secp = secp256k1::Secp256k1::new();
    let k = secp256k1::SecretKey::from_slice(&[0x22; 32]).unwrap();
    secp256k1::PublicKey::from_secret_key(&secp, &k).serialize()
}

fn good() -> Result<AcceptedQuote, QuoteError> {
    AcceptedQuote::at_identity_rate(1_000_000, PAYEE, 3_500_000, l_pub(), 5_000_000)
}

#[test]
fn a_well_formed_quote_is_accepted() {
    let q = good().expect("a 1 USD quote at the identity rate is fine");
    assert_eq!(q.usd_amount_6dec, 1_000_000);
    assert_eq!(q.rate_18dec, IDENTITY_RATE_18DEC);
}

#[test]
fn a_zero_amount_is_refused() {
    assert_eq!(
        AcceptedQuote::at_identity_rate(1_000_000, PAYEE, 3_500_000, l_pub(), 0),
        Err(QuoteError::ZeroAmount)
    );
}

#[test]
fn an_escrow_below_the_dust_and_fee_floor_is_refused() {
    // Spec section 3 sets a 0.001 ZEC minimum. Below it the release fee eats
    // the escrow and the output is dust.
    let err = AcceptedQuote::at_identity_rate(1_000_000, PAYEE, 3_500_000, l_pub(), 50_000)
        .unwrap_err();
    assert_eq!(
        err,
        QuoteError::BelowMinimum {
            amount_zat: 50_000,
            minimum: MINIMUM_ESCROW_ZAT
        }
    );

    // The floor is 0.001 ZEC *above fees* (R5-8), so 100000 flat is refused.
    assert!(matches!(
        AcceptedQuote::at_identity_rate(1_000_000, PAYEE, 3_500_000, l_pub(), 100_000),
        Err(QuoteError::BelowMinimum { .. })
    ));
    assert_eq!(MINIMUM_ESCROW_ZAT, 120_000);
    // And exactly at the floor it is accepted, so the boundary is not off by one.
    AcceptedQuote::at_identity_rate(1_000_000, PAYEE, 3_500_000, l_pub(), MINIMUM_ESCROW_ZAT)
        .unwrap();
}

#[test]
fn a_zero_payout_is_refused() {
    // Locking ZEC for nothing is not a trade.
    assert_eq!(
        AcceptedQuote::at_identity_rate(0, PAYEE, 3_500_000, l_pub(), 5_000_000),
        Err(QuoteError::ZeroPayout)
    );
}

#[test]
fn a_rate_that_is_not_the_identity_rate_is_refused() {
    // Spec 16.3: the enclave's releaseAmount only means dollars at the identity
    // rate. The value below is the one the captured USDC fill carried, and it
    // is exactly the kind of plausible-looking rate this check exists to stop.
    let err = AcceptedQuote::new(
        1_000_000,
        PAYEE,
        990_881_148_896_019_200,
        3_500_000,
        l_pub(),
        5_000_000,
    )
    .unwrap_err();
    assert_eq!(
        err,
        QuoteError::NonIdentityRate {
            got: 990_881_148_896_019_200,
            expected: IDENTITY_RATE_18DEC
        }
    );

    // And a rate of 1, which reproduced the round-1 theft.
    assert!(matches!(
        AcceptedQuote::new(1_000_000, PAYEE, 1, 3_500_000, l_pub(), 5_000_000),
        Err(QuoteError::NonIdentityRate { .. })
    ));
}

#[test]
fn an_unusable_refund_height_is_refused() {
    for t in [0u64, MAX_REFUND_HEIGHT + 1, 1u64 << 32, 1u64 << 62] {
        assert!(
            matches!(
                AcceptedQuote::at_identity_rate(1_000_000, PAYEE, t, l_pub(), 5_000_000),
                Err(QuoteError::RefundHeightOutOfRange { .. })
            ),
            "T={t} must be refused"
        );
    }
    AcceptedQuote::at_identity_rate(1_000_000, PAYEE, MAX_REFUND_HEIGHT, l_pub(), 5_000_000)
        .expect("the cap itself is acceptable");
}

#[test]
fn an_lp_key_that_is_not_a_point_is_refused() {
    // An unspendable escrow the user would discover at T and not before.
    assert_eq!(
        AcceptedQuote::at_identity_rate(1_000_000, PAYEE, 3_500_000, [0xff; 33], 5_000_000),
        Err(QuoteError::BadLpKey)
    );
    assert_eq!(
        AcceptedQuote::at_identity_rate(1_000_000, PAYEE, 3_500_000, [0x00; 33], 5_000_000),
        Err(QuoteError::BadLpKey)
    );
}

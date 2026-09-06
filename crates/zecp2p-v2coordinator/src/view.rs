//! The JSON the page reads.
//!
//! Every field name and every byte order here is the page's, not this crate's.
//! `frontend/app/test/mock-coordinator.mjs` is the reference implementation and
//! `tests/contract.rs` holds this module to it.
//!
//! # The one thing to get right
//!
//! **Txids cross the wire in display order and live in the terms in internal
//! order.** The page reverses `funding.txid` before building terms from it, so
//! sending internal order here makes the page compute an event id for an
//! outpoint that does not exist, and the pre-signature it then makes decrypts
//! to nothing. `announcement.terms.funding_txid`, by contrast, is
//! `WireTerms`, which is internal order by definition. Both appear in the same
//! response, in opposite orders, on purpose.

use serde::{Deserialize, Serialize};

use crate::order::Order;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capabilities {
    pub network: String,
    pub rails: Vec<Rail>,
    pub fee: FeeInfo,
    pub l_pub: String,
    pub attestor_pubkey: String,
    pub consensus_branch_id: u32,
    pub block_seconds: u32,
    pub refund_delay_blocks: u32,
    pub limits: Limits,
    /// The live USD-per-ZEC rate the page displays, spread applied. `None`
    /// when no price could be trusted, which the page must show as unavailable
    /// rather than substituting one of its own.
    pub rate_usd_per_zec: Option<f64>,
    /// The spread in basis points, so the page can say what it is taking.
    pub spread_bps: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rail {
    pub id: String,
    pub label: String,
    pub live: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeInfo {
    pub bps: u64,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Limits {
    pub min_zat: u64,
    pub max_zat: u64,
}

/// The quote as the page reads it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteView {
    pub quote_id: String,
    pub amount_zat: u64,
    pub gross_cents: u64,
    pub net_cents: u64,
    pub usd_amount_6dec: u64,
    pub platform_fee_zat: u64,
    pub miner_fee_zat: u64,
    pub rate_usd_per_zec: f64,
    pub lines: Vec<LineView>,
    pub route_label: String,
    pub expected_seconds: u64,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineView {
    pub label: String,
    pub cents: i64,
    pub is_zpay_fee: bool,
}

impl From<&crate::order::Quote> for QuoteView {
    fn from(q: &crate::order::Quote) -> Self {
        Self {
            quote_id: q.quote_id.clone(),
            amount_zat: q.amount_zat,
            gross_cents: q.gross_cents,
            net_cents: q.net_cents,
            usd_amount_6dec: q.usd_amount_6dec,
            platform_fee_zat: q.platform_fee_zat,
            miner_fee_zat: q.miner_fee_zat,
            rate_usd_per_zec: q.rate_usd_per_zec,
            lines: q
                .lines
                .iter()
                .map(|l| LineView {
                    label: l.label.clone(),
                    cents: l.cents,
                    is_zpay_fee: l.is_zpay_fee,
                })
                .collect(),
            route_label: "escrow on Zcash".into(),
            expected_seconds: 1200,
            expires_at: q.expires_at.to_rfc3339(),
        }
    }
}

/// The order view, which is what `/escrow/orders/{id}` returns and what
/// `/escrow/orders` answers with.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderView {
    pub order_id: String,
    pub network: String,
    pub consensus_branch_id: u32,
    pub stage: String,
    pub current_height: u32,
    pub destination: Destination,
    pub quote: OrderQuoteView,
    pub escrow: EscrowView,
    pub funding: Option<FundingView>,
    pub announcement: Option<AnnouncementView>,
    pub pre_signature: Option<PreSignatureView>,
    pub payment: Option<PaymentView>,
    /// Whether this coordinator's journal says a payment for this escrow may
    /// already have left.
    ///
    /// `payment` is not the same question and cannot answer it. Only one of the
    /// four `Failed` writers that follow a journal claim records a payment on
    /// the order; the other three - the Venmo leg erroring inside `pay`, a
    /// stale `Paying` line, another payment under way - leave it null while the
    /// journal says the dollars may be gone. The page hides its refund form on
    /// this, because offering it there is telling the user to spend against a
    /// release the LP may already hold.
    #[serde(default)]
    pub fiat_may_have_left: bool,
    pub release: Option<TxidView>,
    pub refund: Option<TxidView>,
    /// Only set when the stage is `failed`; the page shows it as the reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Destination {
    pub rail: String,
    pub handle: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderQuoteView {
    pub net_cents: u64,
    pub gross_cents: u64,
    pub lines: Vec<LineView>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscrowView {
    pub address: String,
    pub amount_zat: u64,
    pub refund_height: u64,
    pub u_pub: String,
    pub l_pub: String,
    pub payee_hash: String,
    pub usd_amount_6dec: u64,
    pub platform_fee_zat: u64,
    /// Hex, empty exactly when the fee is zero.
    pub treasury_script: String,
    pub zip321_uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FundingView {
    /// True when this outpoint is only in the mempool: in no block, and it may
    /// never be. Distinct from `confirmations: 0`, which on a mined output
    /// cannot happen - so without this a page renders "0 of 10" identically
    /// for "not mined yet" and for a state that does not exist.
    #[serde(default)]
    pub mempool: bool,
    /// **Display order**, which is what explorers print and what the page
    /// reverses before it builds terms.
    pub txid: String,
    pub vout: u32,
    pub confirmations: u32,
    pub required: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnouncementView {
    #[serde(rename = "P")]
    pub p: String,
    #[serde(rename = "R")]
    pub r: String,
    pub event_id: String,
    pub terms_hash: String,
    /// `lp_client::WireTerms`: `funding_txid` here is **internal** order.
    pub terms: zecp2p_escrow::lp_client::WireTerms,
    pub lp_output_script: String,
    pub miner_fee_zat: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreSignatureView {
    pub received_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentView {
    pub sent_at: String,
    pub cents: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxidView {
    /// Display order.
    pub txid: String,
}

/// Renders one order for the page.
pub fn order_view(order: &Order, current_height: u32) -> OrderView {
    order_view_with_journal(order, current_height, false)
}

/// The same view, told what the journal says about a payment having left.
///
/// Split so this module keeps taking no dependency on the journal: the caller
/// reads it and passes the answer. `order_view` is the plain form for callers
/// that have no journal to ask - it reports `false`, which is only ever used
/// where no payment can have started.
pub fn order_view_with_journal(
    order: &Order,
    current_height: u32,
    fiat_may_have_left: bool,
) -> OrderView {
    OrderView {
        order_id: order.order_id.clone(),
        network: order.network.clone(),
        consensus_branch_id: order.consensus_branch_id,
        stage: order.stage.as_str().to_string(),
        current_height,
        destination: Destination {
            rail: "venmo".into(),
            handle: order.handle.clone(),
        },
        quote: OrderQuoteView {
            net_cents: order.quote.net_cents,
            gross_cents: order.quote.gross_cents,
            lines: order
                .quote
                .lines
                .iter()
                .map(|l| LineView {
                    label: l.label.clone(),
                    cents: l.cents,
                    is_zpay_fee: l.is_zpay_fee,
                })
                .collect(),
        },
        escrow: EscrowView {
            address: order.address.clone(),
            amount_zat: order.quote.amount_zat,
            refund_height: order.refund_height,
            u_pub: hex::encode(order.u_pub),
            l_pub: hex::encode(order.l_pub),
            payee_hash: hex::encode(order.payee_hash),
            usd_amount_6dec: order.quote.usd_amount_6dec,
            platform_fee_zat: order.quote.platform_fee_zat,
            treasury_script: hex::encode(&order.treasury_script),
            zip321_uri: zip321(&order.address, order.quote.amount_zat),
        },
        // The outpoint the page must rebuild the release digest over.
        //
        // `order.funding` alone is not enough once an escrow can be announced
        // from a mempool sighting: the page reaches `needs_presignature`, finds
        // no funding in the view, and refuses to sign ("the announcement has
        // not arrived yet") - so the order announces and can never be signed.
        // The mempool outpoint is reported with zero confirmations, which is
        // the truth: it is in no block, and the page shows it as unconfirmed.
        funding: order
            .funding
            .map(|f| FundingView {
                // Display order: the page reverses this.
                txid: zecp2p_escrow::rpc::txid_to_display(&f.txid),
                vout: f.vout,
                confirmations: f.confirmations,
                required: f.required,
                mempool: false,
            })
            .or_else(|| {
                let txid = order.mempool_announced_txid?;
                let vout = order.mempool_announced_vout?;
                Some(FundingView {
                    txid: zecp2p_escrow::rpc::txid_to_display(&txid),
                    vout,
                    confirmations: 0,
                    required: zecp2p_escrow::depth::required_depth(order.quote.usd_amount_6dec),
                    mempool: true,
                })
            }),
        announcement: announcement_view(order),
        pre_signature: order.pre_signed_at.map(|at| PreSignatureView {
            received_at: at.to_rfc3339(),
        }),
        fiat_may_have_left,
        payment: order.payment.as_ref().map(|p| PaymentView {
            sent_at: p.sent_at.to_rfc3339(),
            cents: p.cents,
        }),
        release: order.release_txid.clone().map(|txid| TxidView { txid }),
        refund: order.refund_txid.clone().map(|txid| TxidView { txid }),
        reason: order.reason.clone(),
    }
}

fn announcement_view(order: &Order) -> Option<AnnouncementView> {
    let a = order.announcement.as_ref()?;
    let canonical = order.canonical_terms()?;
    Some(AnnouncementView {
        p: a.p.clone(),
        r: a.r.clone(),
        event_id: a.event_id.clone(),
        terms_hash: a.terms_hash.clone(),
        terms: zecp2p_escrow::lp_client::WireTerms::from_terms(&canonical),
        lp_output_script: hex::encode(&order.lp_output_script),
        miner_fee_zat: order.quote.miner_fee_zat,
    })
}

/// A ZIP 321 payment URI, so a wallet can be handed the address and amount.
pub fn zip321(address: &str, amount_zat: u64) -> String {
    format!(
        "zcash:{address}?amount={}",
        crate::quote::zec_string(amount_zat)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::order::{Funding, Quote, Stage};

    fn order_with_funding() -> Order {
        Order {
            order_id: "esc_1".into(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            stage: Stage::Confirming,
            reason: None,
            handle: "alice".into(),
            quote: Quote {
                quote_id: "q1".into(),
                amount_zat: 200_000,
                gross_cents: 805,
                net_cents: 700,
                usd_amount_6dec: 7_000_000,
                platform_fee_zat: 400,
                miner_fee_zat: 15_000,
                rate_usd_per_zec: 40.25,
                lines: vec![],
                expires_at: chrono::Utc::now(),
            },
            opened_height: 100,
            scanned_through: None,
            mempool_announced_txid: None,
            mempool_announced_vout: None,
            sighting_never_confirmed: false,
            network: "test".into(),
            consensus_branch_id: 0x37a5_165b,
            u_pub: [2u8; 33],
            l_pub: [3u8; 33],
            refund_height: 1252,
            address: "t2Address".into(),
            redeem_script: vec![1, 2, 3],
            script_pubkey: vec![0xa9, 0x14],
            payee_hash: [7u8; 32],
            treasury_script: vec![0x76, 0xa9],
            lp_output_script: vec![0x76, 0xa9, 0x14],
            funding: Some(Funding {
                // A txid whose reverse is visibly different.
                txid: {
                    let mut t = [0u8; 32];
                    t[0] = 0xaa;
                    t[31] = 0xbb;
                    t
                },
                vout: 1,
                confirmations: 3,
                required: 10,
            }),
            lock_confirmed_ms: Some(1_700_000_000_000),
            announcement: None,
            pre_signature: None,
            pre_signed_at: None,
            payment: None,
            release_txid: None,
            refund_txid: None,
        }
    }

    #[test]
    fn the_funding_txid_crosses_the_wire_in_display_order() {
        // The page reverses this before building terms. Sending internal order
        // makes it compute an event id for an outpoint that does not exist, and
        // the pre-signature it then produces decrypts to nothing.
        let order = order_with_funding();
        let view = order_view(&order, 105);
        let txid = view.funding.expect("funded").txid;
        assert!(txid.starts_with("bb"), "display order starts at the last byte: {txid}");
        assert!(txid.ends_with("aa"));
    }

    #[test]
    fn the_announcement_terms_carry_internal_order() {
        // The opposite convention, in the same response. `WireTerms` is what
        // the attestor and the page both parse, and it is internal by
        // definition.
        let mut order = order_with_funding();
        order.announcement = Some(crate::order::Announcement {
            event_id: "00".into(),
            r: "02".into(),
            p: "03".into(),
            terms_hash: "04".into(),
        });
        let view = order_view(&order, 105);
        let terms = view.announcement.expect("announced").terms;
        assert!(terms.funding_txid.starts_with("aa"), "internal order: {}", terms.funding_txid);
    }

    #[test]
    fn an_order_with_no_lock_time_shows_no_announcement() {
        // `terms_hash` commits to `lock_confirmed_ms`, so an announcement
        // rendered without one would pin a hash that binds nothing.
        let mut order = order_with_funding();
        order.lock_confirmed_ms = None;
        order.announcement = Some(crate::order::Announcement {
            event_id: "00".into(),
            r: "02".into(),
            p: "03".into(),
            terms_hash: "04".into(),
        });
        assert!(order_view(&order, 105).announcement.is_none());
    }

    #[test]
    fn the_treasury_script_is_hex_and_empty_when_there_is_no_fee() {
        let mut order = order_with_funding();
        assert_eq!(order_view(&order, 1).escrow.treasury_script, "76a9");

        order.quote.platform_fee_zat = 0;
        order.treasury_script = vec![];
        assert_eq!(order_view(&order, 1).escrow.treasury_script, "");
    }

    #[test]
    fn the_zip321_uri_names_the_address_and_the_amount() {
        assert_eq!(zip321("t2Foo", 200_000), "zcash:t2Foo?amount=0.002");
    }
}

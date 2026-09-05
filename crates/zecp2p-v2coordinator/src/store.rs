//! Where orders live between requests, and across a restart.
//!
//! One JSON file per order, written whole and renamed into place. A database
//! would be better company for a busy coordinator; what this needs to be is
//! **durable before the address is shown**, because an order the user has sent
//! ZEC to and this process has forgotten is an escrow only the user's refund
//! can recover. Rename-into-place gets that with no schema and no migration.
//!
//! The in-memory map is the read path. Disk is the truth on restart.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};

use crate::order::{Order, Stage};

/// Every order this coordinator knows about.
#[derive(Debug, Clone)]
pub struct OrderStore {
    dir: PathBuf,
    orders: Arc<Mutex<HashMap<String, Order>>>,
}

impl OrderStore {
    /// Opens the store, reading back whatever a previous run left.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("could not create the order directory {}", dir.display()))?;

        let mut orders = HashMap::new();
        for entry in std::fs::read_dir(&dir)
            .with_context(|| format!("could not read {}", dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("could not read {}", path.display()))?;
            // A damaged order file stops the load rather than being skipped.
            // Skipping one means starting a coordinator that has forgotten an
            // escrow somebody's ZEC is sitting in, and it would look healthy.
            let order: Order = serde_json::from_str(&text).with_context(|| {
                format!(
                    "the order at {} is corrupt. Refusing to start having forgotten an \
                     escrow: the user's ZEC may be in it, and this process is the only \
                     thing that can release it before T.",
                    path.display()
                )
            })?;
            orders.insert(order.order_id.clone(), order);
        }

        tracing::info!(count = orders.len(), dir = %dir.display(), "loaded orders");
        Ok(Self {
            dir,
            orders: Arc::new(Mutex::new(orders)),
        })
    }

    fn path_of(&self, order_id: &str) -> PathBuf {
        self.dir.join(format!("{order_id}.json"))
    }

    /// Writes an order to disk, then to memory.
    ///
    /// Disk first, deliberately. An order that is in memory but not on disk is
    /// exactly the order a crash loses, and the moment that matters is between
    /// opening the order and showing its address.
    pub fn put(&self, order: &Order) -> Result<()> {
        let path = self.path_of(&order.order_id);
        let tmp = path.with_extension("json.tmp");
        let text = serde_json::to_string_pretty(order).context("could not serialize the order")?;
        std::fs::write(&tmp, text)
            .with_context(|| format!("could not write {}", tmp.display()))?;
        std::fs::rename(&tmp, &path)
            .with_context(|| format!("could not move {} into place", tmp.display()))?;
        self.orders
            .lock()
            .expect("order store lock")
            .insert(order.order_id.clone(), order.clone());
        Ok(())
    }

    pub fn get(&self, order_id: &str) -> Option<Order> {
        self.orders
            .lock()
            .expect("order store lock")
            .get(order_id)
            .cloned()
    }

    /// Every order, for the driver's sweep.
    pub fn all(&self) -> Vec<Order> {
        self.orders
            .lock()
            .expect("order store lock")
            .values()
            .cloned()
            .collect()
    }

    /// How many orders are still open.
    ///
    /// Used to bound what a caller can create. Eviction is deliberately not
    /// offered: an order this process forgets is an escrow whose release
    /// nobody can assemble, and the user's only recovery is the refund at `T`.
    /// So the limit is applied at the door, and orders leave only by reaching
    /// a terminal stage.
    pub fn open_count(&self) -> usize {
        self.orders
            .lock()
            .expect("order store lock")
            .values()
            .filter(|o| o.stage.is_open())
            .count()
    }

    /// Orders this coordinator is still working on, across every handle.
    ///
    /// What the global bound counts. R3-5: it used to count every open order,
    /// and `Refundable` is open forever - the page must keep being able to
    /// offer the refund - so abandoned, never-funded orders accumulated toward
    /// the ceiling and nothing ever brought them back down. Same reasoning as
    /// [`Self::awaiting_for_handle`], applied to the global limit.
    pub fn awaiting_count(&self) -> usize {
        self.orders
            .lock()
            .expect("order store lock")
            .values()
            .filter(|o| o.stage.is_open() && o.stage != Stage::Refundable)
            .count()
    }

    /// Open orders for one Venmo handle.
    ///
    /// The per-caller bound. A handle is the only thing an order names that a
    /// caller cannot mint for free.
    pub fn open_for_handle(&self, handle: &str) -> usize {
        self.orders
            .lock()
            .expect("order store lock")
            .values()
            .filter(|o| o.stage.is_open() && o.handle.eq_ignore_ascii_case(handle))
            .count()
    }

    /// Orders for one handle that this coordinator is still working on.
    ///
    /// The per-handle bound counts these rather than every open order. R2-5:
    /// `Refundable` is open - the user may still refund, and the order must
    /// stay readable so the page can offer that - but it needs nothing further
    /// from this coordinator. Counting it meant five abandoned, never-funded
    /// orders locked a served handle out permanently, at no cost to whoever
    /// opened them.
    ///
    /// The distinction is "is this coordinator going to do something about it",
    /// not "is this order finished". A refundable escrow is the user's to
    /// resolve, from a page that already holds the key.
    pub fn awaiting_for_handle(&self, handle: &str) -> usize {
        self.orders
            .lock()
            .expect("order store lock")
            .values()
            .filter(|o| {
                o.handle.eq_ignore_ascii_case(handle)
                    && o.stage.is_open()
                    && o.stage != Stage::Refundable
            })
            .count()
    }

    /// What one sweep works through.
    ///
    /// Open orders, plus the finished ones that still owe the user a look at
    /// the refund deadline. This is the list `run` iterates, so a stage missing
    /// from it is a stage nothing ever moves - `Unpaid` and `Failed` sat here
    /// forever, and the page offers its refund form on `Refundable` alone.
    ///
    /// Deliberately not `open_count`, which is the cap on how many orders may
    /// be in flight at once: a finished trade must not hold a slot against that
    /// limit just because its escrow is still refundable.
    pub fn open_orders(&self) -> Vec<Order> {
        self.orders
            .lock()
            .expect("order store lock")
            .values()
            .filter(|o| o.stage.is_open() || o.still_owes_a_refund_check())
            .cloned()
            .collect()
    }

}

// The payment slot deliberately does **not** live here. It used to: a helper on
// this store looked for another order at `Stage::Paid`. That was wrong twice
// over (R1-2). An order in the middle of `settle` is still `Locked`, so the
// check passed while a browser was being driven; and an order whose process
// died mid-payment is `Locked` on restart too, so the check passed there as
// well. Both let the coordinator pay twice.
//
// The slot is read from the journal instead - see `slot.rs`. The journal line
// is written before the click, so it is the only record that distinguishes
// "has not started" from "may already have paid", and it is on disk rather
// than in this process's memory.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::order::{Quote, Stage};

    fn an_order(id: &str, stage: Stage) -> Order {
        Order {
            order_id: id.into(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            stage,
            reason: None,
            handle: "alice".into(),
            quote: Quote {
                quote_id: "q1".into(),
                amount_zat: 200_000,
                gross_cents: 100,
                net_cents: 90,
                usd_amount_6dec: 900_000,
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
            network: "test".into(),
            consensus_branch_id: 0x37a5_165b,
            u_pub: [2u8; 33],
            l_pub: [3u8; 33],
            refund_height: 1252,
            address: "t2Address".into(),
            redeem_script: vec![1, 2, 3],
            script_pubkey: vec![0xa9, 0x14],
            payee_hash: [7u8; 32],
            treasury_script: vec![],
            lp_output_script: vec![0x76, 0xa9],
            funding: None,
            lock_confirmed_ms: None,
            announcement: None,
            pre_signature: None,
            pre_signed_at: None,
            payment: None,
            release_txid: None,
            refund_txid: None,
        }
    }

    #[test]
    fn an_order_survives_a_restart() {
        // The property the whole file format exists for: an order written
        // before its address was shown is still there after a crash.
        let dir = tempfile::tempdir().unwrap();
        let store = OrderStore::open(dir.path()).unwrap();
        store.put(&an_order("esc_1", Stage::AwaitingZec)).unwrap();

        let reopened = OrderStore::open(dir.path()).unwrap();
        let back = reopened.get("esc_1").expect("the order came back");
        assert_eq!(back.stage, Stage::AwaitingZec);
        assert_eq!(back.address, "t2Address");
        assert_eq!(back.quote.amount_zat, 200_000);
    }

    #[test]
    fn a_corrupt_order_stops_the_load_rather_than_being_skipped() {
        // Skipping it would start a coordinator that has forgotten an escrow
        // holding someone's ZEC, and nothing about it would look wrong.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("esc_bad.json"), "{ not json").unwrap();
        let err = OrderStore::open(dir.path()).expect_err("a corrupt order must stop the load");
        assert!(format!("{err:#}").contains("corrupt"));
    }

    #[test]
    fn finished_orders_do_not_hold_the_slot() {
        let dir = tempfile::tempdir().unwrap();
        let store = OrderStore::open(dir.path()).unwrap();
        store.put(&an_order("esc_done", Stage::Released)).unwrap();
        store.put(&an_order("esc_live", Stage::Confirming)).unwrap();

        let open: Vec<_> = store.open_orders().iter().map(|o| o.order_id.clone()).collect();
        assert_eq!(open, vec!["esc_live".to_string()]);
    }
}

//! SQLite database for session persistence
//!
//! Database operations for persisting offramp sessions.

#![allow(dead_code)]

use anyhow::Result;
use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};
use uuid::Uuid;
use zecp2p_types::{OfframpSession, OfframpStatus};

pub struct Database {
    pool: SqlitePool,
}

impl Database {
    pub async fn new(path: &str) -> Result<Self> {
        let url = format!("sqlite:{}?mode=rwc", path);
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await?;

        Ok(Self { pool })
    }

    pub async fn run_migrations(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL,
                request_json TEXT NOT NULL,
                payee_details_hash TEXT NOT NULL,
                expected_usdc TEXT,
                min_output_usdc TEXT,
                received_usdc TEXT,
                near_deposit_address TEXT,
                near_tx_hash TEXT,
                zkp2p_deposit_id TEXT,
                zkp2p_intent_hash TEXT,
                create_session_tx TEXT,
                process_offramp_tx TEXT,
                error TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status)
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Key-value store for tracking state like last processed block
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS kv_store (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get a value from the key-value store
    pub async fn get_kv(&self, key: &str) -> Result<Option<String>> {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT value FROM kv_store WHERE key = ?",
        )
        .bind(key)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|(v,)| v))
    }

    /// Set a value in the key-value store
    pub async fn set_kv(&self, key: &str, value: &str) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO kv_store (key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            "#,
        )
        .bind(key)
        .bind(value)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn insert_session(&self, session: &OfframpSession) -> Result<()> {
        let request_json = serde_json::to_string(&session.request)?;

        sqlx::query(
            r#"
            INSERT INTO sessions (
                id, session_id, status, request_json, payee_details_hash,
                expected_usdc, min_output_usdc, received_usdc, near_deposit_address, near_tx_hash,
                zkp2p_deposit_id, zkp2p_intent_hash, create_session_tx, process_offramp_tx,
                error, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(session.id.to_string())
        .bind(format!("{:?}", session.session_id))
        .bind(session.status.to_string())
        .bind(&request_json)
        .bind(format!("{:?}", session.payee_details_hash))
        .bind(session.expected_usdc.map(|u| u.to_string()))
        .bind(session.min_output_usdc.map(|u| u.to_string()))
        .bind(session.received_usdc.map(|u| u.to_string()))
        .bind(&session.near_deposit_address)
        .bind(&session.near_tx_hash)
        .bind(session.zkp2p_deposit_id.map(|u| u.to_string()))
        .bind(session.zkp2p_intent_hash.map(|h| format!("{:?}", h)))
        .bind(session.create_session_tx.map(|h| format!("{:?}", h)))
        .bind(session.process_offramp_tx.map(|h| format!("{:?}", h)))
        .bind(&session.error)
        .bind(session.created_at.to_rfc3339())
        .bind(session.updated_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn update_session(&self, session: &OfframpSession) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE sessions SET
                status = ?,
                expected_usdc = ?,
                min_output_usdc = ?,
                received_usdc = ?,
                near_deposit_address = ?,
                near_tx_hash = ?,
                zkp2p_deposit_id = ?,
                zkp2p_intent_hash = ?,
                create_session_tx = ?,
                process_offramp_tx = ?,
                error = ?,
                updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(session.status.to_string())
        .bind(session.expected_usdc.map(|u| u.to_string()))
        .bind(session.min_output_usdc.map(|u| u.to_string()))
        .bind(session.received_usdc.map(|u| u.to_string()))
        .bind(&session.near_deposit_address)
        .bind(&session.near_tx_hash)
        .bind(session.zkp2p_deposit_id.map(|u| u.to_string()))
        .bind(session.zkp2p_intent_hash.map(|h| format!("{:?}", h)))
        .bind(session.create_session_tx.map(|h| format!("{:?}", h)))
        .bind(session.process_offramp_tx.map(|h| format!("{:?}", h)))
        .bind(&session.error)
        .bind(session.updated_at.to_rfc3339())
        .bind(session.id.to_string())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_session(&self, id: Uuid) -> Result<Option<OfframpSession>> {
        let row: Option<SessionRow> = sqlx::query_as(
            r#"
            SELECT * FROM sessions WHERE id = ?
            "#,
        )
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => Ok(Some(r.into_session()?)),
            None => Ok(None),
        }
    }

    pub async fn get_sessions_by_status(&self, status: OfframpStatus) -> Result<Vec<OfframpSession>> {
        let rows: Vec<SessionRow> = sqlx::query_as(
            r#"
            SELECT * FROM sessions WHERE status = ?
            "#,
        )
        .bind(status.to_string())
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.into_session()).collect()
    }

    pub async fn get_active_sessions(&self) -> Result<Vec<OfframpSession>> {
        let rows: Vec<SessionRow> = sqlx::query_as(
            r#"
            SELECT * FROM sessions
            WHERE status NOT IN ('fulfilled', 'failed', 'rescued', 'withdrawn')
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.into_session()).collect()
    }

    /// Aggregate counts for the public `/stats` endpoint.
    ///
    /// Sums `received_usdc` in Rust rather than SQL: the column is a decimal
    /// string, and SQLite's SUM over text silently truncates to a double.
    pub async fn stats(&self) -> Result<SessionStats> {
        use alloy::primitives::U256;

        let rows: Vec<StatusCount> = sqlx::query_as(
            r#"
            SELECT status, COUNT(*) AS count FROM sessions GROUP BY status
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let mut stats = SessionStats::default();
        for row in rows {
            match row.status.as_str() {
                "fulfilled" => stats.fulfilled = row.count as u64,
                "zkp2p_deposited" => stats.open_deposits = row.count as u64,
                "failed" | "rescued" | "withdrawn" => {}
                _ => stats.in_flight += row.count as u64,
            }
        }

        let fulfilled: Vec<(Option<String>, String)> = sqlx::query_as(
            r#"
            SELECT received_usdc, updated_at FROM sessions WHERE status = 'fulfilled'
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let mut settled = U256::ZERO;
        let mut last: Option<String> = None;
        for (amount, updated_at) in fulfilled {
            if let Some(a) = amount {
                settled = settled.saturating_add(a.parse::<U256>().unwrap_or(U256::ZERO));
            }
            if last.as_deref().is_none_or(|l| updated_at.as_str() > l) {
                last = Some(updated_at);
            }
        }
        stats.settled_usdc = settled.to_string();
        stats.last_fulfilled_at = last;

        Ok(stats)
    }
}

/// Counts served by `/stats`. No handles, no session ids, no amounts per
/// session: everything here is already derivable from the glue's logs.
#[derive(Debug, Default, Clone, serde::Serialize, PartialEq, Eq)]
pub struct SessionStats {
    /// Sessions that ended with a Venmo payment proven on chain.
    pub fulfilled: u64,
    /// Total USDC released to takers across fulfilled sessions, 6 decimals.
    pub settled_usdc: String,
    /// Deposits sitting in EscrowV2 waiting for a taker.
    pub open_deposits: u64,
    /// Sessions somewhere between creation and the escrow deposit.
    pub in_flight: u64,
    /// RFC 3339 timestamp of the most recent fulfilment, if any.
    pub last_fulfilled_at: Option<String>,
}

#[derive(sqlx::FromRow)]
struct StatusCount {
    status: String,
    count: i64,
}

#[derive(sqlx::FromRow)]
struct SessionRow {
    id: String,
    session_id: String,
    status: String,
    request_json: String,
    payee_details_hash: String,
    expected_usdc: Option<String>,
    min_output_usdc: Option<String>,
    received_usdc: Option<String>,
    near_deposit_address: Option<String>,
    near_tx_hash: Option<String>,
    zkp2p_deposit_id: Option<String>,
    zkp2p_intent_hash: Option<String>,
    create_session_tx: Option<String>,
    process_offramp_tx: Option<String>,
    error: Option<String>,
    created_at: String,
    updated_at: String,
}

impl SessionRow {
    fn into_session(self) -> Result<OfframpSession> {
        use alloy::primitives::{B256, U256};
        use chrono::DateTime;

        let request = serde_json::from_str(&self.request_json)?;

        let parse_b256 = |s: &str| -> Result<B256> {
            // Handle "0x..." format
            let s = s.trim_start_matches("0x");
            let bytes = hex::decode(s)?;
            Ok(B256::from_slice(&bytes))
        };

        let parse_u256 = |s: &str| -> Result<U256> {
            Ok(U256::from_str_radix(s, 10)?)
        };

        Ok(OfframpSession {
            id: self.id.parse()?,
            session_id: parse_b256(&self.session_id)?,
            status: match self.status.as_str() {
                "created" => OfframpStatus::Created,
                "near_intent_pending" => OfframpStatus::NearIntentPending,
                "usdc_received" => OfframpStatus::UsdcReceived,
                "zkp2p_deposited" => OfframpStatus::Zkp2pDeposited,
                "intent_signaled" => OfframpStatus::IntentSignaled,
                "fulfilled" => OfframpStatus::Fulfilled,
                "failed" => OfframpStatus::Failed,
                "rescued" => OfframpStatus::Rescued,
                "withdrawn" => OfframpStatus::Withdrawn,
                s => anyhow::bail!("Unknown status: {}", s),
            },
            request,
            payee_details_hash: parse_b256(&self.payee_details_hash)?,
            expected_usdc: self.expected_usdc.as_ref().map(|s| parse_u256(s)).transpose()?,
            min_output_usdc: self.min_output_usdc.as_ref().map(|s| parse_u256(s)).transpose()?,
            received_usdc: self.received_usdc.as_ref().map(|s| parse_u256(s)).transpose()?,
            near_deposit_address: self.near_deposit_address,
            near_tx_hash: self.near_tx_hash,
            zkp2p_deposit_id: self.zkp2p_deposit_id.as_ref().map(|s| parse_u256(s)).transpose()?,
            zkp2p_intent_hash: self.zkp2p_intent_hash.as_ref().map(|s| parse_b256(s)).transpose()?,
            create_session_tx: self.create_session_tx.as_ref().map(|s| parse_b256(s)).transpose()?,
            process_offramp_tx: self.process_offramp_tx.as_ref().map(|s| parse_b256(s)).transpose()?,
            error: self.error,
            created_at: DateTime::parse_from_rfc3339(&self.created_at)?.with_timezone(&chrono::Utc),
            updated_at: DateTime::parse_from_rfc3339(&self.updated_at)?.with_timezone(&chrono::Utc),
        })
    }
}

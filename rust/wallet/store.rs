//! Postgres state: BDK changesets and payouts.

use bdk_wallet::{ChangeSet, KeychainKind, Wallet, bitcoin::Network, chain::Merge as _};
use sqlx::{PgConnection, PgPool, Postgres, Row as _, pool::PoolConnection};

use crate::service::Error;

/// Serializes transaction building across wallet instances.
const PAYOUT_LOCK: i64 = 0x6661_7374_7764; // "fastwd"

pub async fn migrate(db: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations").run(db).await
}

/// The session-level payout lock, on a connection of its own. Postgres holds
/// it until it is unlocked or the session ends, so if this is dropped without
/// [`Self::release`] (an error, or a cancelled request) the connection is
/// closed rather than returned to the pool still holding the lock.
pub struct PayoutLock {
    conn: Option<PoolConnection<Postgres>>,
}

impl PayoutLock {
    pub async fn acquire(db: &PgPool) -> Result<Self, Error> {
        // Owned before waiting: a wait that is cancelled may still be granted.
        let mut lock = Self {
            conn: Some(db.acquire().await?),
        };
        sqlx::query("SELECT pg_advisory_lock($1)")
            .bind(PAYOUT_LOCK)
            .execute(lock.conn())
            .await?;
        Ok(lock)
    }

    pub fn conn(&mut self) -> &mut PgConnection {
        self.conn.as_mut().expect("held until released")
    }

    pub async fn release(mut self) {
        let Some(mut conn) = self.conn.take() else {
            return;
        };
        match sqlx::query_scalar::<_, bool>("SELECT pg_advisory_unlock($1)")
            .bind(PAYOUT_LOCK)
            .fetch_one(&mut *conn)
            .await
        {
            Ok(true) => {}
            result => {
                tracing::error!(?result, "release payout lock; closing its connection");
                drop(conn.detach());
            }
        }
    }
}

impl Drop for PayoutLock {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            drop(conn.detach());
        }
    }
}

/// Loads the wallet from its changesets, creating it on first use.
pub async fn load_wallet(
    conn: &mut PgConnection,
    descriptor: &str,
    network: Network,
) -> Result<Wallet, Error> {
    let rows: Vec<serde_json::Value> =
        sqlx::query_scalar("SELECT changeset FROM bdk_changesets ORDER BY id")
            .fetch_all(&mut *conn)
            .await?;
    let mut changeset = ChangeSet::default();
    for row in rows {
        changeset.merge(serde_json::from_value(row).map_err(|err| Error::Internal(err.into()))?);
    }
    let loaded = Wallet::load()
        .descriptor(KeychainKind::External, Some(descriptor.to_owned()))
        .check_network(network)
        .load_wallet_no_persist(changeset)
        .map_err(|err| Error::Internal(anyhow::anyhow!("load wallet: {err}")))?;
    match loaded {
        Some(wallet) => Ok(wallet),
        None => Wallet::create_single(descriptor.to_owned())
            .network(network)
            .create_wallet_no_persist()
            .map_err(|err| Error::Internal(anyhow::anyhow!("create wallet: {err}"))),
    }
}

pub async fn save_wallet(conn: &mut PgConnection, wallet: &mut Wallet) -> Result<(), Error> {
    let Some(changeset) = wallet.take_staged() else {
        return Ok(());
    };
    let json = serde_json::to_value(&changeset).map_err(|err| Error::Internal(err.into()))?;
    sqlx::query("INSERT INTO bdk_changesets (changeset) VALUES ($1)")
        .bind(json)
        .execute(conn)
        .await?;
    Ok(())
}

pub struct Payout {
    pub withdrawal_id: String,
    pub l2_index: u32,
    pub l2_txid: String,
    pub l2_vout: u32,
    pub l2_sats: u64,
    pub l1_destination: String,
    pub l1_sats: u64,
    pub fee_sats: u64,
    pub txid: String,
    pub raw_tx: Vec<u8>,
    /// Esplora tip height when the current version was signed.
    pub tip_height: u32,
    /// Esplora tip height when the first version was signed.
    pub signed_tip_height: u32,
}

fn sats(value: i64) -> u64 {
    u64::try_from(value).unwrap_or_default()
}

fn db_sats(value: u64) -> Result<i64, Error> {
    i64::try_from(value).map_err(|_| Error::InvalidArgument("amount out of range".to_owned()))
}

impl Payout {
    fn from_row(row: &sqlx::postgres::PgRow) -> Self {
        Self {
            withdrawal_id: row.get("withdrawal_id"),
            l2_index: u32::try_from(row.get::<i64, _>("l2_index")).unwrap_or_default(),
            l2_txid: row.get("l2_txid"),
            l2_vout: u32::try_from(row.get::<i64, _>("l2_vout")).unwrap_or_default(),
            l2_sats: sats(row.get("l2_sats")),
            l1_destination: row.get("l1_destination"),
            l1_sats: sats(row.get("l1_sats")),
            fee_sats: sats(row.get("fee_sats")),
            txid: row.get("txid"),
            raw_tx: row.get("raw_tx"),
            tip_height: u32::try_from(row.get::<i64, _>("tip_height")).unwrap_or_default(),
            signed_tip_height: u32::try_from(row.get::<i64, _>("signed_tip_height"))
                .unwrap_or_default(),
        }
    }
}

/// The payout for this withdrawal, L2 index or L2 payment, if any.
pub async fn conflicting_payout(
    conn: &mut PgConnection,
    withdrawal_id: &str,
    l2_index: u32,
    l2_txid: &str,
    l2_vout: u32,
) -> Result<Option<Payout>, Error> {
    let row = sqlx::query(
        "SELECT * FROM payouts
         WHERE withdrawal_id = $1 OR l2_index = $2 OR (l2_txid = $3 AND l2_vout = $4)
         LIMIT 1",
    )
    .bind(withdrawal_id)
    .bind(i64::from(l2_index))
    .bind(l2_txid)
    .bind(i64::from(l2_vout))
    .fetch_optional(conn)
    .await?;
    Ok(row.as_ref().map(Payout::from_row))
}

/// Sats paid out, fees included, over the last 24 hours.
pub async fn spent_last_day(conn: &mut PgConnection) -> Result<u64, Error> {
    // Payouts count when signed; each version's miner fee, or its increase
    // over the version it replaced, counts when that version was signed.
    let spent: i64 = sqlx::query_scalar(
        "SELECT ((
             SELECT COALESCE(SUM(l1_sats), 0) FROM payouts
             WHERE created_at > now() - interval '24 hours'
         ) + (
             SELECT COALESCE(SUM(fee_sats - COALESCE(previous_fee_sats, 0)), 0)
             FROM (
                 SELECT fee_sats, created_at,
                        LAG(fee_sats) OVER (PARTITION BY withdrawal_id ORDER BY created_at)
                            AS previous_fee_sats
                 FROM payout_versions
                 WHERE withdrawal_id IN (
                     SELECT withdrawal_id FROM payout_versions
                     WHERE created_at > now() - interval '24 hours'
                 )
             ) versions
             WHERE created_at > now() - interval '24 hours'
         ))::BIGINT",
    )
    .fetch_one(conn)
    .await?;
    Ok(sats(spent))
}

/// Txids of every version of the unsettled payouts that have been
/// fee-bumped. New payouts must not spend their change: which version
/// confirms decides whether that change exists.
pub async fn bumped_txids(conn: &mut PgConnection) -> Result<Vec<String>, Error> {
    Ok(sqlx::query_scalar(
        "SELECT v.txid FROM payout_versions v JOIN payouts p USING (withdrawal_id)
         WHERE NOT p.confirmed
           AND (SELECT count(*) FROM payout_versions o
                WHERE o.withdrawal_id = v.withdrawal_id) > 1",
    )
    .fetch_all(conn)
    .await?)
}

/// Whether another unsettled payout spends an output of any version of this
/// one. Replacing it would invalidate that payout.
pub async fn has_child(conn: &mut PgConnection, withdrawal_id: &str) -> Result<bool, Error> {
    let versions = versions(&mut *conn, withdrawal_id).await?;
    let others: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT raw_tx FROM payouts WHERE NOT confirmed AND withdrawal_id <> $1",
    )
    .bind(withdrawal_id)
    .fetch_all(&mut *conn)
    .await?;
    for raw_tx in others {
        let tx: bdk_wallet::bitcoin::Transaction =
            bdk_wallet::bitcoin::consensus::deserialize(&raw_tx)
                .map_err(|err| Error::Internal(err.into()))?;
        if tx.input.iter().any(|input| {
            versions
                .iter()
                .any(|txid| input.previous_output.txid.to_string() == *txid)
        }) {
            return Ok(true);
        }
    }
    Ok(false)
}

pub async fn insert_payout(conn: &mut PgConnection, payout: &Payout) -> Result<(), Error> {
    sqlx::query(
        "INSERT INTO payouts (withdrawal_id, l2_index, l2_txid, l2_vout, l2_sats,
                              l1_destination, l1_sats, fee_sats, txid, raw_tx, tip_height,
                              signed_tip_height)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
    )
    .bind(&payout.withdrawal_id)
    .bind(i64::from(payout.l2_index))
    .bind(&payout.l2_txid)
    .bind(i64::from(payout.l2_vout))
    .bind(db_sats(payout.l2_sats)?)
    .bind(&payout.l1_destination)
    .bind(db_sats(payout.l1_sats)?)
    .bind(db_sats(payout.fee_sats)?)
    .bind(&payout.txid)
    .bind(&payout.raw_tx)
    .bind(i64::from(payout.tip_height))
    .bind(i64::from(payout.signed_tip_height))
    .execute(&mut *conn)
    .await?;
    insert_version(
        conn,
        &payout.withdrawal_id,
        &payout.txid,
        &payout.raw_tx,
        payout.fee_sats,
    )
    .await
}

async fn insert_version(
    conn: &mut PgConnection,
    withdrawal_id: &str,
    txid: &str,
    raw_tx: &[u8],
    fee_sats: u64,
) -> Result<(), Error> {
    sqlx::query(
        "INSERT INTO payout_versions (txid, withdrawal_id, raw_tx, fee_sats)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(txid)
    .bind(withdrawal_id)
    .bind(raw_tx)
    .bind(db_sats(fee_sats)?)
    .execute(conn)
    .await?;
    Ok(())
}

/// Makes a fee-bumped transaction the payout's current version.
pub async fn replace_payout(
    conn: &mut PgConnection,
    withdrawal_id: &str,
    txid: &str,
    raw_tx: &[u8],
    fee_sats: u64,
    tip_height: u32,
) -> Result<(), Error> {
    sqlx::query(
        "UPDATE payouts SET txid = $2, raw_tx = $3, fee_sats = $4, tip_height = $5
         WHERE withdrawal_id = $1",
    )
    .bind(withdrawal_id)
    .bind(txid)
    .bind(raw_tx)
    .bind(db_sats(fee_sats)?)
    .bind(i64::from(tip_height))
    .execute(&mut *conn)
    .await?;
    insert_version(conn, withdrawal_id, txid, raw_tx, fee_sats).await
}

/// Txids of every version of a payout, newest first.
pub async fn versions(
    db: impl sqlx::PgExecutor<'_>,
    withdrawal_id: &str,
) -> Result<Vec<String>, Error> {
    Ok(sqlx::query_scalar(
        "SELECT txid FROM payout_versions WHERE withdrawal_id = $1 ORDER BY created_at DESC",
    )
    .bind(withdrawal_id)
    .fetch_all(db)
    .await?)
}

pub struct Binding {
    pub l2_index: u32,
    pub l1_destination: String,
    pub l1_sats: u64,
    /// The L2 payment the quote asks for.
    pub l2_sats: u64,
}

/// Records a quote's binding; registering the same one again is a no-op.
pub async fn register(db: &PgPool, withdrawal_id: &str, binding: &Binding) -> Result<(), Error> {
    let inserted = sqlx::query(
        "INSERT INTO bindings (withdrawal_id, l2_index, l1_destination, l1_sats, l2_sats)
         VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
    )
    .bind(withdrawal_id)
    .bind(i64::from(binding.l2_index))
    .bind(&binding.l1_destination)
    .bind(db_sats(binding.l1_sats)?)
    .bind(db_sats(binding.l2_sats)?)
    .execute(db)
    .await?
    .rows_affected();
    if inserted == 1 {
        return Ok(());
    }
    match get_binding(db, withdrawal_id).await? {
        Some(existing)
            if existing.l2_index == binding.l2_index
                && existing.l1_destination == binding.l1_destination
                && existing.l1_sats == binding.l1_sats
                && existing.l2_sats == binding.l2_sats =>
        {
            Ok(())
        }
        _ => Err(Error::AlreadyExists(
            "withdrawal or L2 index is already registered differently".to_owned(),
        )),
    }
}

pub async fn get_binding(db: &PgPool, withdrawal_id: &str) -> Result<Option<Binding>, Error> {
    let row = sqlx::query("SELECT * FROM bindings WHERE withdrawal_id = $1")
        .bind(withdrawal_id)
        .fetch_optional(db)
        .await?;
    Ok(row.map(|row| Binding {
        l2_index: u32::try_from(row.get::<i64, _>("l2_index")).unwrap_or_default(),
        l1_destination: row.get("l1_destination"),
        l1_sats: sats(row.get("l1_sats")),
        l2_sats: sats(row.get("l2_sats")),
    }))
}

/// The payout for a withdrawal and whether it is settled.
pub async fn get_payout(
    db: impl sqlx::PgExecutor<'_>,
    withdrawal_id: &str,
) -> Result<Option<(Payout, bool)>, Error> {
    let row = sqlx::query("SELECT * FROM payouts WHERE withdrawal_id = $1")
        .bind(withdrawal_id)
        .fetch_optional(db)
        .await?;
    Ok(row.map(|row| (Payout::from_row(&row), row.get("confirmed"))))
}

pub async fn unconfirmed_payouts(db: &PgPool) -> Result<Vec<Payout>, Error> {
    let rows = sqlx::query("SELECT * FROM payouts WHERE NOT confirmed ORDER BY id")
        .fetch_all(db)
        .await?;
    Ok(rows.iter().map(Payout::from_row).collect())
}

/// Marks a payout settled with `txid`, whichever of its versions that is.
pub async fn mark_settled(db: &PgPool, withdrawal_id: &str, txid: &str) -> Result<(), Error> {
    sqlx::query(
        "UPDATE payouts SET confirmed = true, txid = v.txid, raw_tx = v.raw_tx,
            fee_sats = v.fee_sats
         FROM payout_versions v
         WHERE payouts.withdrawal_id = $1 AND v.txid = $2 AND v.withdrawal_id = $1",
    )
    .bind(withdrawal_id)
    .bind(txid)
    .execute(db)
    .await?;
    Ok(())
}

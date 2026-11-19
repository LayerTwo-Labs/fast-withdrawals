//! Postgres state for withdrawals.

use sqlx::{PgConnection, PgPool, Row as _, postgres::PgRow};

use crate::service::Error;

/// Matches `fastwithdraw.v1.WithdrawalStatus`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum Status {
    AwaitingPayment = 1,
    ConfirmingPayment = 2,
    PaymentConfirmed = 3,
    Paid = 4,
    Expired = 5,
    /// The wallet refused the payout for a reason retrying won't fix.
    Failed = 6,
    /// A confirmed payment smaller than the quote; refunded on request.
    Underpaid = 7,
    Refunded = 8,
}

impl Status {
    fn from_db(value: i32) -> Self {
        match value {
            1 => Self::AwaitingPayment,
            2 => Self::ConfirmingPayment,
            3 => Self::PaymentConfirmed,
            4 => Self::Paid,
            5 => Self::Expired,
            7 => Self::Underpaid,
            8 => Self::Refunded,
            _ => Self::Failed,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Withdrawal {
    pub id: String,
    pub request_id: String,
    pub request_hash: Vec<u8>,
    pub sidechain: String,
    pub l2_index: u32,
    pub l2_address: String,
    pub l2_payment_sats: u64,
    pub l1_destination: String,
    pub l1_payout_sats: u64,
    pub service_fee_sats: u64,
    pub payout_reserve_sats: u64,
    pub required_confirmations: u32,
    pub status: Status,
    /// Unix seconds.
    pub expires_at: i64,
    pub payment: Option<(String, u32)>,
    /// Where the payment was mined, when known.
    pub payment_block: Option<fastwithdraw_thunder::BlockRef>,
    pub payment_confirmations: u32,
    pub payout_txid: Option<String>,
    /// What an underpaying payment paid.
    pub received_sats: Option<u64>,
    pub refund_address: Option<String>,
    /// An underpayment the current payment replaced.
    pub replaced_underpayment: Option<(String, u32)>,
    pub quote_signature: Vec<u8>,
    pub created_at: i64,
    pub updated_at: i64,
}

fn to_u64(value: i64) -> u64 {
    u64::try_from(value).unwrap_or_default()
}

fn to_u32(value: i64) -> u32 {
    u32::try_from(value).unwrap_or_default()
}

fn to_db(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

const COLUMNS: &str = "id, request_id, request_hash, sidechain, l2_index, l2_address,
    l2_payment_sats, l1_destination, l1_payout_sats, service_fee_sats, payout_reserve_sats,
    required_confirmations, status, extract(epoch FROM expires_at)::BIGINT AS expires_at,
    payment_txid, payment_vout, payment_confirmations, payment_block_height,
    payment_block_hash, payout_txid, received_sats, refund_address, quote_signature,
    underpaid_txid, underpaid_vout,
    extract(epoch FROM created_at)::BIGINT AS created_at,
    extract(epoch FROM updated_at)::BIGINT AS updated_at";

impl Withdrawal {
    fn from_row(row: &PgRow) -> Self {
        let txid: Option<String> = row.get("payment_txid");
        let vout: Option<i64> = row.get("payment_vout");
        let block_height: Option<i64> = row.get("payment_block_height");
        let block_hash: Option<String> = row.get("payment_block_hash");
        Self {
            id: row.get("id"),
            request_id: row.get("request_id"),
            request_hash: row.get("request_hash"),
            sidechain: row.get("sidechain"),
            l2_index: to_u32(row.get("l2_index")),
            l2_address: row.get("l2_address"),
            l2_payment_sats: to_u64(row.get("l2_payment_sats")),
            l1_destination: row.get("l1_destination"),
            l1_payout_sats: to_u64(row.get("l1_payout_sats")),
            service_fee_sats: to_u64(row.get("service_fee_sats")),
            payout_reserve_sats: to_u64(row.get("payout_reserve_sats")),
            required_confirmations: to_u32(row.get::<i32, _>("required_confirmations").into()),
            status: Status::from_db(row.get("status")),
            expires_at: row.get("expires_at"),
            payment: txid.zip(vout.map(to_u32)),
            payment_block: block_hash.zip(block_height).map(|(hash, height)| {
                fastwithdraw_thunder::BlockRef {
                    height: to_u32(height),
                    hash,
                }
            }),
            payment_confirmations: to_u32(
                row.get::<Option<i32>, _>("payment_confirmations")
                    .unwrap_or_default()
                    .into(),
            ),
            payout_txid: row.get("payout_txid"),
            received_sats: row.get::<Option<i64>, _>("received_sats").map(to_u64),
            refund_address: row.get("refund_address"),
            replaced_underpayment: row
                .get::<Option<String>, _>("underpaid_txid")
                .zip(row.get::<Option<i64>, _>("underpaid_vout").map(to_u32)),
            quote_signature: row.get("quote_signature"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        }
    }
}

pub async fn migrate(db: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations").run(db).await
}

pub async fn get(db: &PgPool, id: &str) -> Result<Option<Withdrawal>, Error> {
    let row = sqlx::query(&format!("SELECT {COLUMNS} FROM withdrawals WHERE id = $1"))
        .bind(id)
        .fetch_optional(db)
        .await?;
    Ok(row.as_ref().map(Withdrawal::from_row))
}

pub async fn get_by_request(db: &PgPool, request_id: &str) -> Result<Option<Withdrawal>, Error> {
    let mut conn = db.acquire().await?;
    get_by_request_on(&mut conn, request_id).await
}

async fn get_by_request_on(
    conn: &mut PgConnection,
    request_id: &str,
) -> Result<Option<Withdrawal>, Error> {
    let row = sqlx::query(&format!(
        "SELECT {COLUMNS} FROM withdrawals WHERE request_id = $1"
    ))
    .bind(request_id)
    .fetch_optional(conn)
    .await?;
    Ok(row.as_ref().map(Withdrawal::from_row))
}

pub async fn by_status(db: &PgPool, statuses: &[Status]) -> Result<Vec<Withdrawal>, Error> {
    let statuses: Vec<i32> = statuses.iter().map(|status| *status as i32).collect();
    let rows = sqlx::query(&format!(
        "SELECT {COLUMNS} FROM withdrawals WHERE status = ANY($1) ORDER BY created_at"
    ))
    .bind(statuses)
    .fetch_all(db)
    .await?;
    Ok(rows.iter().map(Withdrawal::from_row).collect())
}

/// Quotes whose addresses are watched for payments: awaiting payment, expired
/// within the last hour (later payments are reported with SubmitPayment), and
/// underpaid ones until a refund is requested or a week has passed (a full
/// payment still pays them out). Unpaid quotes cost nothing to ask for, so
/// this keeps what one client can add to every tick small. Matches the
/// `withdrawals_watched` index.
const WATCHED: &str = "status = 1
    OR (status = 5 AND expires_at > now() - interval '1 hour')
    OR (status = 7 AND refund_address IS NULL AND created_at > now() - interval '7 days')";

pub async fn watched(db: &PgPool) -> Result<Vec<Withdrawal>, Error> {
    let rows = sqlx::query(&format!(
        "SELECT {COLUMNS} FROM withdrawals WHERE {WATCHED}"
    ))
    .fetch_all(db)
    .await?;
    Ok(rows.iter().map(Withdrawal::from_row).collect())
}

pub async fn watched_count(db: &PgPool) -> Result<u64, Error> {
    let count: i64 =
        sqlx::query_scalar(&format!("SELECT count(*) FROM withdrawals WHERE {WATCHED}"))
            .fetch_one(db)
            .await?;
    Ok(to_u64(count))
}

/// Quotes `client_key` asked for that are still awaiting payment.
pub async fn open_quotes(db: &PgPool, client_key: &str) -> Result<u64, Error> {
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM withdrawals
         WHERE client_key = $1 AND status = $2 AND expires_at > now()",
    )
    .bind(client_key)
    .bind(Status::AwaitingPayment as i32)
    .fetch_one(db)
    .await?;
    Ok(to_u64(count))
}

/// The next L2 receive index. Never reused; gaps are fine.
pub async fn next_index(db: &PgPool) -> Result<u32, Error> {
    let index: i64 = sqlx::query_scalar("SELECT nextval('l2_index_seq')")
        .fetch_one(db)
        .await?;
    u32::try_from(index).map_err(|_| Error::Internal(anyhow::anyhow!("L2 index exhausted")))
}

/// Receive indexes of paid-out withdrawals, ascending.
pub async fn paid_indexes(db: &PgPool) -> Result<Vec<u32>, Error> {
    let indexes: Vec<i64> =
        sqlx::query_scalar("SELECT l2_index FROM withdrawals WHERE status = $1 ORDER BY l2_index")
            .bind(Status::Paid as i32)
            .fetch_all(db)
            .await?;
    indexes
        .into_iter()
        .map(|index| {
            u32::try_from(index)
                .map_err(|_| Error::Internal(anyhow::anyhow!("L2 index out of range")))
        })
        .collect()
}

/// Fields of a new, signed quote.
pub struct NewQuote<'a> {
    pub id: &'a str,
    pub request_id: &'a str,
    pub request_hash: &'a [u8],
    pub sidechain: &'a str,
    pub l2_index: u32,
    pub l2_address: &'a str,
    pub l1_destination: &'a str,
    pub l1_payout_sats: u64,
    pub service_fee_sats: u64,
    pub payout_reserve_sats: u64,
    pub required_confirmations: u32,
    pub quote_signature: &'a [u8],
    pub created_at: i64,
    pub expires_at: i64,
    /// See [`open_quotes`].
    pub client_key: Option<&'a str>,
}

pub enum Created {
    /// The request ID was already used with the same parameters.
    Existing(Box<Withdrawal>),
    New,
}

/// Inserts a quote unless its request ID exists. Quotes reserve no
/// liquidity: payouts queue at the wallet until it can fund them.
pub async fn insert_quote(db: &PgPool, quote: NewQuote<'_>) -> Result<Created, Error> {
    let l2_payment_sats = quote.l1_payout_sats + quote.service_fee_sats;
    let inserted = sqlx::query(
        "INSERT INTO withdrawals (id, request_id, request_hash, sidechain, l2_index, l2_address,
            l2_payment_sats, l1_destination, l1_payout_sats, service_fee_sats, payout_reserve_sats,
            required_confirmations, status, expires_at, quote_signature, created_at, updated_at,
            client_key)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
                 to_timestamp($14), $15, to_timestamp($16), to_timestamp($16), $17)
         ON CONFLICT (request_id) DO NOTHING",
    )
    .bind(quote.id)
    .bind(quote.request_id)
    .bind(quote.request_hash)
    .bind(quote.sidechain)
    .bind(i64::from(quote.l2_index))
    .bind(quote.l2_address)
    .bind(to_db(l2_payment_sats))
    .bind(quote.l1_destination)
    .bind(to_db(quote.l1_payout_sats))
    .bind(to_db(quote.service_fee_sats))
    .bind(to_db(quote.payout_reserve_sats))
    .bind(i32::try_from(quote.required_confirmations).unwrap_or(i32::MAX))
    .bind(Status::AwaitingPayment as i32)
    .bind(quote.expires_at)
    .bind(quote.quote_signature)
    .bind(quote.created_at)
    .bind(quote.client_key)
    .execute(db)
    .await?
    .rows_affected();
    if inserted == 1 {
        return Ok(Created::New);
    }
    // A concurrent request with the same ID won.
    match get_by_request(db, quote.request_id).await? {
        Some(existing) if existing.request_hash == quote.request_hash => {
            Ok(Created::Existing(Box::new(existing)))
        }
        _ => Err(Error::RequestConflict),
    }
}

/// Paid withdrawals whose payout the wallet hasn't settled yet; it may still
/// be fee-bumped to a new txid.
pub async fn unsettled_payouts(db: &PgPool) -> Result<Vec<Withdrawal>, Error> {
    let rows = sqlx::query(&format!(
        "SELECT {COLUMNS} FROM withdrawals
         WHERE status = $1 AND NOT payout_settled AND updated_at > now() - interval '7 days'"
    ))
    .bind(Status::Paid as i32)
    .fetch_all(db)
    .await?;
    Ok(rows.iter().map(Withdrawal::from_row).collect())
}

pub async fn update_payout(db: &PgPool, id: &str, txid: &str, settled: bool) -> Result<(), Error> {
    sqlx::query(
        "UPDATE withdrawals SET payout_txid = $2, payout_settled = $3, updated_at = now()
         WHERE id = $1 AND status = $4",
    )
    .bind(id)
    .bind(txid)
    .bind(settled)
    .bind(Status::Paid as i32)
    .execute(db)
    .await?;
    Ok(())
}

/// Claims a payment for withdrawal `id`, or refreshes the claimed one's
/// block and confirmations. A payment already claimed by another withdrawal
/// fails with [`Error::PaymentClaimed`]. A full payment also replaces an
/// underpayment until a refund is requested: else anyone could get dust to
/// the quote address confirmed first and block the customer's payout.
/// Returns whether the withdrawal was open to the payment.
pub async fn record_payment(
    db: &PgPool,
    id: &str,
    payment: &fastwithdraw_thunder::Payment,
    confirmed: bool,
) -> Result<bool, Error> {
    let status = if confirmed {
        Status::PaymentConfirmed
    } else {
        Status::ConfirmingPayment
    };
    let result = sqlx::query(
        "UPDATE withdrawals SET payment_txid = $2, payment_vout = $3, payment_confirmations = $4,
            payment_block_height = $5, payment_block_hash = $6, status = $7, updated_at = now(),
            confirmed_at = CASE WHEN $9 THEN COALESCE(confirmed_at, now()) END,
            underpaid_txid = CASE WHEN status = $10 THEN payment_txid ELSE underpaid_txid END,
            underpaid_vout = CASE WHEN status = $10 THEN payment_vout ELSE underpaid_vout END
         WHERE id = $1
           AND ((status = ANY($8)
                 AND (payment_txid IS NULL OR (payment_txid = $2 AND payment_vout = $3)))
                OR (status = $10 AND refund_address IS NULL))",
    )
    .bind(id)
    .bind(&payment.outpoint.txid)
    .bind(i64::from(payment.outpoint.vout))
    .bind(i32::try_from(payment.confirmations).unwrap_or(i32::MAX))
    .bind(payment.block.as_ref().map(|block| i64::from(block.height)))
    .bind(payment.block.as_ref().map(|block| block.hash.clone()))
    .bind(status as i32)
    .bind(vec![
        Status::AwaitingPayment as i32,
        Status::Expired as i32,
        Status::ConfirmingPayment as i32,
        Status::PaymentConfirmed as i32,
    ])
    .bind(confirmed)
    .bind(Status::Underpaid as i32)
    .execute(db)
    .await;
    match result {
        Ok(result) => Ok(result.rows_affected() == 1),
        Err(sqlx::Error::Database(err)) if err.is_unique_violation() => Err(Error::PaymentClaimed),
        Err(err) => Err(err.into()),
    }
}

/// Withdrawals whose payment confirmed over 10 minutes ago without a payout:
/// the wallet is out of funds, at a cap, or refusing for now.
pub async fn payouts_waiting(db: &PgPool) -> Result<i64, Error> {
    Ok(sqlx::query_scalar(
        "SELECT count(*) FROM withdrawals
         WHERE status = $1 AND confirmed_at < now() - interval '10 minutes'",
    )
    .bind(Status::PaymentConfirmed as i32)
    .fetch_one(db)
    .await?)
}

/// Forgets a payment that left the active chain, back to the underpayment it
/// replaced if there was one.
pub async fn clear_payment(db: &PgPool, id: &str) -> Result<(), Error> {
    sqlx::query(
        "UPDATE withdrawals SET payment_txid = underpaid_txid, payment_vout = underpaid_vout,
            underpaid_txid = NULL, underpaid_vout = NULL,
            payment_confirmations = NULL, payment_block_height = NULL,
            payment_block_hash = NULL, confirmed_at = NULL, updated_at = now(),
            status = CASE WHEN underpaid_txid IS NOT NULL THEN $5
                          WHEN expires_at <= now() THEN $2 ELSE $3 END
         WHERE id = $1 AND status = ANY($4)",
    )
    .bind(id)
    .bind(Status::Expired as i32)
    .bind(Status::AwaitingPayment as i32)
    .bind(vec![
        Status::ConfirmingPayment as i32,
        Status::PaymentConfirmed as i32,
    ])
    .bind(Status::Underpaid as i32)
    .execute(db)
    .await?;
    Ok(())
}

/// Records the payout. The wallet has paid, so this wins over any state a
/// concurrent tick may have moved the row to.
pub async fn mark_paid(db: &PgPool, id: &str, payout_txid: &str) -> Result<(), Error> {
    sqlx::query(
        "UPDATE withdrawals SET status = $2, payout_txid = $3, updated_at = now()
         WHERE id = $1 AND status <> $2",
    )
    .bind(id)
    .bind(Status::Paid as i32)
    .bind(payout_txid)
    .execute(db)
    .await?;
    Ok(())
}

/// Parks a withdrawal the wallet won't pay, for a human to resolve.
pub async fn mark_failed(db: &PgPool, id: &str, reason: &str) -> Result<(), Error> {
    sqlx::query(
        "UPDATE withdrawals SET status = $2, failure_reason = $3, updated_at = now()
         WHERE id = $1 AND status = ANY($4)",
    )
    .bind(id)
    .bind(Status::Failed as i32)
    .bind(reason)
    .bind(vec![
        Status::ConfirmingPayment as i32,
        Status::PaymentConfirmed as i32,
    ])
    .execute(db)
    .await?;
    Ok(())
}

/// Records a confirmed payment smaller than the quote. Returns whether the
/// withdrawal was still open to it.
pub async fn mark_underpaid(
    db: &PgPool,
    id: &str,
    payment: &fastwithdraw_thunder::Payment,
) -> Result<bool, Error> {
    let result = sqlx::query(
        "UPDATE withdrawals SET status = $2, payment_txid = $3, payment_vout = $4,
            received_sats = $5, updated_at = now()
         WHERE id = $1 AND status = ANY($6) AND payment_txid IS NULL",
    )
    .bind(id)
    .bind(Status::Underpaid as i32)
    .bind(&payment.outpoint.txid)
    .bind(i64::from(payment.outpoint.vout))
    .bind(to_db(payment.sats))
    .bind(vec![Status::AwaitingPayment as i32, Status::Expired as i32])
    .execute(db)
    .await;
    match result {
        Ok(result) => Ok(result.rows_affected() == 1),
        Err(sqlx::Error::Database(err)) if err.is_unique_violation() => Ok(false),
        Err(err) => Err(err.into()),
    }
}

/// Whether `address` is a quote's payment address, under the cold key.
pub async fn is_quote_address(db: &PgPool, address: &str) -> Result<bool, Error> {
    Ok(
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM withdrawals WHERE l2_address = $1)")
            .bind(address)
            .fetch_one(db)
            .await?,
    )
}

/// Sets an underpaid withdrawal's refund address, once.
pub async fn set_refund_address(db: &PgPool, id: &str, address: &str) -> Result<(), Error> {
    sqlx::query(
        "UPDATE withdrawals SET refund_address = $3, updated_at = now()
         WHERE id = $1 AND status = $2 AND refund_address IS NULL",
    )
    .bind(id)
    .bind(Status::Underpaid as i32)
    .bind(address)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn mark_refunded(db: &PgPool, id: &str) -> Result<(), Error> {
    sqlx::query(
        "UPDATE withdrawals SET status = $2, updated_at = now()
         WHERE id = $1 AND status = $3 AND refund_address IS NOT NULL",
    )
    .bind(id)
    .bind(Status::Refunded as i32)
    .bind(Status::Underpaid as i32)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn expire_quotes(db: &PgPool) -> Result<(), Error> {
    sqlx::query(
        "UPDATE withdrawals SET status = $1, updated_at = now()
         WHERE status = $2 AND expires_at <= now()",
    )
    .bind(Status::Expired as i32)
    .bind(Status::AwaitingPayment as i32)
    .execute(db)
    .await?;
    // Only open quotes count against their client.
    sqlx::query(
        "UPDATE withdrawals SET client_key = NULL
         WHERE client_key IS NOT NULL AND (status <> $1 OR expires_at <= now())",
    )
    .bind(Status::AwaitingPayment as i32)
    .execute(db)
    .await?;
    Ok(())
}

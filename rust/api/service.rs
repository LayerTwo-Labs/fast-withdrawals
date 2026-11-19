//! Withdrawal logic: signed quotes, L2 payment detection, and payouts through
//! the wallet service.

use std::{str::FromStr as _, sync::Arc, time::SystemTime};

use fastwithdraw_signer::QuoteSigner;
use fastwithdraw_thunder as thunder;
use sha2::{Digest as _, Sha256};
use sqlx::PgPool;
use thiserror::Error;

use crate::{
    store::{self, Created, NewQuote, Status, Withdrawal},
    wallet_client::{WalletClient, WalletStatus},
};

const QUOTE_DOMAIN: &[u8] = b"fastwithdraw.quote.v1\0";
const REQUEST_DOMAIN: &[u8] = b"fastwithdraw.request.v1\0";
/// The only sidechain this service supports.
pub const SIDECHAIN: &str = "thunder";
const MAX_SUPPLY_SATS: u64 = 2_100_000_000_000_000;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    InvalidArgument(String),
    #[error("withdrawal not found")]
    NotFound,
    #[error("request id was already used with different parameters")]
    RequestConflict,
    #[error("payment output is already claimed")]
    PaymentClaimed,
    #[error("withdrawal state changed")]
    StateConflict,
    #[error("liquidity exposure limit exceeded")]
    LiquidityExceeded,
    #[error("{0}")]
    TooManyQuotes(&'static str),
    #[error("payouts are paused: Thunder may have stopped following L1")]
    ThunderStale,
    #[error("only an underpaid withdrawal can be refunded")]
    NotUnderpaid,
    #[error("a different refund address was already given")]
    RefundAddressConflict,
    #[error("thunder: {0}")]
    Thunder(#[from] thunder::rpc::Error),
    #[error("wallet: {0}")]
    Wallet(connectrpc::ConnectError),
    #[error("database: {0}")]
    Database(#[from] sqlx::Error),
    #[error("signer: {0}")]
    Signer(#[from] fastwithdraw_signer::Error),
    #[error(transparent)]
    Internal(anyhow::Error),
}

fn invalid(msg: impl Into<String>) -> Error {
    Error::InvalidArgument(msg.into())
}

/// Whether a failed `Pay` may simply be retried on the next tick. The wallet
/// is idempotent and re-verifies everything, so these are safe: it was
/// unreachable, out of funds or caps for now, or doesn't yet consider the
/// payment confirmed; or it failed in a way that says nothing about the
/// payout (unknown or internal errors, eg. a crash after broadcasting), or
/// the api couldn't authenticate to it (eg. mid-deploy). Anything else needs
/// a human.
fn retry_is_safe(err: &connectrpc::ConnectError) -> bool {
    use connectrpc::error::ErrorCode;
    matches!(
        err.code,
        ErrorCode::Unavailable
            | ErrorCode::DeadlineExceeded
            | ErrorCode::ResourceExhausted
            | ErrorCode::FailedPrecondition
            | ErrorCode::Unknown
            | ErrorCode::Internal
            | ErrorCode::Unauthenticated
            | ErrorCode::PermissionDenied
    )
}

/// What GetStatus reports.
pub struct ServiceStatus {
    /// None while the wallet can't be reached.
    pub wallet: Option<WalletStatus>,
    /// The largest payout a new quote may request, or why none can be quoted.
    pub max_payout_now: Result<u64, String>,
}

#[derive(Clone, Copy, Debug)]
pub struct Policy {
    pub fee_basis_points: u32,
    pub min_payout_sats: u64,
    pub max_payout_sats: u64,
    pub max_exposure_bps: u32,
    pub miner_fee_reserve_sats: u64,
    pub required_confirmations: u32,
    pub quote_ttl_secs: i64,
    /// Open quotes one client (IPv4 address or IPv6 /64) may have.
    pub max_open_quotes_per_client: u64,
    /// Quotes watched for payments at once, across all clients. Each tick
    /// checks every watched address, so this bounds its work.
    pub max_watched_quotes: u64,
}

impl Policy {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.fee_basis_points > 10_000
            || self.max_exposure_bps == 0
            || self.max_exposure_bps > 10_000
        {
            return Err("invalid basis-point configuration");
        }
        if self.min_payout_sats == 0
            || self.max_payout_sats < self.min_payout_sats
            || self.max_payout_sats > MAX_SUPPLY_SATS
            || self.miner_fee_reserve_sats == 0
            || self
                .max_payout_sats
                .checked_add(self.miner_fee_reserve_sats)
                .is_none()
        {
            return Err("invalid payout limits");
        }
        if self.quote_ttl_secs <= 0 || self.quote_ttl_secs > 24 * 3600 {
            return Err("quote TTL must be between zero and 24 hours");
        }
        if self.required_confirmations == 0 {
            return Err("required confirmations must be positive");
        }
        Ok(())
    }
}

pub struct Service {
    pub(crate) db: PgPool,
    thunder: thunder::Client,
    xpub: thunder::Xpub,
    wallet: WalletClient,
    signer: Arc<dyn QuoteSigner>,
    network: bitcoin::Network,
    pub(crate) policy: Policy,
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        })
}

fn floor_bps(value: u64, bps: u32) -> u64 {
    value / 10_000 * u64::from(bps) + value % 10_000 * u64::from(bps) / 10_000
}

fn ceil_bps(value: u64, bps: u32) -> u64 {
    value / 10_000 * u64::from(bps) + (value % 10_000 * u64::from(bps)).div_ceil(10_000)
}

/// Length-prefixes each part with its eight-byte big-endian size.
fn canonical(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for part in parts {
        out.extend_from_slice(&(part.len() as u64).to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

fn hash_request(request_id: &str, destination: &str, payout: u64) -> Vec<u8> {
    Sha256::digest(canonical(&[
        REQUEST_DOMAIN,
        request_id.as_bytes(),
        SIDECHAIN.as_bytes(),
        destination.as_bytes(),
        &payout.to_be_bytes(),
    ]))
    .to_vec()
}

/// The bytes a quote signature covers; see `Withdrawal.quote_signature` in
/// `fastwithdraw.proto`.
#[expect(clippy::too_many_arguments)]
pub fn quote_bytes(
    id: &str,
    l2_address: &str,
    l2_payment_sats: u64,
    l1_destination: &str,
    l1_payout_sats: u64,
    fee_sats: u64,
    required_confirmations: u32,
    expires_at: i64,
) -> Vec<u8> {
    canonical(&[
        QUOTE_DOMAIN,
        id.as_bytes(),
        SIDECHAIN.as_bytes(),
        l2_address.as_bytes(),
        &l2_payment_sats.to_be_bytes(),
        l1_destination.as_bytes(),
        &l1_payout_sats.to_be_bytes(),
        &fee_sats.to_be_bytes(),
        &u64::from(required_confirmations).to_be_bytes(),
        &(expires_at as u64).to_be_bytes(),
    ])
}

pub struct Parts {
    pub db: PgPool,
    pub thunder: thunder::Client,
    pub xpub: thunder::Xpub,
    pub wallet: WalletClient,
    pub signer: Arc<dyn QuoteSigner>,
    pub network: bitcoin::Network,
    pub policy: Policy,
}

impl Service {
    /// The address payouts are sent from, or empty while the wallet can't be
    /// reached: GetServiceInfo doesn't depend on the wallet otherwise.
    pub(crate) async fn hot_wallet_address(&self) -> String {
        self.wallet.address().await.unwrap_or_else(|err| {
            tracing::warn!("wallet address: {err}");
            String::new()
        })
    }

    pub fn new(parts: Parts) -> Self {
        Self {
            db: parts.db,
            thunder: parts.thunder,
            xpub: parts.xpub,
            wallet: parts.wallet,
            signer: parts.signer,
            network: parts.network,
            policy: parts.policy,
        }
    }

    pub fn quote_public_key(&self) -> [u8; 32] {
        self.signer.public_key().to_bytes()
    }

    /// `client_key` identifies who asks, for the per-client cap on open
    /// quotes; None skips it (no client address, eg. in tests).
    pub async fn create(
        &self,
        request_id: &str,
        sidechain: &str,
        destination: &str,
        payout: u64,
        client_key: Option<&str>,
    ) -> Result<Withdrawal, Error> {
        let request_id = uuid::Uuid::parse_str(request_id)
            .ok()
            .filter(|id| !id.is_nil())
            .ok_or_else(|| invalid("request_id must be a non-nil UUID"))?
            .to_string();
        if !sidechain.trim().eq_ignore_ascii_case(SIDECHAIN) {
            return Err(invalid("unsupported sidechain"));
        }
        if payout < self.policy.min_payout_sats || payout > self.policy.max_payout_sats {
            return Err(invalid("payout is outside configured limits"));
        }
        bitcoin::Address::from_str(destination)
            .ok()
            .filter(|address| address.is_valid_for_network(self.network))
            .ok_or_else(|| invalid("invalid bitcoin destination address"))?;

        let request_hash = hash_request(&request_id, destination, payout);
        // A retry returns the existing quote even when liquidity has changed.
        if let Some(existing) = store::get_by_request(&self.db, &request_id).await? {
            if existing.request_hash != request_hash {
                return Err(Error::RequestConflict);
            }
            return Ok(existing);
        }
        // Quotes are free to ask for, but every one is watched for payments
        // until an hour after it expires. Soft limits: concurrent requests may
        // overshoot a little.
        if let Some(client_key) = client_key
            && store::open_quotes(&self.db, client_key).await?
                >= self.policy.max_open_quotes_per_client
        {
            return Err(Error::TooManyQuotes(
                "too many open quotes; pay or let one expire first",
            ));
        }
        if store::watched_count(&self.db).await? >= self.policy.max_watched_quotes {
            tracing::warn!("watched quote limit reached; refusing new quotes");
            return Err(Error::TooManyQuotes(
                "the service is not taking new quotes right now",
            ));
        }
        let fee = ceil_bps(payout, self.policy.fee_basis_points);
        // A soft check against the cached balance: quotes reserve nothing, so
        // they can't be used to lock others out. Paid withdrawals queue at
        // the wallet until it can fund them.
        let wallet = self.wallet.status().await.map_err(Error::Wallet)?;
        if payout > self.max_payout_now(&wallet)? {
            return Err(Error::LiquidityExceeded);
        }
        let reserve = payout + self.policy.miner_fee_reserve_sats;
        let id = uuid::Uuid::new_v4().to_string();
        let created_at = now();
        let expires_at = created_at + self.policy.quote_ttl_secs;
        let required_confirmations = self.policy.required_confirmations;
        let l2_index = store::next_index(&self.db).await?;
        let l2_address = self
            .xpub
            .address(l2_index)
            .map_err(|err| Error::Internal(err.into()))?
            .to_string();
        let message = quote_bytes(
            &id,
            &l2_address,
            payout + fee,
            destination,
            payout,
            fee,
            required_confirmations,
            expires_at,
        );
        let signature = self.signer.sign(&message).await?.to_bytes();
        // The wallet only ever pays this quote to this destination.
        self.wallet
            .register_quote(&id, l2_index, destination, payout, payout + fee)
            .await
            .map_err(|err| match err.code {
                // Eg. a destination the wallet won't pay: the client's to fix.
                connectrpc::error::ErrorCode::InvalidArgument => {
                    invalid(err.message.unwrap_or_default())
                }
                _ => Error::Wallet(err),
            })?;
        let created = store::insert_quote(
            &self.db,
            NewQuote {
                id: &id,
                request_id: &request_id,
                request_hash: &request_hash,
                sidechain: SIDECHAIN,
                l2_index,
                l2_address: &l2_address,
                l1_destination: destination,
                l1_payout_sats: payout,
                service_fee_sats: fee,
                payout_reserve_sats: reserve,
                required_confirmations,
                quote_signature: &signature,
                created_at,
                expires_at,
                client_key,
            },
        )
        .await?;
        match created {
            Created::Existing(existing) => Ok(*existing),
            Created::New => self.get(&id).await,
        }
    }

    /// The largest payout a new quote may request, or why none can be quoted.
    fn max_payout_now(&self, wallet: &WalletStatus) -> Result<u64, Error> {
        // Payouts wait until Thunder catches up; don't take new payments
        // meanwhile.
        if !wallet.thunder_synced {
            return Err(Error::ThunderStale);
        }
        let max = floor_bps(wallet.spendable_sats, self.policy.max_exposure_bps)
            .saturating_sub(self.policy.miner_fee_reserve_sats)
            .min(self.policy.max_payout_sats);
        if max < self.policy.min_payout_sats {
            return Err(Error::LiquidityExceeded);
        }
        Ok(max)
    }

    /// Whether new withdrawals are accepted, and the wallet's view of L1 and
    /// Thunder. Never fails: an unreachable wallet is reported as the reason.
    pub async fn status(&self) -> ServiceStatus {
        let wallet = match self.wallet.status().await {
            Ok(wallet) => wallet,
            Err(err) => {
                tracing::warn!("wallet status: {err}");
                return ServiceStatus {
                    wallet: None,
                    max_payout_now: Err("the payout wallet is unavailable".to_owned()),
                };
            }
        };
        let max_payout_now = self.max_payout_now(&wallet).map_err(|err| match err {
            Error::ThunderStale => format!("{err}: {}", wallet.thunder_unsynced_reason),
            Error::LiquidityExceeded => {
                "the hot wallet can't fund a minimum payout right now".to_owned()
            }
            err => err.to_string(),
        });
        ServiceStatus {
            wallet: Some(wallet),
            max_payout_now,
        }
    }

    pub async fn get(&self, id: &str) -> Result<Withdrawal, Error> {
        uuid::Uuid::parse_str(id).map_err(|_| invalid("invalid withdrawal_id"))?;
        store::get(&self.db, id).await?.ok_or(Error::NotFound)
    }

    /// Records a customer-reported payment, then advances the withdrawal.
    /// Reporting a payment is optional: [`Self::tick`] finds payments on its
    /// own once they are in a block.
    pub async fn submit(&self, id: &str, txid: &str, vout: u32) -> Result<Withdrawal, Error> {
        let txid = txid.trim().to_ascii_lowercase();
        if txid.len() != 64 || hex::decode(&txid).is_err() {
            return Err(invalid("invalid transaction id"));
        }
        let withdrawal = self.get(id).await?;
        match (&withdrawal.status, &withdrawal.payment) {
            (Status::Paid, _) => return Ok(withdrawal),
            // The underpayment, reported again.
            (Status::Underpaid | Status::Refunded, Some((paid_txid, paid_vout)))
                if *paid_txid == txid && *paid_vout == vout =>
            {
                return Ok(withdrawal);
            }
            // A full payment replaces an underpayment; see `record_payment`.
            (Status::Underpaid, _) if withdrawal.refund_address.is_none() => {}
            (_, Some((paid_txid, paid_vout))) if *paid_txid != txid || *paid_vout != vout => {
                return Err(Error::StateConflict);
            }
            _ => {}
        }
        let outpoint = thunder::OutPoint { txid, vout };
        let address = Self::address(&withdrawal)?;
        let payment = self
            .thunder
            .payment(&outpoint, &address, withdrawal.payment_block.as_ref())
            .await?
            .ok_or_else(|| invalid("no unspent output pays the quote address"))?;
        if payment.sats < withdrawal.l2_payment_sats {
            // Eg. a late underpayment, after tick stopped watching the quote.
            if self.is_underpayment(&payment)
                && matches!(withdrawal.status, Status::AwaitingPayment | Status::Expired)
            {
                self.underpaid(&withdrawal, &payment).await?;
                return self.get(id).await;
            }
            return Err(invalid("payment is smaller than the quote"));
        }
        self.record(&withdrawal, &payment).await?;
        self.advance(&self.get(id).await?).await?;
        self.get(id).await
    }

    fn address(withdrawal: &Withdrawal) -> Result<thunder::Address, Error> {
        withdrawal
            .l2_address
            .parse()
            .map_err(|err| Error::Internal(anyhow::anyhow!("stored L2 address: {err}")))
    }

    async fn record(
        &self,
        withdrawal: &Withdrawal,
        payment: &thunder::Payment,
    ) -> Result<(), Error> {
        let recorded = store::record_payment(
            &self.db,
            &withdrawal.id,
            payment,
            payment.confirmations >= withdrawal.required_confirmations,
        )
        .await?;
        if recorded
            && withdrawal.status == Status::Underpaid
            && let Some((txid, vout)) = &withdrawal.payment
        {
            // The smaller payment is swept with the paid-out index; the
            // customer may still want it back.
            tracing::warn!(id = %withdrawal.id, "full payment replaced an underpayment");
            fastwithdraw_alerts::set(&self.db, &format!("underpaid:{}", withdrawal.id), None).await;
            fastwithdraw_alerts::set(
                &self.db,
                &format!("underpayment_replaced:{}", withdrawal.id),
                Some(format!(
                    "A full payment replaced withdrawal {}'s underpayment of {} sats \
                     ({txid}:{vout}) at L2 index {}. Once the withdrawal is paid out, that \
                     payment is swept with the index: refund it if the customer asks.",
                    withdrawal.id,
                    withdrawal.received_sats.unwrap_or_default(),
                    withdrawal.l2_index
                )),
            )
            .await;
        }
        Ok(())
    }

    /// Refreshes a recorded payment and pays out once it is confirmed.
    async fn advance(&self, withdrawal: &Withdrawal) -> Result<(), Error> {
        if !matches!(
            withdrawal.status,
            Status::ConfirmingPayment | Status::PaymentConfirmed
        ) {
            return Ok(());
        }
        let Some((txid, vout)) = withdrawal.payment.clone() else {
            return Ok(());
        };
        let outpoint = thunder::OutPoint { txid, vout };
        let payment = self
            .thunder
            .payment(
                &outpoint,
                &Self::address(withdrawal)?,
                withdrawal.payment_block.as_ref(),
            )
            .await?;
        tracing::debug!(id = %withdrawal.id, ?payment, status = ?withdrawal.status, "refreshed payment");
        // Still mined, or still pending for a payment that never confirmed.
        // A mined payment whose depth can't be established right now (eg. the
        // tip moved mid-scan) is kept, at zero confirmations.
        let Some(payment) = payment
            .filter(|payment| payment.mined || withdrawal.status == Status::ConfirmingPayment)
        else {
            tracing::warn!(id = %withdrawal.id, "payment left the active chain");
            store::clear_payment(&self.db, &withdrawal.id).await?;
            if withdrawal.replaced_underpayment.is_some() {
                // Back to UNDERPAID: the customer can ask for a refund again.
                let id = &withdrawal.id;
                fastwithdraw_alerts::set(&self.db, &format!("underpayment_replaced:{id}"), None)
                    .await;
                fastwithdraw_alerts::set(
                    &self.db,
                    &format!("underpaid:{id}"),
                    Some(format!(
                        "Withdrawal {id} is underpaid again: the full payment that replaced its \
                         underpayment left the chain. It is refunded once the customer gives a \
                         refund address (RequestRefund)."
                    )),
                )
                .await;
            }
            return Ok(());
        };
        if payment.confirmations < withdrawal.required_confirmations {
            return self.record(withdrawal, &payment).await;
        }
        self.record(withdrawal, &payment).await?;
        match self.wallet.pay(withdrawal, &payment).await {
            Ok(payout_txid) => {
                store::mark_paid(&self.db, &withdrawal.id, &payout_txid).await?;
                tracing::info!(id = %withdrawal.id, %payout_txid, "withdrawal paid");
                Ok(())
            }
            Err(err) if retry_is_safe(&err) => Err(Error::Wallet(err)),
            Err(err) => {
                fastwithdraw_alerts::set(
                    &self.db,
                    &format!("withdrawal_failed:{}", withdrawal.id),
                    Some(format!(
                        "Wallet refused the payout for withdrawal {}, which needs review: {err}",
                        withdrawal.id
                    )),
                )
                .await;
                store::mark_failed(&self.db, &withdrawal.id, &err.to_string()).await
            }
        }
    }

    /// Receive indexes of paid-out withdrawals, whose payments can be swept.
    pub async fn paid_indexes(&self) -> Result<Vec<u32>, Error> {
        store::paid_indexes(&self.db).await
    }

    /// Finds payments to open quote addresses, expires stale quotes, and
    /// advances confirming withdrawals. Called by a scheduler.
    /// Each step runs even if an earlier one fails; returns the first error.
    pub async fn tick(&self) -> Result<(), Error> {
        let detected = self.detect_payments().await;
        let expired = store::expire_quotes(&self.db).await;
        let advanced = self.advance_all().await;
        let refreshed = self.refresh_payouts().await;
        let refunded = self.check_refunds().await;
        let result = detected
            .and(expired)
            .and(advanced)
            .and(refreshed)
            .and(refunded);
        match store::payouts_waiting(&self.db).await {
            Ok(waiting) => {
                fastwithdraw_alerts::set(
                    &self.db,
                    "payouts_waiting",
                    (waiting > 0).then(|| {
                        format!(
                            "{waiting} paid withdrawals have waited over 10 minutes for a payout: \
                             the wallet is out of funds, at its daily cap, or paused"
                        )
                    }),
                )
                .await;
            }
            Err(err) => tracing::warn!("count waiting payouts: {err}"),
        }
        if result.is_ok() {
            fastwithdraw_alerts::heartbeat();
        }
        result
    }

    /// Picks up fee-bumped payout txids until the wallet settles them.
    async fn refresh_payouts(&self) -> Result<(), Error> {
        for withdrawal in store::unsettled_payouts(&self.db).await? {
            match self.wallet.get_payout(&withdrawal.id).await {
                Ok((txid, settled)) => {
                    if withdrawal.payout_txid.as_deref() != Some(&txid) || settled {
                        store::update_payout(&self.db, &withdrawal.id, &txid, settled).await?;
                    }
                }
                Err(err) => tracing::warn!(id = %withdrawal.id, "get payout: {err}"),
            }
        }
        Ok(())
    }

    async fn detect_payments(&self) -> Result<(), Error> {
        let watched = store::watched(&self.db).await?;
        let addresses = watched
            .iter()
            .filter_map(|w| w.l2_address.parse().ok())
            .collect::<Vec<thunder::Address>>();
        if addresses.is_empty() {
            return Ok(());
        }
        // Anything smaller than both the minimum payout and every watched
        // quote is neither a payment nor an underpayment, and recorded
        // underpayments are known: so dust and repeat lookups cost Thunder
        // nothing. (A quote can be below the minimum if it was raised since.)
        let min_sats = watched
            .iter()
            .map(|w| w.l2_payment_sats)
            .fold(self.policy.min_payout_sats, u64::min);
        let known = watched
            .iter()
            .filter_map(|w| w.payment.clone())
            .map(|(txid, vout)| thunder::OutPoint { txid, vout })
            .collect();
        let mut payments = self
            .thunder
            .unspent_payments(&addresses, min_sats, &known)
            .await?;
        // A full payment wins over a smaller one to the same address.
        payments.sort_by_key(|payment| std::cmp::Reverse(payment.sats));
        let by_address: std::collections::HashMap<&str, &Withdrawal> =
            watched.iter().map(|w| (w.l2_address.as_str(), w)).collect();
        for payment in payments {
            let address = payment.address.to_string();
            let Some(&withdrawal) = by_address.get(address.as_str()) else {
                continue;
            };
            let result = if payment.sats >= withdrawal.l2_payment_sats {
                self.record(withdrawal, &payment).await
            } else if self.is_underpayment(&payment) {
                self.underpaid(withdrawal, &payment).await
            } else {
                Ok(())
            };
            match result {
                Ok(()) | Err(Error::PaymentClaimed) => {}
                Err(err) => tracing::warn!(id = %withdrawal.id, "record payment: {err:#}"),
            }
        }
        Ok(())
    }

    /// Whether a payment smaller than its quote is parked as an underpayment:
    /// mined, and at least the minimum payout. Smaller ones are ignored, so
    /// dust can't make quotes UNDERPAID, which keeps them watched for a week.
    fn is_underpayment(&self, payment: &thunder::Payment) -> bool {
        payment.mined && payment.sats >= self.policy.min_payout_sats
    }

    /// Parks a confirmed payment smaller than its quote until the customer
    /// asks for a refund.
    async fn underpaid(
        &self,
        withdrawal: &Withdrawal,
        payment: &thunder::Payment,
    ) -> Result<(), Error> {
        if !store::mark_underpaid(&self.db, &withdrawal.id, payment).await? {
            return Ok(());
        }
        tracing::warn!(id = %withdrawal.id, sats = payment.sats, "withdrawal underpaid");
        fastwithdraw_alerts::set(
            &self.db,
            &format!("underpaid:{}", withdrawal.id),
            Some(format!(
                "Withdrawal {} was underpaid: {} of {} sats, at L2 index {}. It is refunded \
                 once the customer gives a refund address (RequestRefund).",
                withdrawal.id, payment.sats, withdrawal.l2_payment_sats, withdrawal.l2_index
            )),
        )
        .await;
        Ok(())
    }

    /// Records where to refund an underpaid withdrawal, once, and asks the
    /// operator to send the refund.
    pub async fn request_refund(&self, id: &str, address: &str) -> Result<Withdrawal, Error> {
        let withdrawal = self.get(id).await?;
        let parsed: thunder::Address = address
            .parse()
            .map_err(|_| invalid("invalid l2_refund_address"))?;
        // Only the canonical spelling, so the alert shows what was checked.
        if parsed.to_string() != address {
            return Err(invalid("invalid l2_refund_address"));
        }
        if store::is_quote_address(&self.db, address).await? {
            return Err(invalid(
                "l2_refund_address is one of this service's payment addresses",
            ));
        }
        match withdrawal.refund_address.as_deref() {
            Some(given) if given == address => return Ok(withdrawal),
            Some(_) => return Err(Error::RefundAddressConflict),
            None if withdrawal.status != Status::Underpaid => return Err(Error::NotUnderpaid),
            None => {}
        }
        store::set_refund_address(&self.db, id, address).await?;
        let withdrawal = self.get(id).await?;
        if withdrawal.refund_address.as_deref() != Some(address) {
            return Err(Error::RefundAddressConflict);
        }
        fastwithdraw_alerts::set(&self.db, &format!("underpaid:{id}"), None).await;
        fastwithdraw_alerts::set(
            &self.db,
            &format!("refund_requested:{id}"),
            Some(format!(
                "Refund withdrawal {id}: {} sats at L2 index {index} to {address}. With \
                 thunder-sweep: plan --index {index} --destination {address} (no --api-url), \
                 then sign with --destination {address} and check it lists only index {index}, \
                 then submit.",
                withdrawal.received_sats.unwrap_or_default(),
                index = withdrawal.l2_index,
            )),
        )
        .await;
        Ok(withdrawal)
    }

    /// Marks requested refunds done once the underpaid payment is spent.
    async fn check_refunds(&self) -> Result<(), Error> {
        for withdrawal in store::by_status(&self.db, &[Status::Underpaid]).await? {
            let (Some((txid, vout)), Some(_)) =
                (withdrawal.payment.clone(), &withdrawal.refund_address)
            else {
                continue;
            };
            let outpoint = thunder::OutPoint { txid, vout };
            let unspent = self
                .thunder
                .payment(&outpoint, &Self::address(&withdrawal)?, None)
                .await?;
            if unspent.is_none() {
                store::mark_refunded(&self.db, &withdrawal.id).await?;
                tracing::info!(id = %withdrawal.id, "withdrawal refunded");
                fastwithdraw_alerts::set(
                    &self.db,
                    &format!("refund_requested:{}", withdrawal.id),
                    None,
                )
                .await;
            }
        }
        Ok(())
    }

    async fn advance_all(&self) -> Result<(), Error> {
        let pending = store::by_status(
            &self.db,
            &[Status::ConfirmingPayment, Status::PaymentConfirmed],
        )
        .await?;
        for withdrawal in pending {
            if let Err(err) = self.advance(&withdrawal).await {
                tracing::warn!(id = %withdrawal.id, "advance withdrawal: {err:#}");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    /// Pins `quote_bytes` to the layout documented on
    /// `Withdrawal.quote_signature`, which clients verify against.
    #[test]
    fn quote_bytes_layout() {
        let mut expected = Vec::new();
        let mut part = |bytes: &[u8]| {
            expected.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            expected.extend_from_slice(bytes);
        };
        part(b"fastwithdraw.quote.v1\0");
        part(b"id");
        part(b"thunder");
        part(b"l2addr");
        part(&1_100u64.to_be_bytes());
        part(b"l1addr");
        part(&1_000u64.to_be_bytes());
        part(&100u64.to_be_bytes());
        part(&2u64.to_be_bytes());
        part(&1_700_000_000u64.to_be_bytes());

        let actual = super::quote_bytes(
            "id",
            "l2addr",
            1_100,
            "l1addr",
            1_000,
            100,
            2,
            1_700_000_000,
        );
        assert_eq!(actual, expected);
    }
}

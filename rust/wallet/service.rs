//! Payout logic. Each payout is checked against Thunder and the wallet's own
//! limits, signed, persisted, and only then broadcast.

use std::{str::FromStr as _, sync::Arc, time::SystemTime};

use bdk_esplora::{EsploraAsyncExt as _, esplora_client::AsyncClient};
use bdk_wallet::{
    SignOptions, Wallet,
    bitcoin::{
        Address, Amount, BlockHash, FeeRate, Network, Psbt, ScriptBuf, Transaction, Txid,
        consensus::{deserialize, serialize},
        ecdsa,
        hashes::Hash as _,
        sighash::{EcdsaSighashType, SighashCache},
    },
};
use fastwithdraw_signer::TxSigner;
use fastwithdraw_thunder as thunder;
use sqlx::PgPool;
use thiserror::Error;

use crate::store::{self, Payout};

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    InvalidArgument(String),
    /// The L2 payment is missing, unconfirmed, or doesn't match the request.
    #[error("{0}")]
    FailedPrecondition(String),
    /// A limit or the wallet balance doesn't allow this payout.
    #[error("{0}")]
    ResourceExhausted(String),
    /// The withdrawal, L2 index or L2 payment already funded another payout.
    #[error("{0}")]
    AlreadyExists(String),
    /// No quote was registered for the withdrawal, or no payout exists.
    #[error("{0}")]
    NotFound(String),
    /// Thunder may have stopped following L1; retry later.
    #[error("{0}")]
    Unavailable(String),
    #[error("thunder: {0}")]
    Thunder(#[from] thunder::rpc::Error),
    #[error("esplora: {0}")]
    Esplora(#[from] bdk_esplora::esplora_client::Error),
    #[error("database: {0}")]
    Database(#[from] sqlx::Error),
    #[error(transparent)]
    Internal(anyhow::Error),
}

impl Error {
    /// The error without backend details, such as URLs that may carry
    /// credentials, for callers and status reasons.
    pub fn summary(&self) -> String {
        match self {
            Self::Thunder(_) => "Thunder unavailable".to_owned(),
            Self::Esplora(_) => "Esplora unavailable".to_owned(),
            Self::Database(_) | Self::Internal(_) => "internal wallet error".to_owned(),
            err => err.to_string(),
        }
    }
}

fn internal(err: impl Into<anyhow::Error>) -> Error {
    Error::Internal(err.into())
}

/// Confirmations after which a payout is no longer rebroadcast or watched.
const SETTLED_DEPTH: u32 = 6;

/// `value * bps / 10_000`, rounded up, without overflowing.
fn ceil_bps(value: u64, bps: u32) -> u64 {
    value / 10_000 * u64::from(bps) + (value % 10_000 * u64::from(bps)).div_ceil(10_000)
}

/// Where a payout stands, as of one tick.
enum PayoutState {
    /// [`SETTLED_DEPTH`] blocks deep; no longer watched.
    Settled,
    /// In a block, not yet settled.
    Mined,
    /// No version in a block yet.
    Unmined,
}

/// Outpoints a payout must not spend: unconfirmed coins from others can be
/// replaced out from under it, leaving it unminable.
fn unspendable(wallet: &Wallet) -> Vec<bdk_wallet::bitcoin::OutPoint> {
    wallet
        .list_unspent()
        .filter(|utxo| !spendable(wallet, utxo))
        .map(|utxo| utxo.outpoint)
        .collect()
}

/// What a payout or fee bump, built under the payout lock, must not spend:
/// [`unspendable`] coins, and the unconfirmed change of fee-bumped payouts.
/// Which of those versions confirms decides whether that change exists.
async fn locked_unspendable(
    wallet: &Wallet,
    conn: &mut sqlx::PgConnection,
) -> Result<Vec<bdk_wallet::bitcoin::OutPoint>, Error> {
    let bumped = store::bumped_txids(conn).await?;
    let mut outpoints = unspendable(wallet);
    outpoints.extend(
        wallet
            .list_unspent()
            .filter(|utxo| {
                !utxo.chain_position.is_confirmed()
                    && bumped.contains(&utxo.outpoint.txid.to_string())
            })
            .map(|utxo| utxo.outpoint),
    );
    Ok(outpoints)
}

/// Whether a payout may spend `utxo`: confirmed, or change from a
/// transaction we sent. With a single descriptor BDK files change under the
/// external keychain, so its own "trusted" notion doesn't apply.
fn spendable(wallet: &Wallet, utxo: &bdk_wallet::LocalOutput) -> bool {
    utxo.chain_position.is_confirmed()
        || wallet
            .get_tx(utxo.outpoint.txid)
            .is_some_and(|tx| wallet.sent_and_received(&tx.tx_node.tx).0 > Amount::ZERO)
}

/// Where L1 and Thunder stand. See [`Service::chain_status`].
#[derive(Clone, Debug, Default)]
pub struct ChainStatus {
    pub l1_tip_height: u32,
    /// None while Thunder has no L2 blocks.
    pub l2_tip_height: Option<u32>,
    /// Height of the L1 block that BMM'd the L2 tip.
    pub l2_tip_bmm_height: Option<u32>,
    /// None when Thunder couldn't say.
    pub thunder_connected_peers: Option<u32>,
    /// Why payouts are paused, if they are.
    pub unsynced: Option<String>,
}

/// Limits the wallet enforces regardless of what its caller asks for.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_payout_sats: u64,
    pub daily_cap_sats: u64,
    pub max_fee_sats: u64,
    /// What a fee bump may spend beyond the customer's fee (L2 payment
    /// less payout).
    pub fee_bump_subsidy_sats: u64,
    /// Minimum service fee, in basis points of the payout, that a quote must
    /// charge on top of it.
    pub min_fee_bps: u32,
}

pub struct Service {
    pub(crate) db: PgPool,
    esplora: AsyncClient,
    thunder: thunder::Client,
    xpub: thunder::Xpub,
    signer: Arc<dyn TxSigner>,
    network: Network,
    descriptor: String,
    script_pubkey: ScriptBuf,
    required_confirmations: u32,
    thunder_max_l1_lag: u32,
    limits: Limits,
    fee_target_blocks: u16,
    fallback_fee_rate: FeeRate,
    fee_bump_after_blocks: u32,
}

pub struct Parts {
    pub db: PgPool,
    pub esplora: AsyncClient,
    pub thunder: thunder::Client,
    pub xpub: thunder::Xpub,
    pub signer: Arc<dyn TxSigner>,
    pub network: Network,
    pub required_confirmations: u32,
    pub thunder_max_l1_lag: u32,
    pub limits: Limits,
    pub fee_target_blocks: u16,
    pub fallback_fee_rate: FeeRate,
    /// Unconfirmed blocks after which a payout is fee-bumped.
    pub fee_bump_after_blocks: u32,
}

impl Service {
    pub fn new(parts: Parts) -> Self {
        let public_key = parts.signer.public_key();
        Self {
            descriptor: format!("wpkh({public_key})"),
            script_pubkey: ScriptBuf::new_p2wpkh(&public_key.wpubkey_hash()),
            db: parts.db,
            esplora: parts.esplora,
            thunder: parts.thunder,
            xpub: parts.xpub,
            signer: parts.signer,
            network: parts.network,
            required_confirmations: parts.required_confirmations,
            thunder_max_l1_lag: parts.thunder_max_l1_lag,
            limits: parts.limits,
            fee_target_blocks: parts.fee_target_blocks,
            fallback_fee_rate: parts.fallback_fee_rate,
            fee_bump_after_blocks: parts.fee_bump_after_blocks,
        }
    }

    /// The wallet's single receive (and change) address.
    pub fn address(&self) -> Result<Address, Error> {
        Address::from_script(&self.script_pubkey, self.network).map_err(internal)
    }

    async fn sync(&self, wallet: &mut Wallet) -> Result<(), Error> {
        let update = self
            .esplora
            .full_scan(wallet.start_full_scan(), 1, 4)
            .await
            .map_err(|err| Error::Esplora(*err))?;
        wallet.apply_update(update).map_err(internal)
    }

    /// Confirmed coins plus our own unconfirmed change, which only we can
    /// spend or replace.
    /// Errors unless Thunder's L2 tip was BMM'd in a recent block on L1's
    /// best chain. Thunder stops following L1 if its enforcer connection
    /// breaks; it then misses new L2 blocks and L1 reorgs that undo old ones.
    pub async fn check_thunder_synced(&self) -> Result<(), Error> {
        match self.chain_status().await?.unsynced {
            Some(reason) => Err(Error::Unavailable(reason)),
            None => Ok(()),
        }
    }

    /// Where L1 and Thunder stand, and why payouts are paused, if they are.
    pub async fn chain_status(&self) -> Result<ChainStatus, Error> {
        let l1_tip_height = self.esplora.get_height().await?;
        let l2_tip_height = match self.thunder.tip_height().await {
            Ok(height) => Some(height),
            Err(thunder::rpc::Error::EmptyChain) => None,
            Err(err) => return Err(err.into()),
        };
        // Only informative: a lagging tip is what pauses payouts.
        let thunder_connected_peers = self
            .thunder
            .connected_peers()
            .await
            .inspect_err(|err| tracing::warn!("Thunder peers: {err}"))
            .ok();
        let mut status = ChainStatus {
            l1_tip_height,
            l2_tip_height,
            l2_tip_bmm_height: None,
            thunder_connected_peers,
            unsynced: None,
        };
        let Some(anchor) = self.thunder.tip_mainchain_block().await? else {
            status.unsynced = Some("Thunder has no L2 blocks".to_owned());
            return Ok(status);
        };
        let hash = BlockHash::from_str(&anchor).map_err(internal)?;
        // The block's height, then whether the best chain has it there. Not
        // `/block/:hash/status`, which mempool.space-style backends lack.
        let height = self.esplora.get_block_info(&hash).await?.height;
        status.l2_tip_bmm_height = Some(height);
        let lag = l1_tip_height.saturating_sub(height);
        if self.esplora.get_block_hash(height).await? != hash {
            status.unsynced = Some(format!(
                "Thunder's L2 tip was BMM'd in L1 block {anchor}, which is not on the best chain"
            ));
        } else if lag > self.thunder_max_l1_lag {
            status.unsynced = Some(format!(
                "Thunder's L2 tip was BMM'd {lag} L1 blocks ago; it may have stopped following L1"
            ));
        }
        Ok(status)
    }

    /// What's left of the rolling 24-hour payout cap.
    pub async fn daily_cap_left(&self) -> Result<u64, Error> {
        let mut conn = self.db.acquire().await?;
        let spent = store::spent_last_day(&mut conn).await?;
        Ok(self.limits.daily_cap_sats.saturating_sub(spent))
    }

    pub async fn spendable_balance(&self) -> Result<u64, Error> {
        Ok(self.balance().await?.0)
    }

    /// The spendable balance, and whether the wallet has ever had a confirmed
    /// transaction. Its first funding counts only once it confirms.
    async fn balance(&self) -> Result<(u64, bool), Error> {
        let mut conn = self.db.acquire().await?;
        let mut wallet = store::load_wallet(&mut conn, &self.descriptor, self.network).await?;
        drop(conn);
        self.sync(&mut wallet).await?;
        let spendable = wallet
            .list_unspent()
            .filter(|utxo| spendable(&wallet, utxo))
            .map(|utxo| utxo.txout.value.to_sat())
            .sum();
        let funded = wallet
            .transactions()
            .any(|tx| tx.chain_position.is_confirmed());
        Ok((spendable, funded))
    }

    async fn fee_rate(&self) -> FeeRate {
        let estimates = match self.esplora.get_fee_estimates().await {
            Ok(estimates) => estimates,
            Err(err) => {
                tracing::warn!("fee estimates unavailable, using fallback: {err}");
                return self.fallback_fee_rate;
            }
        };
        let estimate = estimates
            .iter()
            .filter(|(target, _)| **target <= self.fee_target_blocks)
            .max_by_key(|(target, _)| **target)
            .map(|(_, sat_per_vb)| *sat_per_vb);
        estimate
            .and_then(|sat_per_vb| FeeRate::from_sat_per_vb(sat_per_vb.ceil() as u64))
            .map_or(self.fallback_fee_rate, |rate| {
                rate.max(self.fallback_fee_rate)
            })
    }

    /// Checks that `outpoint` pays at least `min_sats` to receive address
    /// `l2_index` with enough confirmations. `block` is the caller's claim of
    /// where the payment was mined; Thunder re-verifies it.
    async fn check_l2_payment(
        &self,
        l2_index: u32,
        outpoint: &thunder::OutPoint,
        block: Option<&thunder::BlockRef>,
        min_sats: u64,
    ) -> Result<thunder::Payment, Error> {
        let expected = self
            .xpub
            .address(l2_index)
            .map_err(|err| Error::InvalidArgument(err.to_string()))?;
        let payment = self
            .thunder
            .payment(outpoint, &expected, block)
            .await?
            .ok_or_else(|| {
                Error::FailedPrecondition(
                    "no unspent L2 output pays our receive address".to_owned(),
                )
            })?;
        if payment.sats < min_sats {
            return Err(Error::FailedPrecondition(
                "L2 payment is smaller than the payout".to_owned(),
            ));
        }
        if payment.confirmations < self.required_confirmations {
            return Err(Error::FailedPrecondition(format!(
                "L2 payment has {} of {} confirmations",
                payment.confirmations, self.required_confirmations
            )));
        }
        Ok(payment)
    }

    async fn sign(&self, psbt: &mut Psbt) -> Result<(), Error> {
        let unsigned = psbt.unsigned_tx.clone();
        let mut cache = SighashCache::new(&unsigned);
        let public_key = bdk_wallet::bitcoin::PublicKey::from(self.signer.public_key());
        for (index, input) in psbt.inputs.iter_mut().enumerate() {
            let utxo = input
                .witness_utxo
                .clone()
                .ok_or_else(|| internal(anyhow::anyhow!("input {index} has no witness UTXO")))?;
            if utxo.script_pubkey != self.script_pubkey {
                return Err(internal(anyhow::anyhow!("input {index} is not ours")));
            }
            let sighash = cache
                .p2wpkh_signature_hash(
                    index,
                    &utxo.script_pubkey,
                    utxo.value,
                    EcdsaSighashType::All,
                )
                .map_err(internal)?;
            let signature = self
                .signer
                .sign_digest(sighash.to_byte_array())
                .await
                .map_err(internal)?;
            input.partial_sigs.insert(
                public_key,
                ecdsa::Signature {
                    signature,
                    sighash_type: EcdsaSighashType::All,
                },
            );
        }
        Ok(())
    }

    fn parse_destination(&self, l1_destination: &str) -> Result<Address, Error> {
        let destination = Address::from_str(l1_destination)
            .and_then(|address| address.require_network(self.network))
            .map_err(|err| Error::InvalidArgument(format!("invalid L1 destination: {err}")))?;
        if destination.script_pubkey() == self.script_pubkey {
            return Err(Error::InvalidArgument(
                "L1 destination is the wallet itself".to_owned(),
            ));
        }
        Ok(destination)
    }

    /// Records what a new quote pays out: `Pay` for this withdrawal must match.
    pub async fn register(
        &self,
        withdrawal_id: &str,
        l2_index: u32,
        l1_destination: &str,
        l1_sats: u64,
        l2_sats: u64,
    ) -> Result<(), Error> {
        if withdrawal_id.is_empty() || withdrawal_id.len() > 128 {
            return Err(Error::InvalidArgument("invalid withdrawal_id".to_owned()));
        }
        self.xpub
            .address(l2_index)
            .map_err(|err| Error::InvalidArgument(err.to_string()))?;
        self.parse_destination(l1_destination)?;
        if l1_sats == 0 {
            return Err(Error::InvalidArgument("payout must be positive".to_owned()));
        }
        // A compromised api can't hand out quotes below the service fee, and
        // a quote always leaves something for the miner fee.
        let min_l2_sats = l1_sats
            .checked_add(ceil_bps(l1_sats, self.limits.min_fee_bps).max(1))
            .ok_or_else(|| Error::InvalidArgument("amount out of range".to_owned()))?;
        if l2_sats < min_l2_sats {
            return Err(Error::InvalidArgument(format!(
                "quote charges less than the minimum service fee: L2 payment must be at least {min_l2_sats} sats"
            )));
        }
        store::register(
            &self.db,
            withdrawal_id,
            &store::Binding {
                l2_index,
                l1_destination: l1_destination.to_owned(),
                l1_sats,
                l2_sats,
            },
        )
        .await
    }

    /// The current payout transaction for a withdrawal, and whether it is
    /// settled.
    pub async fn get_payout(&self, withdrawal_id: &str) -> Result<(String, bool), Error> {
        let (payout, settled) = store::get_payout(&self.db, withdrawal_id)
            .await?
            .ok_or_else(|| Error::NotFound("no payout for this withdrawal".to_owned()))?;
        Ok((payout.txid, settled))
    }

    /// Pays `l1_sats` to `l1_destination` for a confirmed L2 payment.
    /// Idempotent per withdrawal ID; returns the payout txid.
    pub async fn pay(
        &self,
        withdrawal_id: &str,
        l2_index: u32,
        mut l2_outpoint: thunder::OutPoint,
        l2_block: Option<thunder::BlockRef>,
        l1_destination: &str,
        l1_sats: u64,
    ) -> Result<Txid, Error> {
        if withdrawal_id.is_empty() || withdrawal_id.len() > 128 {
            return Err(Error::InvalidArgument("invalid withdrawal_id".to_owned()));
        }
        l2_outpoint.txid = l2_outpoint.txid.to_ascii_lowercase();
        if l2_outpoint.txid.len() != 64 || hex::decode(&l2_outpoint.txid).is_err() {
            return Err(Error::InvalidArgument("invalid L2 txid".to_owned()));
        }
        if l1_sats == 0 {
            return Err(Error::InvalidArgument("payout must be positive".to_owned()));
        }
        if l1_sats > self.limits.max_payout_sats {
            return Err(Error::ResourceExhausted(
                "payout is outside the wallet's limit".to_owned(),
            ));
        }
        let destination = self.parse_destination(l1_destination)?;
        // Already paid: return it without re-checking a payment that may have
        // been swept since. The full comparison happens under the lock.
        if let Some((existing, _)) = store::get_payout(&self.db, withdrawal_id).await?
            && existing.l2_index == l2_index
            && existing.l2_txid == l2_outpoint.txid
            && existing.l2_vout == l2_outpoint.vout
            && existing.l1_destination == l1_destination
            && existing.l1_sats == l1_sats
        {
            return Txid::from_str(&existing.txid).map_err(internal);
        }
        self.check_thunder_synced().await?;
        // Only what was registered with the quote can be paid out.
        let binding = store::get_binding(&self.db, withdrawal_id)
            .await?
            .ok_or_else(|| Error::NotFound("no quote registered for this withdrawal".to_owned()))?;
        if binding.l2_index != l2_index
            || binding.l1_destination != l1_destination
            || binding.l1_sats != l1_sats
        {
            return Err(Error::InvalidArgument(
                "payout does not match the registered quote".to_owned(),
            ));
        }
        // Read-only, so outside the payout lock; repeated payouts are caught
        // by the uniqueness checks under it.
        let payment = self
            .check_l2_payment(l2_index, &l2_outpoint, l2_block.as_ref(), l1_sats)
            .await?;
        if payment.sats < binding.l2_sats {
            return Err(Error::FailedPrecondition(format!(
                "L2 payment of {} sats is less than the quoted {}",
                payment.sats, binding.l2_sats
            )));
        }

        // A session lock, held through commit and broadcast: the next payout
        // may spend this one's change, so it must reach the mempool first.
        let mut lock = store::PayoutLock::acquire(&self.db).await?;
        let result = self
            .pay_locked(
                lock.conn(),
                withdrawal_id,
                l2_index,
                l2_outpoint,
                &payment,
                l1_destination,
                &destination,
                l1_sats,
            )
            .await;
        lock.release().await;
        result
    }

    /// The part of [`Self::pay`] that runs under the payout lock.
    #[expect(clippy::too_many_arguments)]
    async fn pay_locked(
        &self,
        conn: &mut sqlx::PgConnection,
        withdrawal_id: &str,
        l2_index: u32,
        l2_outpoint: thunder::OutPoint,
        payment: &thunder::Payment,
        l1_destination: &str,
        destination: &Address,
        l1_sats: u64,
    ) -> Result<Txid, Error> {
        let mut tx = sqlx::Connection::begin(&mut *conn).await?;
        if let Some(existing) = store::conflicting_payout(
            &mut tx,
            withdrawal_id,
            l2_index,
            &l2_outpoint.txid,
            l2_outpoint.vout,
        )
        .await?
        {
            let same = existing.withdrawal_id == withdrawal_id
                && existing.l2_index == l2_index
                && existing.l2_txid == l2_outpoint.txid
                && existing.l2_vout == l2_outpoint.vout
                && existing.l1_destination == l1_destination
                && existing.l1_sats == l1_sats;
            if !same {
                return Err(Error::AlreadyExists(
                    "withdrawal, L2 index or L2 payment already has a different payout".to_owned(),
                ));
            }
            return Txid::from_str(&existing.txid).map_err(internal);
        }
        let spent = store::spent_last_day(&mut tx).await?;
        if spent.saturating_add(l1_sats) > self.limits.daily_cap_sats {
            return Err(Error::ResourceExhausted(
                "daily payout cap reached".to_owned(),
            ));
        }

        let mut wallet = store::load_wallet(&mut tx, &self.descriptor, self.network).await?;
        self.sync(&mut wallet).await?;
        let tip_height = self.esplora.get_height().await?;
        let unspendable = locked_unspendable(&wallet, &mut tx).await?;
        let fee_rate = self.fee_rate().await;
        let mut builder = wallet.build_tx();
        builder
            .add_recipient(destination.script_pubkey(), Amount::from_sat(l1_sats))
            .unspendable(unspendable)
            .fee_rate(fee_rate);
        let mut psbt = builder.finish().map_err(|err| match err {
            bdk_wallet::error::CreateTxError::CoinSelection(err) => {
                Error::ResourceExhausted(format!("insufficient wallet funds: {err}"))
            }
            err => internal(err),
        })?;
        let fee = psbt.fee().map_err(internal)?.to_sat();
        if fee > self.limits.max_fee_sats {
            return Err(Error::ResourceExhausted(format!(
                "miner fee {fee} sats exceeds the cap"
            )));
        }
        if payment.sats < l1_sats.saturating_add(fee) {
            return Err(Error::FailedPrecondition(
                "L2 payment does not cover the payout plus the miner fee".to_owned(),
            ));
        }
        if spent.saturating_add(l1_sats).saturating_add(fee) > self.limits.daily_cap_sats {
            return Err(Error::ResourceExhausted(
                "daily payout cap reached".to_owned(),
            ));
        }
        self.sign(&mut psbt).await?;
        if !wallet
            .finalize_psbt(&mut psbt, SignOptions::default())
            .map_err(internal)?
        {
            return Err(internal(anyhow::anyhow!("payout did not finalize")));
        }
        let signed: Transaction = psbt.extract_tx().map_err(internal)?;
        // Exactly one payment output, everything else change back to us.
        let (payments, change): (Vec<_>, Vec<_>) = signed
            .output
            .iter()
            .partition(|output| output.script_pubkey != self.script_pubkey);
        let pays_exactly = matches!(payments.as_slice(), [output]
            if output.script_pubkey == destination.script_pubkey()
                && output.value == Amount::from_sat(l1_sats));
        if !pays_exactly || change.len() > 1 {
            return Err(internal(anyhow::anyhow!(
                "built payout has unexpected outputs"
            )));
        }

        let txid = signed.compute_txid();
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        wallet.apply_unconfirmed_txs([(signed.clone(), now)]);
        store::save_wallet(&mut tx, &mut wallet).await?;
        store::insert_payout(
            &mut tx,
            &Payout {
                withdrawal_id: withdrawal_id.to_owned(),
                l2_index,
                l2_txid: l2_outpoint.txid,
                l2_vout: l2_outpoint.vout,
                l2_sats: payment.sats,
                l1_destination: l1_destination.to_owned(),
                l1_sats,
                fee_sats: fee,
                txid: txid.to_string(),
                raw_tx: serialize(&signed),
                tip_height,
                signed_tip_height: tip_height,
            },
        )
        .await?;
        tx.commit().await?;
        tracing::info!(%withdrawal_id, %txid, l1_sats, fee, "payout signed");

        // Persisted first: if this fails, `tick` rebroadcasts.
        if let Err(err) = self.esplora.broadcast(&signed).await {
            tracing::warn!(%txid, "payout broadcast failed, will retry: {err}");
        }
        Ok(txid)
    }

    /// Rebroadcasts payouts until they are [`SETTLED_DEPTH`] blocks deep, and
    /// fee-bumps those stuck for `fee_bump_after_blocks`. Returns the number
    /// not yet settled. One payout's failure doesn't stop the others.
    pub async fn tick(&self) -> Result<u32, Error> {
        let tip = self.esplora.get_height().await?;
        let unsettled = store::unconfirmed_payouts(&self.db).await?;
        let mut pending = 0;
        let mut stuck = 0;
        for payout in &unsettled {
            match self.settle(payout, tip).await {
                Ok(PayoutState::Settled) => {}
                Ok(PayoutState::Mined) => pending += 1,
                Ok(PayoutState::Unmined) => {
                    pending += 1;
                    // Still unmined well after a fee bump was due. Counted
                    // from the first version: each bump resets `tip_height`.
                    if tip.saturating_sub(payout.signed_tip_height)
                        >= 2 * self.fee_bump_after_blocks
                    {
                        stuck += 1;
                    }
                }
                Err(err) => {
                    pending += 1;
                    tracing::warn!(txid = %payout.txid, "payout check failed: {err:#}");
                }
            }
        }
        let stuck = (stuck > 0).then(|| {
            format!(
                "{stuck} payouts unmined after a fee bump: check the wallet's logs, its fee cap and daily cap"
            )
        });
        fastwithdraw_alerts::set(&self.db, "payouts_stuck", stuck).await;
        self.check_alerts().await;
        fastwithdraw_alerts::heartbeat();
        Ok(pending)
    }

    /// Opens or resolves the wallet's alerts whose conditions don't depend
    /// on a single payout.
    async fn check_alerts(&self) {
        let unsynced = self.check_thunder_synced().await.err();
        fastwithdraw_alerts::set(
            &self.db,
            "thunder_unsynced",
            unsynced.map(|err| format!("Payouts and quotes are paused: {err}")),
        )
        .await;

        let spent = match self.db.acquire().await {
            Ok(mut conn) => store::spent_last_day(&mut conn).await,
            Err(err) => Err(err.into()),
        };
        match spent {
            Ok(spent) => {
                let left = self.limits.daily_cap_sats.saturating_sub(spent);
                let max = self.limits.max_payout_sats;
                fastwithdraw_alerts::set(
                    &self.db,
                    "daily_cap_reached",
                    (left < max).then(|| {
                        format!(
                            "{left} sats left of the daily cap, less than one maximum payout ({max}): \
                             larger payouts wait until it rolls over"
                        )
                    }),
                )
                .await;
            }
            Err(err) => tracing::warn!("check daily cap: {err}"),
        }

        match self.balance().await {
            // A wallet that has never been funded is still being set up.
            Ok((balance, funded)) => {
                let max = self.limits.max_payout_sats;
                fastwithdraw_alerts::set(
                    &self.db,
                    "low_funds",
                    (funded && balance < max).then(|| {
                        let address = self.address().map(|a| a.to_string()).unwrap_or_default();
                        format!(
                            "Hot wallet holds {balance} sats, less than one maximum payout ({max}): \
                             top it up at {address}"
                        )
                    }),
                )
                .await;
            }
            Err(err) => tracing::warn!("check balance: {err}"),
        }
    }

    /// Where `payout` stands. Rebroadcasts it if no version is mined,
    /// and fee-bumps it once it has waited long enough.
    async fn settle(&self, payout: &Payout, tip: u32) -> Result<PayoutState, Error> {
        for version in store::versions(&self.db, &payout.withdrawal_id).await? {
            let txid = Txid::from_str(&version).map_err(internal)?;
            let status = match self.esplora.get_tx_status(&txid).await {
                Ok(status) => status,
                // Some Esplora servers (mempool.space's) answer 404 for a
                // transaction they have never seen: not mined, so rebroadcast.
                Err(bdk_esplora::esplora_client::Error::HttpResponse { status: 404, .. }) => {
                    continue;
                }
                Err(err) => return Err(err.into()),
            };
            if let Some(height) = status.block_height.filter(|_| status.confirmed) {
                if tip.saturating_sub(height) + 1 >= SETTLED_DEPTH {
                    store::mark_settled(&self.db, &payout.withdrawal_id, &version).await?;
                    return Ok(PayoutState::Settled);
                }
                return Ok(PayoutState::Mined);
            }
        }
        let tx: Transaction = deserialize(&payout.raw_tx).map_err(internal)?;
        if let Err(err) = self.esplora.broadcast(&tx).await {
            tracing::warn!(txid = %payout.txid, "payout rebroadcast failed: {err}");
        }
        let waited = tip.saturating_sub(payout.tip_height);
        if waited >= self.fee_bump_after_blocks
            && let Err(err) = self.bump(payout, tip).await
        {
            tracing::warn!(txid = %payout.txid, "fee bump failed: {err:#}");
        }
        Ok(PayoutState::Unmined)
    }

    async fn bump(&self, payout: &Payout, tip: u32) -> Result<(), Error> {
        let mut lock = store::PayoutLock::acquire(&self.db).await?;
        let result = self.bump_locked(lock.conn(), payout, tip).await;
        lock.release().await;
        result
    }

    /// Replaces a stuck payout with one paying the same destination at a
    /// higher fee rate, within the fee and daily caps.
    async fn bump_locked(
        &self,
        conn: &mut sqlx::PgConnection,
        payout: &Payout,
        tip: u32,
    ) -> Result<(), Error> {
        let mut tx = sqlx::Connection::begin(&mut *conn).await?;
        // Another instance may have bumped or settled it meanwhile.
        let current = store::get_payout(&mut *tx, &payout.withdrawal_id).await?;
        if !current.is_some_and(|(current, settled)| !settled && current.txid == payout.txid) {
            return Ok(());
        }
        // Replacing a payout whose change another payout spends would
        // invalidate that one; bumping the newest in a chain pulls its
        // parents along (CPFP) instead. Checked here, under the lock, against
        // every version: a payout signed meanwhile may spend any of them.
        if store::has_child(&mut tx, &payout.withdrawal_id).await? {
            tracing::debug!(txid = %payout.txid, "not bumping a payout another one spends");
            return Ok(());
        }
        let mut wallet = store::load_wallet(&mut tx, &self.descriptor, self.network).await?;
        self.sync(&mut wallet).await?;
        let old: Transaction = deserialize(&payout.raw_tx).map_err(internal)?;
        let old_txid = old.compute_txid();
        let old_rate = payout.fee_sats.div_ceil(old.vsize().max(1) as u64);
        // BIP125 needs a higher rate; step up by half, at least 1 sat/vB.
        let target = self.fee_rate().await.to_sat_per_vb_ceil();
        let new_rate = target.max(old_rate + (old_rate / 2).max(1));
        let unspendable = locked_unspendable(&wallet, &mut tx).await?;
        let mut builder = wallet.build_fee_bump(old_txid).map_err(internal)?;
        builder
            .fee_rate(
                FeeRate::from_sat_per_vb(new_rate)
                    .ok_or_else(|| internal(anyhow::anyhow!("fee rate overflow")))?,
            )
            .unspendable(unspendable);
        let mut psbt = builder.finish().map_err(|err| match err {
            bdk_wallet::error::CreateTxError::CoinSelection(err) => {
                Error::ResourceExhausted(format!("insufficient funds to bump: {err}"))
            }
            err => internal(err),
        })?;
        let fee = psbt.fee().map_err(internal)?.to_sat();
        // Like the first version, paid for by the customer's fee, plus any
        // subsidy the operator allows.
        let customer_fee = payout
            .l2_sats
            .saturating_sub(payout.l1_sats)
            .saturating_add(self.limits.fee_bump_subsidy_sats);
        if fee > self.limits.max_fee_sats.min(customer_fee) {
            return Err(Error::ResourceExhausted(format!(
                "bumped fee {fee} sats would exceed the cap; payout {old_txid} stays stuck"
            )));
        }
        let spent = store::spent_last_day(&mut tx).await?;
        if spent.saturating_add(fee.saturating_sub(payout.fee_sats)) > self.limits.daily_cap_sats {
            return Err(Error::ResourceExhausted(
                "daily cap reached; payout stays stuck".to_owned(),
            ));
        }
        self.sign(&mut psbt).await?;
        if !wallet
            .finalize_psbt(&mut psbt, SignOptions::default())
            .map_err(internal)?
        {
            return Err(internal(anyhow::anyhow!("bumped payout did not finalize")));
        }
        let signed: Transaction = psbt.extract_tx().map_err(internal)?;
        let destination = self.parse_destination(&payout.l1_destination)?;
        let (payments, change): (Vec<_>, Vec<_>) = signed
            .output
            .iter()
            .partition(|output| output.script_pubkey != self.script_pubkey);
        let pays_exactly = matches!(payments.as_slice(), [output]
            if output.script_pubkey == destination.script_pubkey()
                && output.value == Amount::from_sat(payout.l1_sats));
        if !pays_exactly || change.len() > 1 {
            return Err(internal(anyhow::anyhow!(
                "bumped payout has unexpected outputs"
            )));
        }
        let txid = signed.compute_txid();
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        wallet.apply_unconfirmed_txs([(signed.clone(), now)]);
        store::save_wallet(&mut tx, &mut wallet).await?;
        store::replace_payout(
            &mut tx,
            &payout.withdrawal_id,
            &txid.to_string(),
            &serialize(&signed),
            fee,
            tip,
        )
        .await?;
        tx.commit().await?;
        tracing::info!(withdrawal_id = %payout.withdrawal_id, %old_txid, %txid, fee, "payout fee-bumped");
        if let Err(err) = self.esplora.broadcast(&signed).await {
            tracing::warn!(%txid, "bumped payout broadcast failed, will retry: {err}");
        }
        Ok(())
    }
}

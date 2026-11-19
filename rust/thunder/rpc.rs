//! Client for the read-only methods of Thunder's public JSON-RPC.

use std::{
    collections::{HashMap, HashSet},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use thiserror::Error;

use crate::Address;

#[derive(Debug, Error)]
pub enum Error {
    #[error("thunder chain changed while reading block {height}")]
    ChainChanged { height: u32 },
    #[error("thunder RPC {method}: {source}")]
    Transport {
        method: &'static str,
        source: reqwest::Error,
    },
    #[error("thunder RPC {method} error {code}: {message}")]
    Rpc {
        method: &'static str,
        code: i64,
        message: String,
    },
    #[error("thunder RPC {method}: unexpected response: {source}")]
    Decode {
        method: &'static str,
        source: serde_json::Error,
    },
    #[error("thunder chain has no blocks")]
    EmptyChain,
}

/// A transfer output, identified by transaction and output index.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct OutPoint {
    pub txid: String,
    pub vout: u32,
}

/// A block on the active chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockRef {
    pub height: u32,
    pub hash: String,
}

/// A payment to one of our addresses, as seen by the node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Payment {
    pub outpoint: OutPoint,
    pub address: Address,
    pub sats: u64,
    /// The block that includes the payment, if it was located on the active
    /// chain.
    pub block: Option<BlockRef>,
    /// Zero unless the including block was positively located: in the
    /// mempool, or confirmed but its depth couldn't be established.
    pub confirmations: u32,
    /// In the confirmed UTXO set, rather than only in the mempool. A payment
    /// that is but has zero confirmations is still mined; its depth is just
    /// unknown for now.
    pub mined: bool,
}

#[derive(Deserialize)]
struct RpcOutput {
    address: String,
    content: Value,
}

impl RpcOutput {
    /// `{"Value": sats}`; withdrawal outputs and anything else yield `None`.
    fn value_sats(&self) -> Option<u64> {
        self.content.get("Value")?.as_u64()
    }
}

#[derive(Deserialize)]
struct PointedOutput {
    outpoint: Value,
    output: RpcOutput,
}

impl PointedOutput {
    /// The outpoint of a regular (transfer) output; deposits and coinbase
    /// outputs yield `None`.
    fn regular(&self) -> Option<OutPoint> {
        let regular = self.outpoint.get("Regular")?;
        Some(OutPoint {
            txid: regular.get("txid")?.as_str()?.to_owned(),
            vout: u32::try_from(regular.get("vout")?.as_u64()?).ok()?,
        })
    }
}

#[derive(Deserialize)]
struct RpcBlockTransaction {
    canonical_bytes: String,
}

#[derive(Deserialize)]
struct RpcBlockBody {
    transactions: Vec<RpcBlockTransaction>,
}

#[derive(Deserialize)]
struct RpcBlock {
    body: RpcBlockBody,
}

/// Thunder txids are `blake3(canonical bytes)`, hex-encoded.
fn txid(canonical_bytes: &str) -> Option<String> {
    let bytes = hex::decode(canonical_bytes.trim_start_matches("0x")).ok()?;
    Some(hex::encode(blake3::hash(&bytes).as_bytes()))
}

#[derive(Deserialize)]
struct RpcTransaction {
    outputs: Vec<RpcOutput>,
}

#[derive(Deserialize)]
struct TransactionResponse {
    tx: RpcTransaction,
    block_hash: Option<String>,
}

pub struct Client {
    url: String,
    http: reqwest::Client,
    next_id: AtomicU64,
    /// How many recent blocks to search for a payment's block.
    scan_depth: u32,
}

impl Client {
    /// `scan_depth` bounds the search for a payment's block. A confirmed
    /// payment deeper than that counts as `scan_depth + 1` confirmations.
    pub fn new(url: impl Into<String>, scan_depth: u32) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("static reqwest config");
        Self {
            url: url.into(),
            http,
            next_id: AtomicU64::new(1),
            scan_depth: scan_depth.max(1),
        }
    }

    async fn call<T: DeserializeOwned>(
        &self,
        method: &'static str,
        params: Value,
    ) -> Result<T, Error> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let body = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let transport = |source| Error::Transport { method, source };
        let response: Value = self
            .http
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(transport)?
            .json()
            .await
            .map_err(transport)?;
        if let Some(err) = response.get("error").filter(|err| !err.is_null()) {
            return Err(Error::Rpc {
                method,
                code: err.get("code").and_then(Value::as_i64).unwrap_or_default(),
                message: err
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
            });
        }
        let result = response.get("result").cloned().unwrap_or(Value::Null);
        serde_json::from_value(result).map_err(|source| Error::Decode { method, source })
    }

    /// Height of the active tip.
    pub async fn tip_height(&self) -> Result<u32, Error> {
        let count: u32 = self.call("getblockcount", json!([])).await?;
        count.checked_sub(1).ok_or(Error::EmptyChain)
    }

    /// Unspent outputs paid to `addresses`, as Thunder's JSON
    /// `PointedOutput`s.
    pub async fn raw_utxos(&self, addresses: &[Address]) -> Result<Vec<Value>, Error> {
        let addresses: Vec<String> = addresses.iter().map(ToString::to_string).collect();
        self.call("get_utxos", json!([addresses])).await
    }

    /// Submits a signed transaction (Thunder's JSON `AuthorizedTransaction`)
    /// and returns its txid.
    pub async fn submit_transaction(&self, transaction: Value) -> Result<String, Error> {
        self.call("submit_transaction", json!([transaction])).await
    }

    /// The mainchain block that BMM'd the current L2 tip, if there is one.
    /// It only moves when an L2 block is connected.
    pub async fn tip_mainchain_block(&self) -> Result<Option<String>, Error> {
        self.call("get_best_mainchain_block_hash", json!([])).await
    }

    /// How many peers Thunder is connected to. It gets L2 blocks only from
    /// peers; the enforcer tells it which ones L1 committed to.
    pub async fn connected_peers(&self) -> Result<u32, Error> {
        let peers: Vec<Value> = self.call("list_peers", json!([])).await?;
        let connected = peers
            .iter()
            .filter(|peer| peer.get("status").and_then(Value::as_str) == Some("Connected"))
            .count();
        Ok(u32::try_from(connected).unwrap_or(u32::MAX))
    }

    pub async fn block_hash(&self, height: u32) -> Result<Option<String>, Error> {
        self.call("get_block_hash", json!([height])).await
    }

    /// Txids in block `hash`. Missing blocks are an error: callers only ask
    /// for blocks the node just reported.
    async fn block_txids(&self, height: u32, hash: &str) -> Result<HashSet<String>, Error> {
        let block: Option<RpcBlock> = self.call("get_block", json!([hash, true])).await?;
        let block = block.ok_or(Error::ChainChanged { height })?;
        Ok(block
            .body
            .transactions
            .iter()
            .filter_map(|tx| txid(&tx.canonical_bytes))
            .collect())
    }

    /// Finds the blocks including `txids` among the last `scan_depth` blocks.
    /// Returns the tip the scan started from. Never infers anything from
    /// absence: a txid that isn't found is simply not in the map.
    ///
    /// Scans blocks rather than using `get_transaction`, which in thunder
    /// v0.18.1 only finds transactions in the tip block (it calls
    /// `is_descendant(tip, block)` with the arguments swapped).
    async fn locate(
        &self,
        txids: &HashSet<String>,
    ) -> Result<(BlockRef, HashMap<String, BlockRef>), Error> {
        let height = self.tip_height().await?;
        let tip = BlockRef {
            height,
            hash: self
                .block_hash(height)
                .await?
                .ok_or(Error::ChainChanged { height })?,
        };
        let mut found = HashMap::new();
        for depth in 0..self.scan_depth {
            if found.len() == txids.len() {
                break;
            }
            let Some(height) = tip.height.checked_sub(depth) else {
                break;
            };
            let hash = self
                .block_hash(height)
                .await?
                .ok_or(Error::ChainChanged { height })?;
            for txid in self.block_txids(height, &hash).await? {
                if txids.contains(&txid) {
                    found.insert(
                        txid,
                        BlockRef {
                            height,
                            hash: hash.clone(),
                        },
                    );
                }
            }
        }
        Ok((tip, found))
    }

    /// Confirmations of a block found when the tip was at `tip_before`, or
    /// `None` if it has left the active chain since. Counts from the lower of
    /// the two tips, so a reorg mid-scan can't inflate the count.
    async fn confirmations(&self, block: &BlockRef, tip_before: u32) -> Result<Option<u32>, Error> {
        let tip = self.tip_height().await?.min(tip_before);
        if block.height > tip
            || self.block_hash(block.height).await?.as_deref() != Some(&block.hash)
        {
            return Ok(None);
        }
        Ok(Some(tip - block.height + 1))
    }

    /// Confirmed UTXOs paying `addresses`, asked for in batches so a long
    /// list doesn't exceed Thunder's request size limit.
    async fn utxos(&self, addresses: &[Address]) -> Result<Vec<PointedOutput>, Error> {
        const BATCH: usize = 1_000;
        let mut utxos = Vec::new();
        for batch in addresses.chunks(BATCH) {
            let batch: Vec<String> = batch.iter().map(Address::to_string).collect();
            utxos.extend(
                self.call::<Vec<PointedOutput>>("get_utxos", json!([batch]))
                    .await?,
            );
        }
        Ok(utxos)
    }

    /// Of `payments`, in the UTXO set but not found in the last `scan_depth`
    /// blocks below `tip`, those deeper than the scan reached: still unspent,
    /// with the chain unchanged since the scan (a reorg or a new block could
    /// hold them where the scan didn't look). They count as `scan_depth + 1`
    /// confirmations. None of them if the chain is too short for a full scan.
    async fn beyond_scan(
        &self,
        tip: &BlockRef,
        payments: &[(&OutPoint, &Address)],
    ) -> Result<HashSet<OutPoint>, Error> {
        if tip.height < self.scan_depth || payments.is_empty() {
            return Ok(HashSet::new());
        }
        let addresses: HashSet<Address> = payments.iter().map(|(_, address)| **address).collect();
        let addresses: Vec<Address> = addresses.into_iter().collect();
        let unspent: HashSet<OutPoint> = self
            .utxos(&addresses)
            .await?
            .iter()
            .filter_map(PointedOutput::regular)
            .collect();
        let unchanged = self.tip_height().await? == tip.height
            && self.block_hash(tip.height).await?.as_deref() == Some(tip.hash.as_str());
        if !unchanged {
            return Ok(HashSet::new());
        }
        Ok(payments
            .iter()
            .filter(|(outpoint, _)| unspent.contains(*outpoint))
            .map(|(outpoint, _)| (*outpoint).clone())
            .collect())
    }

    /// Regular (transfer) outputs paying `addresses` in the confirmed UTXO set,
    /// at least `min_sats` each, other than those in `known` (eg. already
    /// recorded). Deposit and coinbase outputs are ignored. Payments deeper
    /// than the scan count as `scan_depth + 1` confirmations. The lookups are
    /// per block and per call, not per payment, so many small outputs to
    /// watched addresses cost little.
    pub async fn unspent_payments(
        &self,
        addresses: &[Address],
        min_sats: u64,
        known: &HashSet<OutPoint>,
    ) -> Result<Vec<Payment>, Error> {
        let wanted: HashSet<&Address> = addresses.iter().collect();
        let mut payments = Vec::new();
        for utxo in self.utxos(addresses).await? {
            let (Some(outpoint), Ok(address), Some(sats)) = (
                utxo.regular(),
                utxo.output.address.parse::<Address>(),
                utxo.output.value_sats(),
            ) else {
                continue;
            };
            // `get_utxos` filters by address; check anyway.
            if sats >= min_sats && wanted.contains(&address) && !known.contains(&outpoint) {
                payments.push(Payment {
                    outpoint,
                    address,
                    sats,
                    block: None,
                    confirmations: 0,
                    mined: true,
                });
            }
        }
        if payments.is_empty() {
            return Ok(payments);
        }
        let txids = payments.iter().map(|p| p.outpoint.txid.clone()).collect();
        let (tip, blocks) = self.locate(&txids).await?;
        let mut depths: HashMap<String, Option<u32>> = HashMap::new();
        for payment in &mut payments {
            let Some(block) = blocks.get(&payment.outpoint.txid) else {
                continue;
            };
            let confirmations = match depths.get(&block.hash) {
                Some(confirmations) => *confirmations,
                None => {
                    let confirmations = self.confirmations(block, tip.height).await?;
                    depths.insert(block.hash.clone(), confirmations);
                    confirmations
                }
            };
            if let Some(confirmations) = confirmations {
                payment.block = Some(block.clone());
                payment.confirmations = confirmations;
            }
        }
        let unlocated: Vec<(&OutPoint, &Address)> = payments
            .iter()
            .filter(|payment| !blocks.contains_key(&payment.outpoint.txid))
            .map(|payment| (&payment.outpoint, &payment.address))
            .collect();
        let deep = self.beyond_scan(&tip, &unlocated).await?;
        for payment in &mut payments {
            if deep.contains(&payment.outpoint) {
                payment.confirmations = self.scan_depth + 1;
            }
        }
        Ok(payments)
    }

    /// The unspent output at `outpoint` if it pays `address`: confirmed (from
    /// the UTXO set) or in the mempool (zero confirmations). `known_block` is
    /// where the payment was seen before; it is re-verified, never trusted.
    pub async fn payment(
        &self,
        outpoint: &OutPoint,
        address: &Address,
        known_block: Option<&BlockRef>,
    ) -> Result<Option<Payment>, Error> {
        let confirmed = self
            .utxos(std::slice::from_ref(address))
            .await?
            .into_iter()
            .find_map(|utxo| {
                let sats = utxo.output.value_sats()?;
                (utxo.regular().as_ref() == Some(outpoint)
                    && utxo.output.address == address.to_string())
                .then_some(sats)
            });
        if let Some(sats) = confirmed {
            let mut payment = Payment {
                outpoint: outpoint.clone(),
                address: *address,
                sats,
                block: None,
                confirmations: 0,
                mined: true,
            };
            if let Some(block) = known_block {
                let tip = self.tip_height().await?;
                if self
                    .block_txids(block.height, &block.hash)
                    .await
                    .is_ok_and(|txids| txids.contains(&outpoint.txid))
                    && let Some(confirmations) = self.confirmations(block, tip).await?
                {
                    payment.block = Some(block.clone());
                    payment.confirmations = confirmations;
                    return Ok(Some(payment));
                }
            }
            let (tip, blocks) = self.locate(&HashSet::from([outpoint.txid.clone()])).await?;
            match blocks.get(&outpoint.txid) {
                Some(block) => {
                    if let Some(confirmations) = self.confirmations(block, tip.height).await? {
                        payment.block = Some(block.clone());
                        payment.confirmations = confirmations;
                    }
                }
                None => {
                    if self
                        .beyond_scan(&tip, &[(outpoint, address)])
                        .await?
                        .contains(outpoint)
                    {
                        payment.confirmations = self.scan_depth + 1;
                    }
                }
            }
            return Ok(Some(payment));
        }
        let tx: Option<TransactionResponse> =
            self.call("get_transaction", json!([outpoint.txid])).await?;
        let Some(TransactionResponse {
            tx,
            block_hash: None,
        }) = tx
        else {
            return Ok(None);
        };
        let output = usize::try_from(outpoint.vout)
            .ok()
            .and_then(|vout| tx.outputs.get(vout))
            .filter(|output| output.address == address.to_string());
        Ok(output.and_then(RpcOutput::value_sats).map(|sats| Payment {
            outpoint: outpoint.clone(),
            address: *address,
            sats,
            block: None,
            confirmations: 0,
            mined: false,
        }))
    }
}

//! Client for the internal wallet service. On Cloud Run, requests carry a
//! Google ID token for the `api` service account, which `wallet` requires
//! through IAM.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use buffa::MessageField;
use connectrpc::{
    ConnectError,
    client::{CallOptions, ClientConfig, HttpClient},
};
use fastwithdraw_proto::{
    wallet::{GetBalanceRequest, GetPayoutRequest, L2Block, PayRequest, RegisterQuoteRequest},
    wallet_connect::WalletServiceClient,
};
use fastwithdraw_thunder as thunder;
use parking_lot::Mutex;

use crate::store::Withdrawal;

/// ID tokens from the GCE/Cloud Run metadata server, cached for most of
/// their one-hour lifetime.
struct IdTokens {
    audience: String,
    http: reqwest::Client,
    cached: Mutex<Option<(String, Instant)>>,
}

impl IdTokens {
    const LIFETIME: Duration = Duration::from_secs(45 * 60);

    async fn token(&self) -> Result<String, ConnectError> {
        if let Some((token, fetched)) = self.cached.lock().clone()
            && fetched.elapsed() < Self::LIFETIME
        {
            return Ok(token);
        }
        // GCE_METADATA_HOST overrides the metadata server, as in Google's SDKs.
        let host = std::env::var("GCE_METADATA_HOST")
            .unwrap_or_else(|_| "metadata.google.internal".to_owned());
        let url =
            format!("http://{host}/computeMetadata/v1/instance/service-accounts/default/identity");
        let token = self
            .http
            .get(url)
            // `full` adds the email claim, which the wallet checks the caller by.
            .query(&[("audience", self.audience.as_str()), ("format", "full")])
            .header("Metadata-Flavor", "Google")
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|err| ConnectError::unavailable(format!("ID token: {err}")))?
            .text()
            .await
            .map_err(|err| ConnectError::unavailable(format!("ID token: {err}")))?;
        *self.cached.lock() = Some((token.clone(), Instant::now()));
        Ok(token)
    }
}

pub struct WalletClient {
    client: WalletServiceClient<HttpClient>,
    id_tokens: Option<IdTokens>,
    /// Every quote checks the balance; the wallet syncs from Esplora for it.
    status: Mutex<Option<(WalletStatus, Instant)>>,
    /// Fixed by the payout key, so kept once fetched.
    address: Mutex<Option<String>>,
}

#[derive(Clone, Debug)]
pub struct WalletStatus {
    pub spendable_sats: u64,
    pub thunder_synced: bool,
    pub thunder_unsynced_reason: String,
    pub daily_cap_left_sats: u64,
    pub l1_tip_height: u32,
    pub l2_tip_height: Option<u32>,
    pub l2_tip_bmm_height: Option<u32>,
    pub thunder_connected_peers: Option<u32>,
}

/// How long a fetched wallet balance is reused.
const BALANCE_TTL: Duration = Duration::from_secs(10);

impl WalletClient {
    /// `id_token_auth` attaches Google ID tokens with `url` as the audience.
    pub fn new(url: &str, id_token_auth: bool) -> anyhow::Result<Self> {
        let uri: http::Uri = url.parse()?;
        let transport = if uri.scheme_str() == Some("https") {
            let roots =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
            HttpClient::with_tls(Arc::new(tls))
        } else {
            HttpClient::plaintext()
        };
        let config = ClientConfig::new(uri).with_default_timeout(Duration::from_secs(60));
        let id_tokens = if id_token_auth {
            Some(IdTokens {
                audience: url.trim_end_matches('/').to_owned(),
                http: reqwest::Client::builder()
                    .timeout(Duration::from_secs(5))
                    .build()?,
                cached: Mutex::new(None),
            })
        } else {
            None
        };
        Ok(Self {
            client: WalletServiceClient::new(transport, config),
            id_tokens,
            status: Mutex::new(None),
            address: Mutex::new(None),
        })
    }

    async fn options(&self) -> Result<CallOptions, ConnectError> {
        let options = CallOptions::default();
        let Some(id_tokens) = &self.id_tokens else {
            return Ok(options);
        };
        let value = format!("Bearer {}", id_tokens.token().await?);
        let value = http::HeaderValue::from_str(&value)
            .map_err(|_| ConnectError::internal("invalid ID token"))?;
        Ok(options.with_header(http::header::AUTHORIZATION, value))
    }

    pub async fn status(&self) -> Result<WalletStatus, ConnectError> {
        if let Some((status, fetched)) = &*self.status.lock()
            && fetched.elapsed() < BALANCE_TTL
        {
            return Ok(status.clone());
        }
        let response = self
            .client
            .get_balance_with_options(GetBalanceRequest::default(), self.options().await?)
            .await?
            .into_owned();
        let status = WalletStatus {
            spendable_sats: response.spendable_sats,
            thunder_synced: response.thunder_synced,
            thunder_unsynced_reason: response.thunder_unsynced_reason,
            daily_cap_left_sats: response.daily_cap_left_sats,
            l1_tip_height: response.l1_tip_height,
            l2_tip_height: response.l2_tip_height,
            l2_tip_bmm_height: response.l2_tip_bmm_height,
            thunder_connected_peers: response.thunder_connected_peers,
        };
        *self.status.lock() = Some((status.clone(), Instant::now()));
        *self.address.lock() = Some(response.hot_wallet_address);
        Ok(status)
    }

    /// The wallet's address, which payouts are sent from.
    pub async fn address(&self) -> Result<String, ConnectError> {
        if let Some(address) = self.address.lock().clone() {
            return Ok(address);
        }
        self.status().await?;
        Ok(self.address.lock().clone().unwrap_or_default())
    }

    pub async fn register_quote(
        &self,
        withdrawal_id: &str,
        l2_index: u32,
        l1_destination: &str,
        l1_payout_sats: u64,
        l2_payment_sats: u64,
    ) -> Result<(), ConnectError> {
        let request = RegisterQuoteRequest {
            withdrawal_id: withdrawal_id.to_owned(),
            l2_index,
            l1_address: l1_destination.to_owned(),
            l1_payout_sats,
            l2_payment_sats,
        };
        self.client
            .register_quote_with_options(request, self.options().await?)
            .await?;
        Ok(())
    }

    /// The current payout txid and whether the wallet has settled it.
    pub async fn get_payout(&self, withdrawal_id: &str) -> Result<(String, bool), ConnectError> {
        let request = GetPayoutRequest {
            withdrawal_id: withdrawal_id.to_owned(),
        };
        let response = self
            .client
            .get_payout_with_options(request, self.options().await?)
            .await?
            .into_owned();
        Ok((response.l1_payout_txid, response.settled))
    }

    pub async fn pay(
        &self,
        withdrawal: &Withdrawal,
        payment: &thunder::Payment,
    ) -> Result<String, ConnectError> {
        let l2_block = match &payment.block {
            Some(block) => MessageField::some(L2Block {
                height: block.height,
                hash: block.hash.clone(),
            }),
            None => MessageField::none(),
        };
        let request = PayRequest {
            withdrawal_id: withdrawal.id.clone(),
            l2_index: withdrawal.l2_index,
            l2_payment_txid: payment.outpoint.txid.clone(),
            l2_payment_vout: payment.outpoint.vout,
            l1_address: withdrawal.l1_destination.clone(),
            l1_payout_sats: withdrawal.l1_payout_sats,
            l2_block,
        };
        let response = self
            .client
            .pay_with_options(request, self.options().await?)
            .await?;
        Ok(response.into_owned().l1_payout_txid)
    }
}

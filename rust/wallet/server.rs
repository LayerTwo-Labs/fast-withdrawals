//! Connect server for the internal wallet API.

use std::{str::FromStr as _, sync::Arc};

use anyhow::Context as _;
use bdk_esplora::esplora_client;
use bdk_wallet::bitcoin::{FeeRate, secp256k1};
use connectrpc::{ConnectError, RequestContext, ServiceRequest, ServiceResult};
use fastwithdraw_proto::{
    wallet::{
        GetBalanceRequest, GetBalanceResponse, GetPayoutRequest, GetPayoutResponse, PayRequest,
        PayResponse, RegisterQuoteRequest, RegisterQuoteResponse, TickRequest, TickResponse,
    },
    wallet_connect::{WalletService, WalletServiceExt as _},
};
#[cfg(feature = "gcp-kms")]
use fastwithdraw_signer::KmsTxSigner;
use fastwithdraw_signer::{LocalTxSigner, Pkcs11TxSigner, TxSigner, pkcs11};
use fastwithdraw_thunder as thunder;

use crate::{
    Config,
    service::{ChainStatus, Error, Limits, Parts, Service},
    store,
};

impl From<Error> for ConnectError {
    fn from(err: Error) -> Self {
        match err {
            Error::InvalidArgument(msg) => ConnectError::invalid_argument(msg),
            Error::FailedPrecondition(msg) => ConnectError::failed_precondition(msg),
            Error::ResourceExhausted(msg) => ConnectError::resource_exhausted(msg),
            Error::AlreadyExists(msg) => ConnectError::already_exists(msg),
            Error::NotFound(msg) => ConnectError::not_found(msg),
            Error::Unavailable(msg) => ConnectError::unavailable(msg),
            err @ (Error::Thunder(_) | Error::Esplora(_)) => {
                tracing::warn!("{err:#}");
                ConnectError::unavailable(err.summary())
            }
            err @ (Error::Database(_) | Error::Internal(_)) => {
                tracing::error!("{err:#}");
                ConnectError::internal("internal wallet error")
            }
        }
    }
}

struct Handler {
    service: Arc<Service>,
    callers: Option<Callers>,
}

/// Who may call what, by the service account in the caller's ID token. See
/// [`Config::api_email`].
struct Callers {
    api: String,
    scheduler: String,
}

impl Handler {
    /// Admits the api to every method and the scheduler to `Tick` only.
    /// Anyone else, or a request without a readable identity, is refused.
    fn authorize(&self, ctx: &RequestContext, tick: bool) -> Result<(), ConnectError> {
        let Some(callers) = &self.callers else {
            return Ok(());
        };
        match caller_email(ctx) {
            Some(email) if email == callers.api => Ok(()),
            Some(email) if tick && email == callers.scheduler => Ok(()),
            _ => Err(ConnectError::permission_denied("caller not allowed")),
        }
    }
}

/// The `email` claim of the ID token Cloud Run IAM verified, without
/// verifying it again. Cloud Run takes the token from
/// `X-Serverless-Authorization` when present, and then passes
/// `Authorization` through unchecked, so that one is only read otherwise.
fn caller_email(ctx: &RequestContext) -> Option<String> {
    use base64::Engine as _;
    let header = ctx
        .headers()
        .get("x-serverless-authorization")
        .or_else(|| ctx.headers().get(http::header::AUTHORIZATION))?;
    let token = header.to_str().ok()?.strip_prefix("Bearer ")?;
    let payload = token.split('.').nth(1)?;
    let claims: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload.trim_end_matches('='))
            .ok()?,
    )
    .ok()?;
    Some(claims.get("email")?.as_str()?.to_owned())
}

impl WalletService for Handler {
    async fn register_quote(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, RegisterQuoteRequest>,
    ) -> ServiceResult<RegisterQuoteResponse> {
        self.authorize(&ctx, false)?;
        let request = request.to_owned_message();
        self.service
            .register(
                &request.withdrawal_id,
                request.l2_index,
                &request.l1_address,
                request.l1_payout_sats,
                request.l2_payment_sats,
            )
            .await?;
        Ok(connectrpc::Response::new(RegisterQuoteResponse {}))
    }

    async fn get_payout(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetPayoutRequest>,
    ) -> ServiceResult<GetPayoutResponse> {
        self.authorize(&ctx, false)?;
        let (payout_txid, settled) = self
            .service
            .get_payout(&request.to_owned_message().withdrawal_id)
            .await?;
        Ok(connectrpc::Response::new(GetPayoutResponse {
            l1_payout_txid: payout_txid,
            settled,
        }))
    }

    async fn pay(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, PayRequest>,
    ) -> ServiceResult<PayResponse> {
        self.authorize(&ctx, false)?;
        let request = request.to_owned_message();
        let txid = self
            .service
            .pay(
                &request.withdrawal_id,
                request.l2_index,
                thunder::OutPoint {
                    txid: request.l2_payment_txid,
                    vout: request.l2_payment_vout,
                },
                request
                    .l2_block
                    .into_option()
                    .map(|block| thunder::BlockRef {
                        height: block.height,
                        hash: block.hash,
                    }),
                &request.l1_address,
                request.l1_payout_sats,
            )
            .await?;
        Ok(connectrpc::Response::new(PayResponse {
            l1_payout_txid: txid.to_string(),
        }))
    }

    async fn get_balance(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, GetBalanceRequest>,
    ) -> ServiceResult<GetBalanceResponse> {
        self.authorize(&ctx, false)?;
        // Thunder or Esplora being unreachable pauses payouts too.
        let chain = self.service.chain_status().await.unwrap_or_else(|err| {
            tracing::warn!("{err:#}");
            ChainStatus {
                unsynced: Some(err.summary()),
                ..ChainStatus::default()
            }
        });
        Ok(connectrpc::Response::new(GetBalanceResponse {
            spendable_sats: self.service.spendable_balance().await?,
            thunder_synced: chain.unsynced.is_none(),
            hot_wallet_address: self.service.address()?.to_string(),
            daily_cap_left_sats: self.service.daily_cap_left().await?,
            l1_tip_height: chain.l1_tip_height,
            l2_tip_height: chain.l2_tip_height,
            l2_tip_bmm_height: chain.l2_tip_bmm_height,
            thunder_connected_peers: chain.thunder_connected_peers,
            thunder_unsynced_reason: chain.unsynced.unwrap_or_default(),
        }))
    }

    async fn tick(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, TickRequest>,
    ) -> ServiceResult<TickResponse> {
        self.authorize(&ctx, true)?;
        Ok(connectrpc::Response::new(TickResponse {
            pending_payouts: self.service.tick().await?,
        }))
    }
}

async fn signer(config: &Config) -> anyhow::Result<Arc<dyn TxSigner>> {
    #[cfg(feature = "gcp-kms")]
    if let Some(key_version) = &config.key.kms_key_version {
        let client = google_cloud_kms_v1::client::KeyManagementService::builder()
            .build()
            .await
            .context("KMS client")?;
        return Ok(Arc::new(
            KmsTxSigner::new(client, key_version.clone()).await?,
        ));
    }
    if let Some(path) = &config.key.pkcs11_config {
        let pin =
            std::env::var("PKCS11_PIN").context("PKCS11_PIN is required with a PKCS#11 signer")?;
        let pkcs11 = pkcs11::Config::load(path)?;
        return Ok(Arc::new(Pkcs11TxSigner::open(&pkcs11, &pin)?));
    }
    let hex_key = config
        .key
        .local_key
        .as_deref()
        .context("no payout key configured")?;
    let secret = secp256k1::SecretKey::from_str(hex_key).context("invalid local key")?;
    Ok(Arc::new(LocalTxSigner::new(secret)))
}

pub async fn service(config: &Config) -> anyhow::Result<Service> {
    // A payment first seen deeper than the scan counts as scan depth + 1
    // confirmations; requiring more would never pay it out.
    anyhow::ensure!(
        config.thunder_confirmations <= config.thunder_scan_depth,
        "THUNDER_CONFIRMATIONS must not exceed THUNDER_SCAN_DEPTH"
    );
    let db = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&config.database_url)
        .await
        .context("connect to Postgres")?;
    store::migrate(&db).await.context("migrate")?;
    let esplora = esplora_client::Builder::new(&config.esplora_url)
        .timeout(30)
        .build_async()
        .context("Esplora client")?;
    Ok(Service::new(Parts {
        db,
        esplora,
        thunder: thunder::Client::new(&config.thunder_url, config.thunder_scan_depth),
        xpub: config.thunder_xpub,
        signer: signer(config).await?,
        network: config.network,
        required_confirmations: config.thunder_confirmations,
        thunder_max_l1_lag: config.thunder_max_l1_lag,
        limits: Limits {
            max_payout_sats: config.max_payout_sats,
            daily_cap_sats: config.daily_cap_sats,
            max_fee_sats: config.max_fee_sats,
            fee_bump_subsidy_sats: config.fee_bump_subsidy_sats,
            min_fee_bps: config.min_fee_bps,
        },
        fee_target_blocks: config.fee_target_blocks,
        fallback_fee_rate: FeeRate::from_sat_per_vb(config.fallback_fee_sat_per_vb)
            .context("fallback fee rate out of range")?,
        fee_bump_after_blocks: config.fee_bump_after_blocks,
    }))
}

/// Serves the wallet API until the process receives SIGINT or SIGTERM.
pub async fn run(config: Config) -> anyhow::Result<()> {
    let service = Arc::new(service(&config).await?);
    tracing::info!(address = %service.address()?, "wallet ready");
    let handler = Handler {
        service,
        callers: config
            .api_email
            .clone()
            .zip(config.scheduler_email.clone())
            .map(|(api, scheduler)| Callers { api, scheduler }),
    };
    let router = Arc::new(handler).register(connectrpc::Router::new());
    let app = axum::Router::new()
        .route("/healthz", axum::routing::get(|| async { "ok" }))
        .fallback_service(router.into_axum_service());
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    tracing::info!("listening on {}", config.listen);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown())
        .await?;
    Ok(())
}

async fn shutdown() {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = terminate.recv() => {}
    }
}

//! Public Connect API, the internal service, and HTTP middleware.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    str::FromStr as _,
    sync::Arc,
    time::Instant,
};

use anyhow::Context as _;
use axum::{
    extract::{ConnectInfo, Request, State},
    http::{HeaderValue, StatusCode, header},
    middleware::Next,
    response::{IntoResponse as _, Response},
};
use buffa::{Inline, MessageField};
use buffa_types::google::protobuf::Timestamp;
use connectrpc::{ConnectError, RequestContext, ServiceRequest, ServiceResult};
use fastwithdraw_proto::{
    internal::{ListPaidIndexesRequest, ListPaidIndexesResponse, TickRequest, TickResponse},
    internal_connect::{InternalService, InternalServiceExt as _},
    v1::{
        CreateWithdrawalRequest, CreateWithdrawalResponse, GetServiceInfoRequest,
        GetServiceInfoResponse, GetStatusRequest, GetStatusResponse, GetWithdrawalRequest,
        GetWithdrawalResponse, RequestRefundRequest, RequestRefundResponse, SidechainPolicy,
        SidechainStatus, SubmitPaymentRequest, SubmitPaymentResponse, Withdrawal, WithdrawalStatus,
    },
    v1_connect::{FastWithdrawalService, FastWithdrawalServiceExt as _},
};
#[cfg(feature = "gcp-kms")]
use fastwithdraw_signer::KmsQuoteSigner;
use fastwithdraw_signer::{LocalQuoteSigner, QuoteSigner};
use fastwithdraw_thunder as thunder;
use parking_lot::Mutex;

use crate::{
    Config,
    auth::{InternalAuth, SchedulerIdentity},
    service::{Error, Parts, Policy, SIDECHAIN, Service},
    store::{self, Status},
    wallet_client::WalletClient,
};

impl From<Error> for ConnectError {
    fn from(err: Error) -> Self {
        match err {
            Error::InvalidArgument(msg) => ConnectError::invalid_argument(msg),
            Error::NotFound => ConnectError::not_found(err.to_string()),
            Error::RequestConflict | Error::PaymentClaimed | Error::StateConflict => {
                ConnectError::already_exists(err.to_string())
            }
            Error::LiquidityExceeded | Error::TooManyQuotes(_) => {
                ConnectError::resource_exhausted(err.to_string())
            }
            Error::ThunderStale => ConnectError::unavailable(err.to_string()),
            Error::NotUnderpaid => ConnectError::failed_precondition(err.to_string()),
            Error::RefundAddressConflict => ConnectError::already_exists(err.to_string()),
            err @ (Error::Thunder(_) | Error::Wallet(_)) => {
                tracing::warn!("{err:#}");
                ConnectError::unavailable("upstream service unavailable")
            }
            err @ (Error::Database(_) | Error::Signer(_) | Error::Internal(_)) => {
                tracing::error!("{err:#}");
                ConnectError::internal("internal service error")
            }
        }
    }
}

fn status(status: Status) -> WithdrawalStatus {
    match status {
        Status::AwaitingPayment => WithdrawalStatus::WITHDRAWAL_STATUS_AWAITING_PAYMENT,
        Status::ConfirmingPayment => WithdrawalStatus::WITHDRAWAL_STATUS_CONFIRMING_PAYMENT,
        Status::PaymentConfirmed => WithdrawalStatus::WITHDRAWAL_STATUS_PAYMENT_CONFIRMED,
        Status::Paid => WithdrawalStatus::WITHDRAWAL_STATUS_PAID,
        Status::Expired => WithdrawalStatus::WITHDRAWAL_STATUS_EXPIRED,
        Status::Failed => WithdrawalStatus::WITHDRAWAL_STATUS_FAILED,
        Status::Underpaid => WithdrawalStatus::WITHDRAWAL_STATUS_UNDERPAID,
        Status::Refunded => WithdrawalStatus::WITHDRAWAL_STATUS_REFUNDED,
    }
}

fn proto(w: store::Withdrawal) -> MessageField<Withdrawal, Inline<Withdrawal>> {
    let (payment_txid, payment_vout) = w.payment.unwrap_or_default();
    MessageField::some(Withdrawal {
        withdrawal_id: w.id,
        sidechain: w.sidechain,
        l2_payment_address: w.l2_address,
        l2_payment_sats: w.l2_payment_sats,
        l1_address: w.l1_destination,
        l1_payout_sats: w.l1_payout_sats,
        service_fee_sats: w.service_fee_sats,
        required_confirmations: w.required_confirmations,
        status: status(w.status).into(),
        expires_at: MessageField::some(Timestamp::from_unix_secs(w.expires_at)),
        l2_payment_txid: payment_txid,
        l2_payment_vout: payment_vout,
        l1_payout_txid: w.payout_txid.unwrap_or_default(),
        quote_signature: w.quote_signature,
        created_at: MessageField::some(Timestamp::from_unix_secs(w.created_at)),
        updated_at: MessageField::some(Timestamp::from_unix_secs(w.updated_at)),
        // Also kept when a full payment replaced the underpayment.
        l2_received_sats: matches!(w.status, Status::Underpaid | Status::Refunded)
            .then_some(w.received_sats)
            .flatten()
            .unwrap_or_default(),
        l2_refund_address: w.refund_address.unwrap_or_default(),
    })
}

struct Handler(Arc<Service>);

impl FastWithdrawalService for Handler {
    async fn create_withdrawal(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateWithdrawalRequest>,
    ) -> ServiceResult<CreateWithdrawalResponse> {
        let request = request.to_owned_message();
        let client = ctx.extensions().get::<ClientKey>();
        let withdrawal = self
            .0
            .create(
                &request.request_id,
                &request.sidechain,
                &request.l1_address,
                request.l1_payout_sats,
                client.map(|key| key.0.as_str()),
            )
            .await?;
        Ok(connectrpc::Response::new(CreateWithdrawalResponse {
            withdrawal: proto(withdrawal),
        }))
    }

    async fn request_refund(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, RequestRefundRequest>,
    ) -> ServiceResult<RequestRefundResponse> {
        let request = request.to_owned_message();
        let withdrawal = self
            .0
            .request_refund(&request.withdrawal_id, &request.l2_refund_address)
            .await?;
        Ok(connectrpc::Response::new(RequestRefundResponse {
            withdrawal: proto(withdrawal),
        }))
    }

    async fn submit_payment(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, SubmitPaymentRequest>,
    ) -> ServiceResult<SubmitPaymentResponse> {
        let request = request.to_owned_message();
        let withdrawal = self
            .0
            .submit(
                &request.withdrawal_id,
                &request.l2_payment_txid,
                request.l2_payment_vout,
            )
            .await?;
        Ok(connectrpc::Response::new(SubmitPaymentResponse {
            withdrawal: proto(withdrawal),
        }))
    }

    async fn get_withdrawal(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, GetWithdrawalRequest>,
    ) -> ServiceResult<GetWithdrawalResponse> {
        let withdrawal = self
            .0
            .get(&request.to_owned_message().withdrawal_id)
            .await?;
        Ok(connectrpc::Response::new(GetWithdrawalResponse {
            withdrawal: proto(withdrawal),
        }))
    }

    async fn get_service_info(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, GetServiceInfoRequest>,
    ) -> ServiceResult<GetServiceInfoResponse> {
        let policy = self.0.policy;
        Ok(connectrpc::Response::new(GetServiceInfoResponse {
            quote_signing_public_key: self.0.quote_public_key().to_vec(),
            fee_basis_points: policy.fee_basis_points,
            min_payout_sats: policy.min_payout_sats,
            max_payout_sats: policy.max_payout_sats,
            sidechains: vec![SidechainPolicy {
                sidechain: SIDECHAIN.to_owned(),
                required_confirmations: policy.required_confirmations,
            }],
            hot_wallet_address: self.0.hot_wallet_address().await,
        }))
    }

    async fn get_status(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, GetStatusRequest>,
    ) -> ServiceResult<GetStatusResponse> {
        let status = self.0.status().await;
        let mut response = GetStatusResponse {
            accepting_withdrawals: status.max_payout_now.is_ok(),
            max_payout_now_sats: status.max_payout_now.clone().unwrap_or_default(),
            paused_reason: status.max_payout_now.err().unwrap_or_default(),
            ..Default::default()
        };
        if let Some(wallet) = status.wallet {
            response.hot_wallet_balance_sats = wallet.spendable_sats;
            response.daily_cap_left_sats = wallet.daily_cap_left_sats;
            response.l1_tip_height = wallet.l1_tip_height;
            response.sidechains = vec![SidechainStatus {
                sidechain: SIDECHAIN.to_owned(),
                tip_height: wallet.l2_tip_height,
                tip_bmm_height: wallet.l2_tip_bmm_height,
                connected_peers: wallet.thunder_connected_peers,
            }];
        }
        Ok(connectrpc::Response::new(response))
    }
}

/// Set by the load balancer from `{client_ip_address}`.
pub(crate) const CLIENT_IP_HEADER: &str = "x-client-ip";

/// Rate-limit key: the address, or its /64 for IPv6, since one host
/// typically controls a whole /64.
fn rate_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            octets[8..].fill(0);
            IpAddr::from(octets)
        }
    }
}

/// Token bucket per client.
pub struct RateLimiter {
    rate: f64,
    burst: f64,
    visitors: Mutex<HashMap<IpAddr, (f64, Instant)>>,
}

impl RateLimiter {
    const MAX_VISITORS: usize = 10_000;

    pub fn new(rate: f64, burst: f64) -> Self {
        Self {
            rate,
            burst,
            visitors: Mutex::new(HashMap::new()),
        }
    }

    fn allow(&self, ip: IpAddr, now: Instant) -> bool {
        let key = rate_key(ip);
        let mut visitors = self.visitors.lock();
        if !visitors.contains_key(&key) && visitors.len() >= Self::MAX_VISITORS {
            // Full buckets are as good as absent; then evict the stalest.
            let (rate, burst) = (self.rate, self.burst);
            visitors.retain(|_, (tokens, last)| {
                *tokens + now.duration_since(*last).as_secs_f64() * rate < burst
            });
            if visitors.len() >= Self::MAX_VISITORS
                && let Some(oldest) = visitors
                    .iter()
                    .min_by_key(|(_, (_, last))| *last)
                    .map(|(key, _)| *key)
            {
                visitors.remove(&oldest);
            }
        }
        let (tokens, last) = visitors.entry(key).or_insert((self.burst, now));
        *tokens = (*tokens + now.duration_since(*last).as_secs_f64() * self.rate).min(self.burst);
        *last = now;
        if *tokens < 1.0 {
            return false;
        }
        *tokens -= 1.0;
        true
    }
}

/// The client IP: the load balancer's `X-Client-IP`, else the TCP peer. The
/// last value wins, whether in a later header line or after a comma, in case
/// a client-sent header survives in front of the load balancer's.
fn client_ip(request: &Request) -> Option<IpAddr> {
    request
        .headers()
        .get_all(CLIENT_IP_HEADER)
        .iter()
        .next_back()
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.rsplit(',').next())
        .and_then(|value| IpAddr::from_str(value.trim()).ok())
        .or_else(|| {
            request
                .extensions()
                .get::<ConnectInfo<SocketAddr>>()
                .map(|info| info.0.ip())
        })
}

/// The client's rate-limit key, as a request extension for handlers.
#[derive(Clone, Debug)]
struct ClientKey(String);

async fn rate_limit(
    State(limiter): State<Arc<RateLimiter>>,
    mut request: Request,
    next: Next,
) -> Response {
    let ip = client_ip(&request);
    if let Some(ip) = ip {
        request
            .extensions_mut()
            .insert(ClientKey(rate_key(ip).to_string()));
    }
    if let Some(ip) = ip
        && !limiter.allow(ip, Instant::now())
    {
        let mut response = (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response();
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        return response;
    }
    next.run(request).await
}

async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// For the scheduler and the operator; see [`InternalAuth`].
struct Internal {
    service: Arc<Service>,
    auth: InternalAuth,
}

impl InternalService for Internal {
    async fn tick(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, TickRequest>,
    ) -> ServiceResult<TickResponse> {
        self.auth.authorize(&ctx).await?;
        self.service.tick().await?;
        Ok(connectrpc::Response::new(TickResponse {}))
    }

    async fn list_paid_indexes(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, ListPaidIndexesRequest>,
    ) -> ServiceResult<ListPaidIndexesResponse> {
        self.auth.authorize(&ctx).await?;
        Ok(connectrpc::Response::new(ListPaidIndexesResponse {
            l2_indexes: self.service.paid_indexes().await?,
        }))
    }
}

async fn signer(config: &Config) -> anyhow::Result<Arc<dyn QuoteSigner>> {
    #[cfg(feature = "gcp-kms")]
    if let Some(key_version) = &config.key.kms_key_version {
        let client = google_cloud_kms_v1::client::KeyManagementService::builder()
            .build()
            .await
            .context("KMS client")?;
        return Ok(Arc::new(
            KmsQuoteSigner::new(client, key_version.clone()).await?,
        ));
    }
    let hex_key = config
        .key
        .local_key
        .as_deref()
        .context("no quote key configured")?;
    let secret: [u8; 32] = hex::decode(hex_key)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .context("local key must be 32 hex-encoded bytes")?;
    Ok(Arc::new(LocalQuoteSigner::new(secret)))
}

pub async fn service(config: &Config) -> anyhow::Result<Service> {
    let policy = Policy {
        fee_basis_points: config.fee_bps,
        min_payout_sats: config.min_payout_sats,
        max_payout_sats: config.max_payout_sats,
        max_exposure_bps: config.max_exposure_bps,
        miner_fee_reserve_sats: config.miner_fee_reserve_sats,
        required_confirmations: config.thunder_confirmations,
        quote_ttl_secs: config.quote_ttl_secs,
        max_open_quotes_per_client: config.max_open_quotes_per_client,
        max_watched_quotes: config.max_watched_quotes,
    };
    policy.validate().map_err(anyhow::Error::msg)?;
    // A payment first seen deeper than the scan counts as scan depth + 1
    // confirmations; requiring more would never pay it out.
    anyhow::ensure!(
        config.thunder_confirmations <= config.thunder_scan_depth,
        "THUNDER_CONFIRMATIONS must not exceed THUNDER_SCAN_DEPTH"
    );
    let db = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&config.database_url)
        .await
        .context("connect to Postgres")?;
    store::migrate(&db).await.context("migrate")?;
    Ok(Service::new(Parts {
        db,
        thunder: thunder::Client::new(&config.thunder_url, config.thunder_scan_depth),
        xpub: config.thunder_xpub,
        wallet: WalletClient::new(&config.wallet_url, config.wallet_id_token_auth)?,
        signer: signer(config).await?,
        network: config.network,
        policy,
    }))
}

/// The public API's schema (not the internal service's), served over gRPC
/// reflection so `buf curl` and grpcurl work without a local copy. Embedded
/// in the generated code by `just proto`.
const PUBLIC_DESCRIPTORS: &[u8] = fastwithdraw_proto::v1::FILE_DESCRIPTOR_SET_BYTES;

/// The request limits: messages are small, so anything larger is refused
/// before it is read in full.
const MAX_MESSAGE_BYTES: usize = 64 << 10;

fn app(service: Arc<Service>, limiter: Arc<RateLimiter>, auth: InternalAuth) -> axum::Router {
    let router = Arc::new(Handler(Arc::clone(&service))).register(connectrpc::Router::new());
    let reflector = connectrpc_reflection::Reflector::from_descriptor_set_bytes(PUBLIC_DESCRIPTORS)
        .expect("embedded descriptor set");
    let router = connectrpc_reflection::install(router, reflector);
    let connect = Arc::new(Internal { service, auth })
        .register(router)
        .into_axum_service()
        .with_limits(
            connectrpc::Limits::default()
                .with_max_request_body_size(MAX_MESSAGE_BYTES)
                .with_max_message_size(MAX_MESSAGE_BYTES),
        );
    let public = axum::Router::new()
        .fallback_service(connect)
        .layer(axum::middleware::from_fn_with_state(limiter, rate_limit));
    axum::Router::new()
        .route("/healthz", axum::routing::get(|| async { "ok" }))
        .merge(public)
        .layer(axum::middleware::from_fn(security_headers))
}

/// Serves the API until the process receives SIGINT or SIGTERM.
pub async fn run(config: Config) -> anyhow::Result<()> {
    let service = Arc::new(service(&config).await?);
    let limiter = Arc::new(RateLimiter::new(config.rate_limit, config.rate_burst));
    let scheduler = match (&config.scheduler_audience, &config.scheduler_email) {
        (Some(audience), Some(email)) => Some(SchedulerIdentity {
            audience: audience.clone(),
            email: email.clone(),
            jwks_url: config.scheduler_jwks_url.clone(),
        }),
        (None, None) => None,
        _ => anyhow::bail!("set both API_SCHEDULER_AUDIENCE and API_SCHEDULER_EMAIL, or neither"),
    };
    let auth = InternalAuth::new(config.internal_token.clone(), scheduler)?;
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    tracing::info!("listening on {}", config.listen);
    axum::serve(
        listener,
        app(service, limiter, auth).into_make_service_with_connect_info::<SocketAddr>(),
    )
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

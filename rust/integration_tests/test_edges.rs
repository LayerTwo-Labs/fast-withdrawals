//! The api's edge: rate limiting, authentication to the internal service,
//! and authentication to the wallet. These don't need a chain.

use anyhow::{Context as _, ensure};
use connectrpc::{
    client::{CallOptions, ClientConfig, Http2Connection},
    error::ErrorCode,
};
use connectrpc_reflection::{
    ServerReflectionClient,
    wire::v1::{
        ServerReflectionRequest, server_reflection_request::MessageRequest,
        server_reflection_response::MessageResponse,
    },
};
use fastwithdraw_proto::{
    internal::ListPaidIndexesRequest,
    v1::{CreateWithdrawalRequest, GetServiceInfoRequest},
    wallet::{RegisterQuoteRequest, TickRequest as WalletTickRequest},
};

use crate::{
    fakes::{GoogleIdTokens, ID_TOKEN, Metadata, Proxy},
    helpers::expect_code,
    setup::{INTERNAL_TOKEN, ServiceOptions, Services, bearer, test_dir},
    util::{BinPaths, TestContext},
};

/// Nothing listens here; these tests never reach Thunder or Esplora.
const UNREACHABLE: &str = "http://127.0.0.1:1";

fn from_ip(ip: &str) -> CallOptions {
    CallOptions::default().with_header(
        http::HeaderName::from_static("x-client-ip"),
        http::HeaderValue::from_str(ip).expect("valid header"),
    )
}

/// Requests are limited per `X-Client-IP`, the header the load balancer sets.
pub async fn rate_limit(context: TestContext, bins: BinPaths) -> anyhow::Result<()> {
    let dir = test_dir(context.name)?;
    let mut options = ServiceOptions::detached(UNREACHABLE.to_owned(), UNREACHABLE.to_owned());
    options.api_env.extend([
        ("RATE_LIMIT", "0.001".to_owned()),
        ("RATE_BURST", "3".to_owned()),
    ]);
    let services = Services::start(&context, &bins, &dir, options).await?;
    let info = |ip: &'static str| {
        services
            .api
            .get_service_info_with_options(GetServiceInfoRequest::default(), from_ip(ip))
    };
    for _ in 0..3 {
        info("203.0.113.7").await?;
    }
    let limited = info("203.0.113.7").await;
    ensure!(
        limited.is_err(),
        "fourth request within the burst was allowed"
    );
    expect_code(limited, ErrorCode::Unavailable)?;
    info("203.0.113.8").await?;
    // IPv6 clients share a bucket per /64: one host gets many addresses.
    for _ in 0..3 {
        info("2001:db8::1").await?;
    }
    expect_code(info("2001:db8::2").await, ErrorCode::Unavailable)?;
    info("2001:db8:0:1::1").await?;
    services.check_running()
}

/// With ID-token auth on, the api gets a token for the wallet's URL from the
/// metadata server and sends it on every wallet call.
pub async fn wallet_id_token_auth(context: TestContext, bins: BinPaths) -> anyhow::Result<()> {
    let dir = test_dir(context.name)?;
    let metadata = Metadata::start().await?;
    let wallet_proxy = Proxy::start(UNREACHABLE).await?;
    let mut options = ServiceOptions::detached(UNREACHABLE.to_owned(), UNREACHABLE.to_owned());
    options.wallet_url = Some(wallet_proxy.url());
    options.api_env.extend([
        ("WALLET_ID_TOKEN_AUTH", "true".to_owned()),
        ("GCE_METADATA_HOST", metadata.host()),
    ]);
    let services = Services::start(&context, &bins, &dir, options).await?;
    wallet_proxy.set_upstream(format!("http://127.0.0.1:{}", services.wallet_port));

    // Quoting asks the wallet for its balance. Esplora is unreachable, so the
    // call fails, but only after the request reached the wallet.
    let quote = services
        .api
        .create_withdrawal(CreateWithdrawalRequest {
            request_id: uuid::Uuid::new_v4().to_string(),
            sidechain: "thunder".to_owned(),
            l1_address: services.wallet_address.to_string(),
            l1_payout_sats: 100_000,
        })
        .await;
    expect_code(quote, ErrorCode::Unavailable)?;
    ensure!(
        wallet_proxy.authorizations() == [format!("Bearer {ID_TOKEN}")],
        "authorization headers: {:?}",
        wallet_proxy.authorizations()
    );
    ensure!(
        metadata.audiences() == [wallet_proxy.url()],
        "token audiences: {:?}",
        metadata.audiences()
    );
    services.check_running()
}

/// The public API is discoverable over gRPC reflection, so `buf curl` works
/// without a local schema. The internal service isn't listed.
pub async fn reflection(context: TestContext, bins: BinPaths) -> anyhow::Result<()> {
    let dir = test_dir(context.name)?;
    let options = ServiceOptions::detached(UNREACHABLE.to_owned(), UNREACHABLE.to_owned());
    let services = Services::start(&context, &bins, &dir, options).await?;
    let uri: http::Uri = format!("http://127.0.0.1:{}", services.api_port).parse()?;
    // A bidirectional stream: HTTP/2 only, as `buf curl` speaks it.
    let connection = Http2Connection::connect_plaintext(uri.clone()).await?;
    let client = ServerReflectionClient::new(connection.shared(16), ClientConfig::new(uri));
    let mut stream = client.server_reflection_info().await?;
    for request in [
        MessageRequest::ListServices(String::new()),
        MessageRequest::FileContainingSymbol("fastwithdraw.v1.FastWithdrawalService".to_owned()),
    ] {
        stream
            .send(ServerReflectionRequest {
                message_request: Some(request),
                ..Default::default()
            })
            .await?;
    }
    stream.close_send();

    let listed = stream
        .message()
        .await?
        .context("no list response")?
        .to_owned_message();
    let Some(MessageResponse::ListServicesResponse(listed)) = listed.message_response else {
        anyhow::bail!("unexpected list response: {listed:?}");
    };
    let mut names: Vec<_> = listed.service.into_iter().map(|s| s.name).collect();
    names.sort();
    ensure!(
        names
            == [
                "fastwithdraw.v1.FastWithdrawalService",
                "grpc.reflection.v1.ServerReflection",
                "grpc.reflection.v1alpha.ServerReflection",
            ],
        "listed services: {names:?}"
    );

    let file = stream
        .message()
        .await?
        .context("no file response")?
        .to_owned_message();
    ensure!(
        matches!(
            file.message_response,
            Some(MessageResponse::FileDescriptorResponse(ref files))
                if !files.file_descriptor_proto.is_empty()
        ),
        "unexpected file response: {file:?}"
    );
    Ok(())
}

/// The internal service needs the operator token, whether the request came
/// through the load balancer or not; without one configured, it is closed.
pub async fn internal_token(context: TestContext, bins: BinPaths) -> anyhow::Result<()> {
    let dir = test_dir(context.name)?;
    let options = ServiceOptions::detached(UNREACHABLE.to_owned(), UNREACHABLE.to_owned());
    let services = Services::start(&context, &bins, &dir, options).await?;
    let list = |options: CallOptions| {
        services
            .internal
            .list_paid_indexes_with_options(ListPaidIndexesRequest::default(), options)
    };
    expect_code(
        list(CallOptions::default()).await,
        ErrorCode::Unauthenticated,
    )?;
    expect_code(
        list(from_ip("203.0.113.7")).await,
        ErrorCode::Unauthenticated,
    )?;
    expect_code(
        list(bearer("wrong-token")).await,
        ErrorCode::Unauthenticated,
    )?;
    let listed = list(bearer(INTERNAL_TOKEN)).await?.into_owned();
    ensure!(listed.l2_indexes.is_empty(), "{listed:?}");
    // Through the load balancer too.
    let through_lb = bearer(INTERNAL_TOKEN).with_header(
        http::HeaderName::from_static("x-client-ip"),
        http::HeaderValue::from_static("203.0.113.7"),
    );
    list(through_lb).await?;
    services.check_running()?;

    let dir = test_dir(&format!("{}-untokened", context.name))?;
    let mut options = ServiceOptions::detached(UNREACHABLE.to_owned(), UNREACHABLE.to_owned());
    options.api_env.push(("API_INTERNAL_TOKEN", String::new()));
    let refused = Services::start(&context, &bins, &dir, options).await;
    ensure!(
        refused.is_err(),
        "the api started with an empty internal token"
    );
    Ok(())
}

/// With the scheduler's identity configured, the internal service also
/// admits Google ID tokens for that audience and service account, and
/// nothing else.
pub async fn scheduler_id_token(context: TestContext, bins: BinPaths) -> anyhow::Result<()> {
    const AUDIENCE: &str = "https://withdraw.example";
    const SCHEDULER: &str = "scheduler@example.iam.gserviceaccount.com";
    let dir = test_dir(context.name)?;
    let google = GoogleIdTokens::start(&dir).await?;
    let mut options = ServiceOptions::detached(UNREACHABLE.to_owned(), UNREACHABLE.to_owned());
    options.api_env.extend([
        ("API_SCHEDULER_AUDIENCE", AUDIENCE.to_owned()),
        ("API_SCHEDULER_EMAIL", SCHEDULER.to_owned()),
        ("API_SCHEDULER_JWKS_URL", google.jwks_url()),
    ]);
    let services = Services::start(&context, &bins, &dir, options).await?;
    let list = |token: String| {
        services
            .internal
            .list_paid_indexes_with_options(ListPaidIndexesRequest::default(), bearer(&token))
    };
    list(google.token(AUDIENCE, SCHEDULER, 300)?).await?;
    // The scheduler calls the service directly; through the load balancer, ID
    // tokens aren't even looked at.
    let through_lb = bearer(&google.token(AUDIENCE, SCHEDULER, 300)?).with_header(
        http::HeaderName::from_static("x-client-ip"),
        http::HeaderValue::from_static("203.0.113.7"),
    );
    expect_code(
        services
            .internal
            .list_paid_indexes_with_options(ListPaidIndexesRequest::default(), through_lb)
            .await,
        ErrorCode::Unauthenticated,
    )?;
    for (token, why) in [
        (
            google.token("https://other.example", SCHEDULER, 300)?,
            "another audience",
        ),
        (
            google.token(AUDIENCE, "someone@example.com", 300)?,
            "another account",
        ),
        (
            google.token(AUDIENCE, SCHEDULER, -3600)?,
            "an expired token",
        ),
    ] {
        expect_code(list(token).await, ErrorCode::Unauthenticated)
            .with_context(|| format!("accepted {why}"))?;
    }
    services.check_running()
}

/// With the callers configured, only the api may use the wallet, and the
/// scheduler only Tick. Requests without a readable identity are refused,
/// and the identity is read from the header Cloud Run verifies.
pub async fn wallet_callers(context: TestContext, bins: BinPaths) -> anyhow::Result<()> {
    const API: &str = "api@example.iam.gserviceaccount.com";
    const SCHEDULER: &str = "scheduler@example.iam.gserviceaccount.com";
    let dir = test_dir(context.name)?;
    // The wallet reads the caller from tokens Cloud Run has verified, so any
    // well-formed token stands in for one here.
    let google = GoogleIdTokens::start(&dir).await?;
    let mut options = ServiceOptions::detached(UNREACHABLE.to_owned(), UNREACHABLE.to_owned());
    options.wallet_env.extend([
        ("WALLET_API_EMAIL", API.to_owned()),
        ("WALLET_SCHEDULER_EMAIL", SCHEDULER.to_owned()),
    ]);
    let services = Services::start(&context, &bins, &dir, options).await?;
    let as_caller = |email: &str| -> anyhow::Result<CallOptions> {
        Ok(bearer(&google.token("https://wallet", email, 300)?))
    };
    let register = |options: CallOptions| {
        services.wallet.register_quote_with_options(
            RegisterQuoteRequest {
                withdrawal_id: uuid::Uuid::new_v4().to_string(),
                l2_index: 1,
                l1_address: services.wallet_address.to_string(),
                l1_payout_sats: 100_000,
                l2_payment_sats: 101_000,
            },
            options,
        )
    };
    let tick = |options: CallOptions| {
        services
            .wallet
            .tick_with_options(WalletTickRequest {}, options)
    };
    let denied = ErrorCode::PermissionDenied;
    expect_code(register(CallOptions::default()).await, denied)?;
    expect_code(register(as_caller(SCHEDULER)?).await, denied)?;
    expect_code(register(as_caller("someone@example.com")?).await, denied)?;
    expect_code(tick(CallOptions::default()).await, denied)?;
    expect_code(tick(as_caller("someone@example.com")?).await, denied)?;
    // The api gets as far as validation: the wallet refuses to pay itself.
    expect_code(register(as_caller(API)?).await, ErrorCode::InvalidArgument)?;
    for caller in [API, SCHEDULER] {
        let result = tick(as_caller(caller)?).await;
        ensure!(
            !matches!(&result, Err(err) if err.code == denied),
            "{caller} may tick: {result:?}"
        );
    }
    // Cloud Run verifies X-Serverless-Authorization when it's present and
    // passes Authorization through unchecked: the first one counts.
    let forged = as_caller(API)?.with_header(
        http::HeaderName::from_static("x-serverless-authorization"),
        http::HeaderValue::from_str(&format!(
            "Bearer {}",
            google.token("https://wallet", SCHEDULER, 300)?
        ))?,
    );
    expect_code(register(forged).await, denied)?;
    services.check_running()
}

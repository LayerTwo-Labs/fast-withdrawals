//! Fake third parties: an HTTP proxy that records requests and injects
//! failures, and a GCE metadata server that issues ID tokens.

use std::{collections::HashMap, sync::Arc};

use anyhow::Context as _;
use base64::Engine as _;

use axum::{
    body::{Body, to_bytes},
    extract::{Query, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse as _, Response},
};
use parking_lot::Mutex;

use crate::util::reserve_port;

async fn serve(router: axum::Router) -> anyhow::Result<u16> {
    let port = reserve_port()?;
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    tokio::spawn(async move { axum::serve(listener, router).await });
    Ok(port)
}

#[derive(Default)]
struct ProxyState {
    upstream: Mutex<String>,
    /// `POST`s to this path get a 503.
    fail_posts_to: Mutex<Option<String>>,
    /// Behave like mempool.space's Esplora API, as on signet: a 404 for an
    /// unknown transaction's status, where electrs says unconfirmed.
    mimic_mempool: Mutex<bool>,
    authorizations: Mutex<Vec<String>>,
    /// Set `X-Client-IP`, as the load balancer in front of the api does.
    stamp_client_ip: Mutex<bool>,
    http: reqwest::Client,
}

/// A forwarding HTTP proxy.
#[derive(Clone)]
pub struct Proxy {
    pub port: u16,
    state: Arc<ProxyState>,
}

impl Proxy {
    pub async fn start(upstream: impl Into<String>) -> anyhow::Result<Self> {
        let state = Arc::new(ProxyState {
            upstream: Mutex::new(upstream.into()),
            ..Default::default()
        });
        let router = axum::Router::new()
            .fallback(forward)
            .with_state(Arc::clone(&state));
        Ok(Self {
            port: serve(router).await?,
            state,
        })
    }

    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    pub fn set_upstream(&self, upstream: impl Into<String>) {
        *self.state.upstream.lock() = upstream.into();
    }

    pub fn fail_posts_to(&self, path: Option<&str>) {
        *self.state.fail_posts_to.lock() = path.map(str::to_owned);
    }

    pub fn mimic_mempool(&self, enabled: bool) {
        *self.state.mimic_mempool.lock() = enabled;
    }

    pub fn stamp_client_ip(&self, enabled: bool) {
        *self.state.stamp_client_ip.lock() = enabled;
    }

    /// `Authorization` headers seen so far.
    pub fn authorizations(&self) -> Vec<String> {
        self.state.authorizations.lock().clone()
    }
}

async fn forward(State(state): State<Arc<ProxyState>>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    if let Some(auth) = parts
        .headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
    {
        state.authorizations.lock().push(auth.to_owned());
    }
    let path = parts.uri.path().to_owned();
    if parts.method == axum::http::Method::POST
        && state.fail_posts_to.lock().as_deref() == Some(path.as_str())
    {
        return (StatusCode::SERVICE_UNAVAILABLE, "injected failure").into_response();
    }
    if *state.mimic_mempool.lock()
        && parts.method == axum::http::Method::GET
        && let Some(txid) = path
            .strip_prefix("/tx/")
            .and_then(|rest| rest.strip_suffix("/status"))
    {
        let url = format!("{}/tx/{txid}", state.upstream.lock());
        if let Ok(response) = state.http.get(url).send().await
            && response.status() == StatusCode::NOT_FOUND
        {
            return (
                StatusCode::NOT_FOUND,
                r#"{"error":"No such mempool or blockchain transaction"}"#,
            )
                .into_response();
        }
    }
    let Ok(body) = to_bytes(body, 16 << 20).await else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let path_and_query = parts.uri.path_and_query().map_or("/", |pq| pq.as_str());
    let url = format!("{}{path_and_query}", state.upstream.lock());
    let mut headers = HeaderMap::new();
    for (name, value) in &parts.headers {
        if name != "host" {
            headers.insert(name.clone(), value.clone());
        }
    }
    if *state.stamp_client_ip.lock() {
        headers.insert("x-client-ip", HeaderValue::from_static("203.0.113.9"));
    }
    let response = match state
        .http
        .request(parts.method, url)
        .headers(headers)
        .body(body)
        .send()
        .await
    {
        Ok(response) => response,
        Err(err) => return (StatusCode::BAD_GATEWAY, err.to_string()).into_response(),
    };
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.bytes().await.unwrap_or_default();
    let mut out = Response::new(Body::from(body));
    *out.status_mut() = status;
    for (name, value) in &headers {
        if name != "content-length" && name != "transfer-encoding" {
            out.headers_mut().insert(name.clone(), value.clone());
        }
    }
    out
}

pub const ID_TOKEN: &str = "test-id-token";

#[derive(Default)]
struct MetadataState {
    audiences: Mutex<Vec<String>>,
}

/// A GCE metadata server that hands out [`ID_TOKEN`] for any audience. Point
/// services at it with `GCE_METADATA_HOST`.
pub struct Metadata {
    pub port: u16,
    state: Arc<MetadataState>,
}

impl Metadata {
    pub async fn start() -> anyhow::Result<Self> {
        let state = Arc::new(MetadataState::default());
        let router = axum::Router::new()
            .route(
                "/computeMetadata/v1/instance/service-accounts/default/identity",
                axum::routing::get(identity),
            )
            .with_state(Arc::clone(&state));
        Ok(Self {
            port: serve(router).await?,
            state,
        })
    }

    pub fn host(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    /// Audiences tokens were requested for.
    pub fn audiences(&self) -> Vec<String> {
        self.state.audiences.lock().clone()
    }
}

async fn identity(
    State(state): State<Arc<MetadataState>>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    if headers.get("metadata-flavor").and_then(|v| v.to_str().ok()) != Some("Google") {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(audience) = query.get("audience") else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    // Without `full`, a real token lacks the email claim the wallet checks.
    if query.get("format").map(String::as_str) != Some("full") {
        return StatusCode::BAD_REQUEST.into_response();
    }
    state.audiences.lock().push(audience.clone());
    ID_TOKEN.into_response()
}

/// Google's ID token issuer, for the api's scheduler check: serves a JWKS
/// with one RSA key (made with `openssl` per run, so no private key is
/// checked in) and signs tokens with it. Point the api at [`Self::jwks_url`]
/// with `API_SCHEDULER_JWKS_URL`.
pub struct GoogleIdTokens {
    port: u16,
    key: jsonwebtoken::EncodingKey,
}

const ID_TOKEN_KEY_ID: &str = "test-key";

impl GoogleIdTokens {
    pub async fn start(dir: &std::path::Path) -> anyhow::Result<Self> {
        let pem = dir.join("id-token-key.pem");
        let openssl = |args: &[&str]| -> anyhow::Result<Vec<u8>> {
            let output = std::process::Command::new("openssl").args(args).output()?;
            anyhow::ensure!(output.status.success(), "openssl {args:?} failed");
            Ok(output.stdout)
        };
        let pem_path = pem.to_str().context("non-UTF-8 path")?;
        openssl(&[
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
            pem_path,
        ])?;
        let modulus = String::from_utf8(openssl(&["rsa", "-in", pem_path, "-noout", "-modulus"])?)?;
        let modulus = hex::decode(
            modulus
                .trim()
                .strip_prefix("Modulus=")
                .context("unexpected openssl output")?,
        )?;
        let n = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(modulus);
        let jwks = serde_json::json!({"keys": [{
            "kty": "RSA", "alg": "RS256", "use": "sig", "kid": ID_TOKEN_KEY_ID,
            "n": n, "e": "AQAB",
        }]});
        let router = axum::Router::new().route(
            "/certs",
            axum::routing::get(move || {
                let jwks = jwks.to_string();
                async move {
                    (
                        [(axum::http::header::CONTENT_TYPE, "application/json")],
                        jwks,
                    )
                }
            }),
        );
        Ok(Self {
            port: serve(router).await?,
            key: jsonwebtoken::EncodingKey::from_rsa_pem(&std::fs::read(&pem)?)?,
        })
    }

    pub fn jwks_url(&self) -> String {
        format!("http://127.0.0.1:{}/certs", self.port)
    }

    /// A token for `audience` and `email`, expiring `ttl_secs` from now
    /// (negative: already expired).
    pub fn token(&self, audience: &str, email: &str, ttl_secs: i64) -> anyhow::Result<String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(ID_TOKEN_KEY_ID.to_owned());
        let claims = serde_json::json!({
            "iss": "https://accounts.google.com",
            "aud": audience,
            "email": email,
            "email_verified": true,
            "iat": now,
            "exp": now + ttl_secs,
            "sub": "1234567890",
        });
        Ok(jsonwebtoken::encode(&header, &claims, &self.key)?)
    }
}

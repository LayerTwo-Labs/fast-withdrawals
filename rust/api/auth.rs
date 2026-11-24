//! Who may call the internal service: holders of the operator token, and,
//! with the `gcp-auth` feature, the scheduler presenting a Google ID token.

use connectrpc::{ConnectError, RequestContext};
use sha2::{Digest as _, Sha256};

/// The scheduler's Google ID tokens: signed by Google for `email`, with
/// `audience` as their audience.
#[derive(Clone, Debug)]
#[cfg_attr(
    not(feature = "gcp-auth"),
    expect(dead_code, reason = "refused at startup without gcp-auth")
)]
pub struct SchedulerIdentity {
    pub audience: String,
    pub email: String,
    /// Where Google's signing keys are fetched; tests serve their own.
    pub jwks_url: Option<String>,
}

pub struct InternalAuth {
    token: Option<String>,
    #[cfg(feature = "gcp-auth")]
    scheduler: Option<google_cloud_auth::credentials::idtoken::verifier::Verifier>,
    #[cfg(feature = "gcp-auth")]
    verifying: tokio::sync::Mutex<()>,
}

impl InternalAuth {
    pub fn new(
        token: Option<String>,
        scheduler: Option<SchedulerIdentity>,
    ) -> anyhow::Result<Self> {
        if token
            .as_deref()
            .is_some_and(|token| token.trim().is_empty())
        {
            anyhow::bail!("the internal token must not be empty");
        }
        #[cfg(not(feature = "gcp-auth"))]
        if scheduler.is_some() {
            anyhow::bail!("scheduler ID tokens need the gcp-auth feature");
        }
        Ok(Self {
            token,
            #[cfg(feature = "gcp-auth")]
            scheduler: scheduler.map(|identity| {
                let builder = google_cloud_auth::credentials::idtoken::verifier::Builder::new([
                    identity.audience,
                ])
                .with_email(identity.email);
                match identity.jwks_url {
                    Some(url) => builder.with_jwks_url(url),
                    None => builder,
                }
                .build()
            }),
            #[cfg(feature = "gcp-auth")]
            verifying: tokio::sync::Mutex::new(()),
        })
    }

    /// Admits the request if it carries the operator token or a valid
    /// scheduler ID token, as `Authorization: Bearer`.
    pub async fn authorize(&self, ctx: &RequestContext) -> Result<(), ConnectError> {
        let presented = ctx
            .headers()
            .get(http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .filter(|token| !token.is_empty())
            .ok_or_else(|| ConnectError::unauthenticated("credentials required"))?;
        // Comparing digests keeps the comparison's timing from leaking the
        // token.
        if let Some(token) = &self.token
            && Sha256::digest(presented) == Sha256::digest(token)
        {
            return Ok(());
        }
        // Only for requests that didn't come through the load balancer: the
        // scheduler calls the service directly, and verifying a token with an
        // unknown key fetches Google's keys under a lock other checks fail on,
        // which anyone on the internet could otherwise keep busy.
        #[cfg(feature = "gcp-auth")]
        if let Some(verifier) = &self.scheduler
            && !ctx.headers().contains_key(crate::server::CLIENT_IP_HEADER)
            && is_rs256(presented)
        {
            // One at a time: the verifier's key cache refuses concurrent use.
            let _serialized = self.verifying.lock().await;
            match verifier.verify(presented).await {
                Ok(_) => return Ok(()),
                Err(err) => tracing::warn!("scheduler ID token rejected: {err}"),
            }
        }
        Err(ConnectError::unauthenticated("invalid credentials"))
    }
}

/// Google signs ID tokens with RS256. Checked before verifying, so the
/// token's own header can't pick another algorithm.
#[cfg(feature = "gcp-auth")]
fn is_rs256(token: &str) -> bool {
    use base64::Engine as _;
    let Some(header) = token.split('.').next() else {
        return false;
    };
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(header)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .is_some_and(|header| header["alg"] == "RS256")
}

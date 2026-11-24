use std::net::SocketAddr;

/// Where the quote signing key lives.
#[derive(Clone, Debug, clap::Args)]
#[group(required = true, multiple = false)]
pub struct KeyConfig {
    /// Google Cloud KMS key version (`projects/.../cryptoKeyVersions/N`) of an
    /// `EC_SIGN_ED25519` key.
    #[cfg(feature = "gcp-kms")]
    #[arg(long, env = "API_KMS_KEY_VERSION")]
    pub kms_key_version: Option<String>,
    /// Hex Ed25519 secret key. Development and tests only.
    #[arg(long, env = "API_LOCAL_KEY")]
    pub local_key: Option<String>,
}

#[derive(Clone, Debug, clap::Parser)]
#[command(name = "fastwithdraw-api", about = "Fast withdrawal API")]
pub struct Config {
    #[arg(long, env = "LISTEN", default_value = "127.0.0.1:8080")]
    pub listen: SocketAddr,
    /// Postgres URL. On Cloud Run, the Cloud SQL Auth Proxy sidecar with
    /// automatic IAM login, so no password.
    #[arg(long, env = "DATABASE_URL")]
    pub database_url: String,
    /// L1 network, for validating payout addresses; ECX mainnet is `bitcoin`.
    #[arg(long, env = "API_NETWORK", default_value = "bitcoin")]
    pub network: bitcoin::Network,
    /// Thunder public JSON-RPC.
    #[arg(long, env = "THUNDER_URL")]
    pub thunder_url: String,
    /// Account xpub of the cold Thunder key (see `thunder-xpub`).
    #[arg(long, env = "THUNDER_XPUB")]
    pub thunder_xpub: fastwithdraw_thunder::Xpub,
    /// L2 confirmations a payment needs before it is paid out. The wallet
    /// must require no more.
    #[arg(long, env = "THUNDER_CONFIRMATIONS", default_value_t = 2)]
    pub thunder_confirmations: u32,
    /// How many recent Thunder blocks to search when locating a payment.
    #[arg(long, env = "THUNDER_SCAN_DEPTH", default_value_t = 100)]
    pub thunder_scan_depth: u32,
    /// Base URL of the wallet service.
    #[arg(long, env = "WALLET_URL")]
    pub wallet_url: String,
    /// Authenticate to the wallet with Google ID tokens (Cloud Run).
    #[arg(long, env = "WALLET_ID_TOKEN_AUTH", default_value_t = false)]
    pub wallet_id_token_auth: bool,
    /// Lets the operator (and a scheduler without ID tokens) call the internal
    /// service, eg. `Tick`, or `ListPaidIndexes` for sweeping, with
    /// `Authorization: Bearer <token>`.
    #[arg(long, env = "API_INTERNAL_TOKEN", hide_env_values = true)]
    pub internal_token: Option<String>,
    /// With `API_SCHEDULER_EMAIL`, the internal service also admits Google ID
    /// tokens for this audience (Cloud Scheduler's OIDC tokens). Needs the
    /// `gcp-auth` feature.
    #[arg(long, env = "API_SCHEDULER_AUDIENCE")]
    pub scheduler_audience: Option<String>,
    /// The service account those ID tokens must be for.
    #[arg(long, env = "API_SCHEDULER_EMAIL")]
    pub scheduler_email: Option<String>,
    /// Where to fetch Google's ID token signing keys. Tests only.
    #[arg(long, env = "API_SCHEDULER_JWKS_URL", hide = true)]
    pub scheduler_jwks_url: Option<String>,
    #[command(flatten)]
    pub key: KeyConfig,
    #[arg(long, env = "FEE_BPS", default_value_t = 100)]
    pub fee_bps: u32,
    #[arg(long, env = "MIN_PAYOUT_SATS", default_value_t = 10_000)]
    pub min_payout_sats: u64,
    #[arg(long, env = "MAX_PAYOUT_SATS", default_value_t = 10_000_000)]
    pub max_payout_sats: u64,
    #[arg(long, env = "MAX_EXPOSURE_BPS", default_value_t = 2_500)]
    pub max_exposure_bps: u32,
    #[arg(long, env = "MINER_FEE_RESERVE_SATS", default_value_t = 100_000)]
    pub miner_fee_reserve_sats: u64,
    #[arg(long, env = "QUOTE_TTL_SECS", default_value_t = 900)]
    pub quote_ttl_secs: i64,
    /// Open quotes one client (IPv4 address or IPv6 /64) may have at once.
    #[arg(long, env = "MAX_OPEN_QUOTES_PER_CLIENT", default_value_t = 5)]
    pub max_open_quotes_per_client: u64,
    /// Quotes watched for payments at once; new quotes are refused beyond it.
    /// Every tick checks each watched address.
    #[arg(long, env = "MAX_WATCHED_QUOTES", default_value_t = 100_000)]
    pub max_watched_quotes: u64,
    /// Requests per second per client IP, and burst.
    #[arg(long, env = "RATE_LIMIT", default_value_t = 5.0)]
    pub rate_limit: f64,
    #[arg(long, env = "RATE_BURST", default_value_t = 20.0)]
    pub rate_burst: f64,
}

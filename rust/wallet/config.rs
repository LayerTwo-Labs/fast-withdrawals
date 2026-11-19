use std::net::SocketAddr;

use bdk_wallet::bitcoin::Network;

/// Where the payout key lives.
#[derive(Clone, Debug, clap::Args)]
#[group(required = true, multiple = false)]
pub struct KeyConfig {
    /// Google Cloud KMS key version (`projects/.../cryptoKeyVersions/N`) of an
    /// `EC_SIGN_SECP256K1_SHA256` HSM key.
    #[cfg(feature = "gcp-kms")]
    #[arg(long, env = "WALLET_KMS_KEY_VERSION")]
    pub kms_key_version: Option<String>,
    /// PKCS#11 signer config written by `fastwithdraw-pkcs11 init`. The token
    /// PIN is read from `PKCS11_PIN`.
    #[arg(long, env = "WALLET_PKCS11_CONFIG")]
    pub pkcs11_config: Option<std::path::PathBuf>,
    /// Hex secp256k1 secret key. Development and tests only.
    #[arg(long, env = "WALLET_LOCAL_KEY")]
    pub local_key: Option<String>,
}

#[derive(Clone, Debug, clap::Parser)]
#[command(name = "fastwithdraw-wallet", about = "L1 payout wallet")]
pub struct Config {
    #[arg(long, env = "LISTEN", default_value = "127.0.0.1:8081")]
    pub listen: SocketAddr,
    /// Postgres URL. On Cloud Run, the Cloud SQL Auth Proxy sidecar with
    /// automatic IAM login, so no password.
    #[arg(long, env = "DATABASE_URL")]
    pub database_url: String,
    /// L1 network; ECX mainnet uses `bitcoin`.
    #[arg(long, env = "WALLET_NETWORK", default_value = "bitcoin")]
    pub network: Network,
    #[arg(long, env = "ESPLORA_URL")]
    pub esplora_url: String,
    /// Thunder public JSON-RPC.
    #[arg(long, env = "THUNDER_URL")]
    pub thunder_url: String,
    /// Account xpub of the cold Thunder key (see `thunder-xpub`).
    #[arg(long, env = "THUNDER_XPUB")]
    pub thunder_xpub: fastwithdraw_thunder::Xpub,
    /// L2 confirmations a payment needs before it is paid out.
    #[arg(long, env = "THUNDER_CONFIRMATIONS", default_value_t = 2,
          value_parser = clap::value_parser!(u32).range(1..))]
    pub thunder_confirmations: u32,
    /// How many recent Thunder blocks to search for a payment whose block the
    /// caller didn't name.
    #[arg(long, env = "THUNDER_SCAN_DEPTH", default_value_t = 100)]
    pub thunder_scan_depth: u32,
    /// Refuse payouts while Thunder's L2 tip was BMM'd more than this many
    /// L1 blocks ago: Thunder may have stopped following L1.
    #[arg(long, env = "THUNDER_MAX_L1_LAG", default_value_t = 6)]
    pub thunder_max_l1_lag: u32,
    #[command(flatten)]
    pub key: KeyConfig,
    #[arg(long, env = "MAX_PAYOUT_SATS", default_value_t = 10_000_000)]
    pub max_payout_sats: u64,
    #[arg(long, env = "DAILY_CAP_SATS", default_value_t = 100_000_000)]
    pub daily_cap_sats: u64,
    #[arg(long, env = "MAX_FEE_SATS", default_value_t = 100_000)]
    pub max_fee_sats: u64,
    /// What a fee bump may spend on miner fees beyond the customer's fee
    /// (L2 payment less payout). Never more than `MAX_FEE_SATS` in all.
    #[arg(long, env = "FEE_BUMP_SUBSIDY_SATS", default_value_t = 0)]
    pub fee_bump_subsidy_sats: u64,
    /// Minimum service fee in basis points; quotes registered by the api must
    /// charge at least this. Keep it at or below the api's `FEE_BPS`.
    #[arg(long, env = "MIN_FEE_BPS", default_value_t = 100,
          value_parser = clap::value_parser!(u32).range(0..=10_000))]
    pub min_fee_bps: u32,
    #[arg(long, env = "FEE_TARGET_BLOCKS", default_value_t = 6)]
    pub fee_target_blocks: u16,
    /// Used when Esplora has no estimate, and as a floor.
    #[arg(long, env = "FALLBACK_FEE_SAT_PER_VB", default_value_t = 2)]
    pub fallback_fee_sat_per_vb: u64,
    /// Unconfirmed blocks after which a payout is replaced at a higher fee.
    #[arg(long, env = "FEE_BUMP_AFTER_BLOCKS", default_value_t = 3,
          value_parser = clap::value_parser!(u32).range(1..))]
    pub fee_bump_after_blocks: u32,
    /// The api's service account. With `WALLET_SCHEDULER_EMAIL`, only the api
    /// may call the wallet, and the scheduler only `Tick`; requests from
    /// anyone else are refused. Needs Cloud Run IAM (or a proxy) in front
    /// that verifies ID tokens: the wallet reads the caller from the token
    /// without checking it.
    #[arg(long, env = "WALLET_API_EMAIL", requires = "scheduler_email")]
    pub api_email: Option<String>,
    /// The scheduler's service account. See `WALLET_API_EMAIL`.
    #[arg(long, env = "WALLET_SCHEDULER_EMAIL", requires = "api_email")]
    pub scheduler_email: Option<String>,
}

//! A regtest stack: drivechain-patched bitcoind, electrs (Esplora API), the
//! enforcer, a Thunder node acting as the customer's wallet, Postgres, and
//! the api and wallet services under test.

use std::{path::PathBuf, time::Duration};

use anyhow::{Context as _, anyhow, bail};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use connectrpc::client::{CallOptions, ClientConfig, HttpClient};
use fastwithdraw_proto::{
    internal_connect::InternalServiceClient, v1_connect::FastWithdrawalServiceClient,
    wallet_connect::WalletServiceClient,
};
use fastwithdraw_thunder::{Xpriv, Xpub};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::{
    enforcer::Enforcer,
    util::{BinPaths, Process, TestContext, reserve_port, run, wait_for},
};

/// Where the wallet's payout key lives.
#[derive(Clone, Copy, Debug)]
pub enum PayoutKey {
    Local,
    /// A key generated on a SoftHSM token by `fastwithdraw-pkcs11 init`.
    SoftHsm,
}

const SOFTHSM_PIN: &str = "1234";

/// Initializes a SoftHSM token under `dir` and generates the payout key on
/// it. Returns the wallet's env vars and its public key.
async fn softhsm_key(
    bins: &BinPaths,
    dir: &std::path::Path,
) -> anyhow::Result<(Vec<(&'static str, String)>, bitcoin::CompressedPublicKey)> {
    let hsm_dir = dir.join("softhsm");
    std::fs::create_dir_all(hsm_dir.join("tokens"))?;
    let conf = hsm_dir.join("softhsm2.conf");
    std::fs::write(
        &conf,
        format!(
            "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\n",
            hsm_dir.join("tokens").display()
        ),
    )?;
    let envs = vec![
        ("SOFTHSM2_CONF", conf.display().to_string()),
        ("PKCS11_PIN", SOFTHSM_PIN.to_owned()),
    ];
    run(
        &bins.softhsm2_util,
        &envs,
        &[
            "--init-token",
            "--free",
            "--label",
            "fastwithdraw",
            "--pin",
            SOFTHSM_PIN,
            "--so-pin",
            "5678",
        ],
    )
    .await?;
    let config = hsm_dir.join("signer.toml");
    let module = bins.softhsm2_module.display().to_string();
    let config_arg = config.display().to_string();
    run(
        &bins.pkcs11_tool,
        &envs,
        &[
            "init",
            "--module",
            &module,
            "--token-label",
            "fastwithdraw",
            "--out",
            &config_arg,
            "--network",
            "regtest",
        ],
    )
    .await?;
    let check = run(
        &bins.pkcs11_tool,
        &envs,
        &["check", "--config", &config_arg, "--network", "regtest"],
    )
    .await?;
    if !check.contains("ok:") {
        bail!("fastwithdraw-pkcs11 check: {check}");
    }
    let text = std::fs::read_to_string(&config)?;
    let public_key = text
        .lines()
        .find_map(|line| line.strip_prefix("public_key = "))
        .context("config has no public_key")?
        .trim_matches('"');
    let public_key = bitcoin::CompressedPublicKey::from_slice(&hex::decode(public_key)?)?;
    let mut wallet_env = envs;
    wallet_env.push(("WALLET_PKCS11_CONFIG", config_arg));
    Ok((wallet_env, public_key))
}

/// Cold Thunder mnemonic of the service under test.
pub const SERVICE_MNEMONIC: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";
/// Required Thunder confirmations configured for the services.
pub const CONFIRMATIONS: u32 = 2;

const RPC_USER: &str = "user";
const RPC_PASS: &str = "pass";

/// JSON-RPC 2.0 over HTTP, for the third-party nodes (bitcoind, Thunder).
#[derive(Clone)]
pub struct JsonRpc {
    url: String,
    http: reqwest::Client,
    basic_auth: bool,
}

impl JsonRpc {
    fn new(url: String, basic_auth: bool) -> Self {
        Self {
            url,
            http: reqwest::Client::new(),
            basic_auth,
        }
    }

    pub async fn call<T: DeserializeOwned>(
        &self,
        method: &str,
        params: Value,
    ) -> anyhow::Result<T> {
        let mut request = self
            .http
            .post(&self.url)
            .json(&json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}));
        if self.basic_auth {
            request = request.basic_auth(RPC_USER, Some(RPC_PASS));
        }
        let response: Value = request
            .send()
            .await
            .with_context(|| method.to_owned())?
            .json()
            .await
            .with_context(|| format!("{method} response"))?;
        if let Some(err) = response.get("error").filter(|err| !err.is_null()) {
            bail!("{method}: {err}");
        }
        serde_json::from_value(response.get("result").cloned().unwrap_or(Value::Null))
            .with_context(|| format!("{method} result"))
    }
}

pub type ApiClient = FastWithdrawalServiceClient<HttpClient>;
pub type InternalClient = InternalServiceClient<HttpClient>;
pub type WalletClient = WalletServiceClient<HttpClient>;

/// The L1 side: bitcoind, electrs and the enforcer, with Thunder's slot
/// active and the enforcer wallet funded for deposits and BMM.
pub struct Mainchain {
    pub bitcoind: JsonRpc,
    pub enforcer: Enforcer,
    pub enforcer_address: String,
    pub esplora_url: String,
    pub enforcer_grpc_port: u16,
    // Dropped last: kills the processes.
    processes: Vec<Process>,
}

impl Mainchain {
    pub async fn start(
        context: &TestContext,
        bins: &BinPaths,
        dir: &std::path::Path,
    ) -> anyhow::Result<Self> {
        let mut processes = Vec::new();

        let rpc_port = reserve_port()?;
        let zmq_port = reserve_port()?;
        let bitcoind_dir = dir.join("bitcoind");
        std::fs::create_dir_all(&bitcoind_dir)?;
        processes.push(Process::spawn(
            context,
            "bitcoind",
            &bitcoind_dir,
            &bins.bitcoind,
            &[],
            [
                "-regtest".to_owned(),
                format!("-datadir={}", bitcoind_dir.display()),
                "-listen=0".to_owned(),
                "-server".to_owned(),
                "-txindex".to_owned(),
                "-rest".to_owned(),
                "-fallbackfee=0.0001".to_owned(),
                format!("-rpcport={rpc_port}"),
                format!("-rpcuser={RPC_USER}"),
                format!("-rpcpassword={RPC_PASS}"),
                format!("-zmqpubsequence=tcp://127.0.0.1:{zmq_port}"),
            ],
        )?);
        let node = JsonRpc::new(format!("http://127.0.0.1:{rpc_port}"), true);
        wait_for("bitcoind RPC", Duration::from_secs(60), || async {
            node.call::<Value>("getblockchaininfo", json!([])).await
        })
        .await?;
        node.call::<Value>("createwallet", json!(["w"])).await?;
        let bitcoind = JsonRpc::new(format!("http://127.0.0.1:{rpc_port}/wallet/w"), true);
        let address: String = bitcoind.call("getnewaddress", json!([])).await?;
        bitcoind
            .call::<Value>("generatetoaddress", json!([101, address]))
            .await?;

        let electrum_port = reserve_port()?;
        let http_port = reserve_port()?;
        let electrs_dir = dir.join("electrs");
        processes.push(Process::spawn(
            context,
            "electrs",
            &electrs_dir,
            &bins.electrs,
            &[],
            [
                "-vv".to_owned(),
                format!("--db-dir={}", electrs_dir.display()),
                format!("--daemon-dir={}", bitcoind_dir.display()),
                format!("--daemon-rpc-addr=127.0.0.1:{rpc_port}"),
                format!("--electrum-rpc-addr=127.0.0.1:{electrum_port}"),
                format!("--http-addr=127.0.0.1:{http_port}"),
                format!("--monitoring-addr=127.0.0.1:{}", reserve_port()?),
                "--network=regtest".to_owned(),
                format!("--cookie={RPC_USER}:{RPC_PASS}"),
                "--jsonrpc-import".to_owned(),
            ],
        )?);
        let esplora_url = format!("http://127.0.0.1:{http_port}");
        wait_for("electrs", Duration::from_secs(120), || async {
            let height: u32 = reqwest::get(format!("{esplora_url}/blocks/tip/height"))
                .await?
                .text()
                .await?
                .trim()
                .parse()?;
            if height < 101 {
                bail!("electrs at height {height}");
            }
            Ok(())
        })
        .await?;

        let enforcer_grpc_port = reserve_port()?;
        let enforcer_dir = dir.join("enforcer");
        processes.push(Process::spawn(
            context,
            "enforcer",
            &enforcer_dir,
            &bins.enforcer,
            &[],
            [
                format!("--data-dir={}", enforcer_dir.display()),
                "--log-level=info".to_owned(),
                format!("--node-rpc-addr=127.0.0.1:{rpc_port}"),
                format!("--node-rpc-user={RPC_USER}"),
                format!("--node-rpc-pass={RPC_PASS}"),
                format!("--node-zmq-addr-sequence=tcp://127.0.0.1:{zmq_port}"),
                "--enable-wallet".to_owned(),
                "--wallet-auto-create".to_owned(),
                "--wallet-skip-periodic-sync".to_owned(),
                "--wallet-electrum-host=127.0.0.1".to_owned(),
                format!("--wallet-electrum-port={electrum_port}"),
                format!("--wallet-esplora-url={esplora_url}"),
                "--enable-mempool".to_owned(),
                "--enable-block-template-server".to_owned(),
                format!("--serve-grpc-addr=127.0.0.1:{enforcer_grpc_port}"),
                format!("--serve-rpc-addr=127.0.0.1:{}", reserve_port()?),
            ],
        )?);
        let enforcer = Enforcer::new(enforcer_grpc_port)?;
        let enforcer_address = wait_for("enforcer wallet", Duration::from_secs(120), || async {
            enforcer.new_address().await
        })
        .await?;
        let mainchain = Self {
            bitcoind,
            enforcer,
            enforcer_address,
            esplora_url,
            enforcer_grpc_port,
            processes,
        };
        mainchain.activate_thunder().await?;
        mainchain.fund_enforcer().await?;
        Ok(mainchain)
    }

    pub fn check_running(&self) -> anyhow::Result<()> {
        self.processes.iter().try_for_each(Process::check_running)
    }

    /// Waits for the enforcer and electrs to process bitcoind's tip.
    pub async fn synced(&self) -> anyhow::Result<()> {
        let best: String = self.bitcoind.call("getbestblockhash", json!([])).await?;
        wait_for(
            "enforcer to reach the tip",
            Duration::from_secs(60),
            || async {
                let tip = self.enforcer.tip().await?;
                if tip != best {
                    bail!("enforcer at {tip}, bitcoind at {best}");
                }
                Ok(())
            },
        )
        .await?;
        // The wallet reads the chain through electrs.
        wait_for(
            "electrs to reach the tip",
            Duration::from_secs(60),
            || async {
                let tip = reqwest::get(format!("{}/blocks/tip/hash", self.esplora_url))
                    .await?
                    .text()
                    .await?;
                if tip.trim() != best {
                    bail!("electrs at {tip}, bitcoind at {best}");
                }
                Ok(())
            },
        )
        .await
    }

    /// Mines through the enforcer, so its block template includes BMM requests.
    pub async fn mine(&self, blocks: u32) -> anyhow::Result<()> {
        for _ in 0..blocks {
            self.synced().await?;
            // The block template server can lag the validator under load.
            wait_for("a block template", Duration::from_secs(30), || async {
                self.enforcer
                    .generate_to_address(&self.enforcer_address)
                    .await
            })
            .await?;
        }
        self.synced().await
    }

    /// Mines a block with no transactions, straight through bitcoind.
    pub async fn mine_empty(&self) -> anyhow::Result<()> {
        self.synced().await?;
        let _block: Value = self
            .bitcoind
            .call("generateblock", json!([self.enforcer_address, []]))
            .await?;
        self.synced().await
    }

    async fn activate_thunder(&self) -> anyhow::Result<()> {
        self.enforcer.propose_thunder().await?;
        wait_for("sidechain proposal", Duration::from_secs(60), || async {
            if self.enforcer.pending_proposals().await? == 0 {
                bail!("no pending proposal");
            }
            Ok(())
        })
        .await?;
        self.mine(7).await?;
        if self.enforcer.active_sidechains().await? != 1 {
            bail!("Thunder's slot did not activate");
        }
        Ok(())
    }

    async fn fund_enforcer(&self) -> anyhow::Result<()> {
        self.bitcoind
            .call::<Value>("generatetoaddress", json!([101, self.enforcer_address]))
            .await?;
        self.synced().await?;
        wait_for(
            "enforcer wallet funds",
            Duration::from_secs(120),
            || async {
                if self.enforcer.confirmed_balance().await? == 0 {
                    bail!("no confirmed balance");
                }
                Ok(())
            },
        )
        .await
    }
}

/// A Thunder node with a fresh wallet: the customer's L2 wallet, and the
/// node the services observe.
pub struct Thunder {
    pub rpc: JsonRpc,
    pub rpc_url: String,
    /// P2P address, for `connect_peer`.
    pub net_addr: String,
    process: Process,
}

impl Thunder {
    pub async fn start(
        context: &TestContext,
        bins: &BinPaths,
        dir: &std::path::Path,
        mainchain: &Mainchain,
        mnemonic: Option<&str>,
    ) -> anyhow::Result<Self> {
        Self::start_named(context, bins, dir, mainchain, mnemonic, "thunder").await
    }

    pub async fn start_named(
        context: &TestContext,
        bins: &BinPaths,
        dir: &std::path::Path,
        mainchain: &Mainchain,
        mnemonic: Option<&str>,
        name: &str,
    ) -> anyhow::Result<Self> {
        let rpc_port = reserve_port()?;
        let net_addr = format!("127.0.0.1:{}", reserve_port()?);
        let thunder_dir = dir.join(name);
        let process = Process::spawn(
            context,
            name,
            &thunder_dir,
            &bins.thunder,
            &[],
            [
                format!("--datadir={}", thunder_dir.display()),
                "--headless".to_owned(),
                "--network=regtest".to_owned(),
                "--log-level=info".to_owned(),
                format!(
                    "--mainchain-grpc-url=http://127.0.0.1:{}",
                    mainchain.enforcer_grpc_port
                ),
                format!("--net-addr={net_addr}"),
                format!("--rpc-addr=127.0.0.1:{rpc_port}"),
                format!("--private-rpc-addr=127.0.0.1:{rpc_port}"),
            ],
        )?;
        let rpc_url = format!("http://127.0.0.1:{rpc_port}");
        let rpc = JsonRpc::new(rpc_url.clone(), false);
        wait_for("Thunder RPC", Duration::from_secs(60), || async {
            process.check_running()?;
            rpc.call::<u32>("getblockcount", json!([])).await
        })
        .await?;
        let mnemonic = match mnemonic {
            Some(mnemonic) => mnemonic.to_owned(),
            None => rpc.call("generate_mnemonic", json!([])).await?,
        };
        rpc.call::<Value>("set_seed_from_mnemonic", json!([mnemonic]))
            .await?;
        Ok(Self {
            rpc,
            rpc_url,
            net_addr,
            process,
        })
    }

    pub fn check_running(&self) -> anyhow::Result<()> {
        self.process.check_running()
    }

    pub async fn tip(&self) -> anyhow::Result<String> {
        self.rpc
            .call("get_best_sidechain_block_hash", json!([]))
            .await
    }

    pub async fn block_count(&self) -> anyhow::Result<u32> {
        self.rpc.call("getblockcount", json!([])).await
    }

    /// Blind-merge-mines one Thunder block: `mine` broadcasts a BMM request
    /// and returns once a mainchain block includes it. A node that hasn't
    /// processed that mainchain block yet rejects the new tip ("not ready to
    /// reorg"), so retry a few times.
    pub async fn bmm(&self, mainchain: &Mainchain) -> anyhow::Result<()> {
        let before = self.block_count().await?;
        for _ in 0..3 {
            self.bmm_attempt(mainchain).await?;
            if self.block_count().await? == before + 1 {
                return Ok(());
            }
        }
        bail!("BMM did not advance Thunder past {before} blocks")
    }

    async fn bmm_attempt(&self, mainchain: &Mainchain) -> anyhow::Result<()> {
        let mempool_before: Vec<String> =
            mainchain.bitcoind.call("getrawmempool", json!([])).await?;
        let rpc = self.rpc.clone();
        let mine = tokio::spawn(async move { rpc.call::<Value>("mine", json!([null])).await });
        wait_for(
            "BMM request in the mempool",
            Duration::from_secs(60),
            || async {
                let mempool: Vec<String> =
                    mainchain.bitcoind.call("getrawmempool", json!([])).await?;
                if mempool.len() <= mempool_before.len() {
                    bail!("no BMM request yet");
                }
                Ok(())
            },
        )
        .await?;
        mainchain.mine(1).await?;
        mine.await??;
        Ok(())
    }

    /// Deposits L1 coins from the enforcer wallet to a new address of this
    /// wallet and waits until they are spendable.
    pub async fn fund(&self, mainchain: &Mainchain, sats: u64) -> anyhow::Result<()> {
        let address: String = self.rpc.call("get_new_address", json!([])).await?;
        let txid = mainchain.enforcer.deposit(&address, sats).await?;
        wait_for(
            "deposit in the mempool",
            Duration::from_secs(60),
            || async {
                mainchain
                    .bitcoind
                    .call::<Value>("getmempoolentry", json!([txid]))
                    .await
            },
        )
        .await?;
        mainchain.mine(1).await?;
        for _ in 0..3 {
            self.bmm(mainchain).await?;
            let balance: Value = self.rpc.call("balance", json!([])).await?;
            if balance["available_sats"].as_u64().unwrap_or_default() >= sats {
                return Ok(());
            }
        }
        Err(anyhow!("Thunder wallet never received the deposit"))
    }
}

/// Embedded Postgres with the `api` and `wallet` databases.
pub struct Postgres {
    pub api_url: String,
    pub wallet_url: String,
    _server: postgresql_embedded::PostgreSQL,
}

impl Postgres {
    pub async fn start(dir: &std::path::Path) -> anyhow::Result<Self> {
        let settings = postgresql_embedded::Settings {
            port: reserve_port()?,
            data_dir: dir.join("postgres"),
            password_file: dir.join("postgres.pw"),
            temporary: true,
            ..Default::default()
        };
        let mut server = postgresql_embedded::PostgreSQL::new(settings);
        server.setup().await.context("postgres setup")?;
        server.start().await.context("postgres start")?;
        server.create_database("api").await?;
        server.create_database("wallet").await?;
        Ok(Self {
            api_url: server.settings().url("api"),
            wallet_url: server.settings().url("wallet"),
            _server: server,
        })
    }
}

/// How to run the services under test. Env overrides apply on top of the
/// defaults.
pub struct ServiceOptions {
    pub payout_key: PayoutKey,
    pub thunder_url: String,
    pub esplora_url: String,
    pub api_env: Vec<(&'static str, String)>,
    pub wallet_env: Vec<(&'static str, String)>,
    /// Routes api→wallet traffic through this URL, eg. a recording proxy.
    pub wallet_url: Option<String>,
}

impl ServiceOptions {
    pub fn new(mainchain: &Mainchain, thunder: &Thunder) -> Self {
        Self::detached(thunder.rpc_url.clone(), mainchain.esplora_url.clone())
    }

    /// Services pointed at arbitrary upstreams, for tests that don't need a
    /// chain.
    pub fn detached(thunder_url: String, esplora_url: String) -> Self {
        Self {
            payout_key: PayoutKey::Local,
            thunder_url,
            esplora_url,
            api_env: Vec::new(),
            wallet_env: Vec::new(),
            wallet_url: None,
        }
    }
}

/// The api's internal token in tests.
pub const INTERNAL_TOKEN: &str = "test-internal-token";

/// Call options carrying `Authorization: Bearer <token>`.
pub fn bearer(token: &str) -> CallOptions {
    CallOptions::default().with_header(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_str(&format!("Bearer {token}")).expect("valid header"),
    )
}

/// The api and wallet services under test, with Connect clients.
pub struct Services {
    pub api: ApiClient,
    pub internal: InternalClient,
    pub wallet: WalletClient,
    pub api_port: u16,
    pub wallet_port: u16,
    /// The wallet's single L1 address.
    pub wallet_address: bitcoin::Address,
    pub quote_key: ed25519_dalek::VerifyingKey,
    pub xpub: Xpub,
    wallet_env: Vec<(&'static str, String)>,
    processes: Vec<Process>,
    pub postgres: Postgres,
}

fn connect_config(port: u16) -> anyhow::Result<ClientConfig> {
    Ok(ClientConfig::new(
        format!("http://127.0.0.1:{port}").parse()?,
    ))
}

async fn wait_healthy(process: &Process, port: u16) -> anyhow::Result<()> {
    wait_for("service health", Duration::from_secs(60), || async {
        process.check_running()?;
        reqwest::get(format!("http://127.0.0.1:{port}/healthz"))
            .await?
            .error_for_status()?;
        Ok(())
    })
    .await
}

pub fn api_client(port: u16) -> anyhow::Result<ApiClient> {
    Ok(FastWithdrawalServiceClient::new(
        HttpClient::plaintext(),
        connect_config(port)?,
    ))
}

pub fn wallet_client(port: u16) -> anyhow::Result<WalletClient> {
    Ok(WalletServiceClient::new(
        HttpClient::plaintext(),
        connect_config(port)?,
    ))
}

impl Services {
    pub async fn start(
        context: &TestContext,
        bins: &BinPaths,
        dir: &std::path::Path,
        options: ServiceOptions,
    ) -> anyhow::Result<Self> {
        let postgres = Postgres::start(dir).await?;
        let xpub = Xpriv::from_mnemonic(SERVICE_MNEMONIC)?.account().xpub();
        let (key_env, public_key) = match options.payout_key {
            PayoutKey::Local => {
                let secret = SecretKey::from_slice(&[0x11; 32])?;
                (
                    vec![("WALLET_LOCAL_KEY", hex::encode(secret.secret_bytes()))],
                    bitcoin::CompressedPublicKey(secret.public_key(&Secp256k1::new())),
                )
            }
            PayoutKey::SoftHsm => softhsm_key(bins, dir).await?,
        };
        let wallet_address = bitcoin::Address::p2wpkh(&public_key, bitcoin::Network::Regtest);
        let quote_secret = [0x22; 32];
        let quote_key = ed25519_dalek::SigningKey::from_bytes(&quote_secret).verifying_key();
        let common = vec![
            ("THUNDER_URL", options.thunder_url.clone()),
            ("THUNDER_XPUB", xpub.to_string()),
            ("THUNDER_CONFIRMATIONS", CONFIRMATIONS.to_string()),
            (
                "RUST_LOG",
                "info,fastwithdraw_api=debug,fastwithdraw_wallet=debug".to_owned(),
            ),
        ];

        let mut wallet_env = common.clone();
        wallet_env.extend([
            ("DATABASE_URL", postgres.wallet_url.clone()),
            ("WALLET_NETWORK", "regtest".to_owned()),
            ("ESPLORA_URL", options.esplora_url.clone()),
        ]);
        wallet_env.extend(key_env);
        // Tests mine L1 blocks without BMM'ing L2 ones; `thunder_stale`
        // lowers this.
        wallet_env.push(("THUNDER_MAX_L1_LAG", "1000".to_owned()));
        wallet_env.extend(options.wallet_env);
        let (wallet_process, wallet_port) =
            spawn_wallet(context, bins, &dir.join("wallet"), &wallet_env).await?;

        let api_port = reserve_port()?;
        let mut api_env = common;
        api_env.extend([
            ("LISTEN", format!("127.0.0.1:{api_port}")),
            ("DATABASE_URL", postgres.api_url.clone()),
            ("API_NETWORK", "regtest".to_owned()),
            (
                "WALLET_URL",
                options
                    .wallet_url
                    .unwrap_or_else(|| format!("http://127.0.0.1:{wallet_port}")),
            ),
            ("API_LOCAL_KEY", hex::encode(quote_secret)),
            ("API_INTERNAL_TOKEN", INTERNAL_TOKEN.to_owned()),
            // Tests quote freely from one address.
            ("MAX_OPEN_QUOTES_PER_CLIENT", "1000".to_owned()),
        ]);
        api_env.extend(options.api_env);
        let api_process = Process::spawn(
            context,
            "api",
            &dir.join("api"),
            &bins.api,
            &api_env,
            Vec::<String>::new(),
        )?;
        wait_healthy(&api_process, api_port).await?;

        Ok(Self {
            api: api_client(api_port)?,
            internal: InternalServiceClient::new(
                HttpClient::plaintext(),
                connect_config(api_port)?,
            ),
            wallet: wallet_client(wallet_port)?,
            api_port,
            wallet_port,
            wallet_address,
            quote_key,
            xpub,
            wallet_env,
            processes: vec![wallet_process, api_process],
            postgres,
        })
    }

    /// Starts another wallet instance on the same database.
    pub async fn spawn_wallet(
        &mut self,
        context: &TestContext,
        bins: &BinPaths,
        dir: &std::path::Path,
        name: &str,
    ) -> anyhow::Result<WalletClient> {
        let (process, port) =
            spawn_wallet(context, bins, &dir.join(name), &self.wallet_env).await?;
        self.processes.push(process);
        wallet_client(port)
    }

    pub fn check_running(&self) -> anyhow::Result<()> {
        self.processes.iter().try_for_each(Process::check_running)
    }
}

async fn spawn_wallet(
    context: &TestContext,
    bins: &BinPaths,
    dir: &std::path::Path,
    env: &[(&'static str, String)],
) -> anyhow::Result<(Process, u16)> {
    let port = reserve_port()?;
    let mut env = env.to_vec();
    env.push(("LISTEN", format!("127.0.0.1:{port}")));
    let name = dir.file_name().map_or_else(
        || "wallet".to_owned(),
        |name| name.to_string_lossy().into_owned(),
    );
    let process = Process::spawn(
        context,
        &name,
        dir,
        &bins.wallet,
        &env,
        Vec::<String>::new(),
    )?;
    wait_healthy(&process, port).await?;
    Ok((process, port))
}

/// A per-test directory, removed if the test passes.
pub fn test_dir(name: &str) -> anyhow::Result<PathBuf> {
    let dir = crate::util::test_root().join(format!("{name}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

//! Sweeps customer payments from the cold Thunder key's receive addresses to
//! a treasury address. Neither service holds that key, so the payments pile
//! up until an operator sweeps them, in three steps:
//!
//! - `plan` (online): finds the unspent payments to withdrawals the wallet
//!   has paid out, and writes an unsigned transaction.
//! - `sign` (offline): checks the plan against the mnemonic and the expected
//!   destination, and signs it. No networking.
//! - `submit` (online): sends the signed transaction to Thunder.

use std::{
    collections::{BTreeSet, HashMap},
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context as _, bail, ensure};
use clap::Parser;
use connectrpc::client::{CallOptions, ClientConfig, HttpClient};
use fastwithdraw_proto::{
    internal::ListPaidIndexesRequest, internal_connect::InternalServiceClient,
};
use fastwithdraw_thunder::{Xpriv, Xpub, rpc};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thunder_types::{
    Address, AuthorizedTransaction, GetValue as _, Output, OutputContent, PointedOutput,
    Transaction,
    authorization::{self, SigningKey},
    hash,
};

#[derive(Parser)]
#[expect(clippy::large_enum_variant, reason = "parsed once")]
#[command(
    name = "thunder-sweep",
    about = "Sweep Thunder payments to a treasury address"
)]
enum Command {
    /// Build an unsigned sweep transaction (online)
    Plan {
        #[arg(long, env = "THUNDER_URL")]
        thunder_url: String,
        /// Account xpub of the cold Thunder key
        #[arg(long, env = "THUNDER_XPUB")]
        thunder_xpub: Xpub,
        /// The api, asked for withdrawals the wallet has paid out. Deliberately
        /// not read from the environment: a refund (`--index` alone) must
        /// never pick up every paid index by accident.
        #[arg(long)]
        api_url: Option<String>,
        /// The api's internal token. Pass it in the environment, not on the
        /// command line, where other users can see it.
        #[arg(long, env = "API_INTERNAL_TOKEN", hide_env_values = true)]
        api_token: Option<String>,
        /// Also sweep these receive indexes, eg. payments that matched no
        /// quote. Decide on refunds first.
        #[arg(long = "index")]
        indexes: Vec<u32>,
        /// Thunder treasury address
        #[arg(long)]
        destination: Address,
        #[arg(long)]
        fee_sats: u64,
        /// Spend at most this many outputs; run again for the rest
        #[arg(long, default_value_t = 500)]
        max_inputs: usize,
        #[arg(long)]
        out: PathBuf,
    },
    /// Check and sign a plan with the mnemonic read from stdin (offline)
    Sign {
        #[arg(long)]
        plan: PathBuf,
        /// The treasury address the plan must pay
        #[arg(long)]
        destination: Address,
        #[arg(long)]
        max_fee_sats: u64,
        #[arg(long)]
        out: PathBuf,
    },
    /// Submit a signed sweep (online)
    Submit {
        #[arg(long, env = "THUNDER_URL")]
        thunder_url: String,
        #[arg(long)]
        signed: PathBuf,
    },
}

/// An unsigned sweep. The inputs' Utreexo proof is left empty: Thunder
/// regenerates it on submit, and it isn't signed.
#[derive(Deserialize, Serialize)]
struct Plan {
    transaction: Transaction,
    /// The receive index and output spent by each input, in order
    inputs: Vec<PlanInput>,
}

#[derive(Deserialize, Serialize)]
struct PlanInput {
    l2_index: u32,
    output: Output,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Command::parse() {
        Command::Plan {
            thunder_url,
            thunder_xpub,
            api_url,
            api_token,
            indexes,
            destination,
            fee_sats,
            max_inputs,
            out,
        } => {
            let mut indexes: BTreeSet<u32> = indexes.into_iter().collect();
            if let Some(url) = api_url {
                indexes.extend(paid_indexes(&url, api_token.as_deref()).await?);
            }
            let thunder = rpc::Client::new(&thunder_url, 1);
            let plan = plan(
                &thunder,
                &thunder_xpub,
                &indexes,
                destination,
                fee_sats,
                max_inputs,
            )
            .await?;
            write_new(&out, &plan)?;
            report(&format!(
                "planned: {} inputs, {} sats to {destination}, fee {fee_sats} sats\n{}wrote {}",
                plan.inputs.len(),
                plan.transaction.outputs.as_slice()[0].get_value().to_sat(),
                swept_indexes(&plan.inputs),
                out.display()
            ))
        }
        Command::Sign {
            plan,
            destination,
            max_fee_sats,
            out,
        } => {
            let plan: Plan = read(&plan)?;
            let mut mnemonic = zeroize::Zeroizing::new(String::new());
            std::io::stdin().read_to_string(&mut mnemonic)?;
            let account = Xpriv::from_mnemonic(mnemonic.trim())?.account();
            let (signed, summary) = sign(&account, plan, destination, max_fee_sats)?;
            write_new(&out, &signed)?;
            report(&format!("{summary}\nwrote {}", out.display()))
        }
        Command::Submit {
            thunder_url,
            signed,
        } => {
            let signed: AuthorizedTransaction = read(&signed)?;
            let thunder = rpc::Client::new(&thunder_url, 1);
            let txid = thunder
                .submit_transaction(serde_json::to_value(&signed)?)
                .await?;
            writeln!(std::io::stdout().lock(), "{txid}")?;
            Ok(())
        }
    }
}

/// Receive indexes of withdrawals the wallet has paid out. Payments to others
/// are still needed: the wallet checks them before paying.
async fn paid_indexes(api_url: &str, token: Option<&str>) -> anyhow::Result<Vec<u32>> {
    let uri: http::Uri = api_url.parse().context("--api-url")?;
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
    let client = InternalServiceClient::new(
        transport,
        ClientConfig::new(uri.clone()).with_default_timeout(Duration::from_secs(60)),
    );
    let mut options = CallOptions::default();
    if let Some(token) = token {
        let loopback = matches!(uri.host(), Some("localhost" | "127.0.0.1" | "[::1]"));
        ensure!(
            uri.scheme_str() == Some("https") || loopback,
            "refusing to send the token over plain HTTP; use an https --api-url"
        );
        let value = http::HeaderValue::from_str(&format!("Bearer {token}"))
            .context("invalid --api-token")?;
        options = options.with_header(http::header::AUTHORIZATION, value);
    }
    let response = client
        .list_paid_indexes_with_options(ListPaidIndexesRequest::default(), options)
        .await
        .context("list paid indexes")?;
    Ok(response.into_owned().l2_indexes)
}

async fn plan(
    thunder: &rpc::Client,
    xpub: &Xpub,
    indexes: &BTreeSet<u32>,
    destination: Address,
    fee_sats: u64,
    max_inputs: usize,
) -> anyhow::Result<Plan> {
    ensure!(
        !indexes.is_empty(),
        "nothing to sweep: no paid withdrawals or --index"
    );
    let mut by_address = HashMap::new();
    for &index in indexes {
        by_address.insert(xpub.address(index)?.0, index);
    }
    let addresses: Vec<_> = by_address
        .keys()
        .map(|bytes| fastwithdraw_thunder::Address(*bytes))
        .collect();
    let mut utxos: Vec<PointedOutput> = thunder
        .raw_utxos(&addresses)
        .await?
        .into_iter()
        .map(serde_json::from_value)
        .collect::<Result<_, _>>()
        .context("decode Thunder UTXOs")?;
    // Only plain values; withdrawal outputs are locked until their bundle
    // resolves.
    utxos.retain(|utxo| matches!(utxo.output.content, OutputContent::Value(_)));
    utxos.sort_by_key(|utxo| std::cmp::Reverse(utxo.output.get_value()));
    utxos.truncate(max_inputs);
    ensure!(!utxos.is_empty(), "no unspent payments at those addresses");

    let total: u64 = utxos
        .iter()
        .map(|utxo| utxo.output.get_value().to_sat())
        .sum();
    let Some(swept) = total.checked_sub(fee_sats).filter(|&sats| sats > 0) else {
        bail!("{total} sats doesn't cover the {fee_sats} sats fee");
    };
    let mut inputs = Vec::with_capacity(utxos.len());
    let mut plan_inputs = Vec::with_capacity(utxos.len());
    for utxo in utxos {
        let l2_index = *by_address
            .get(&utxo.output.address.0)
            .context("Thunder returned an output to an address that wasn't asked for")?;
        inputs.push((utxo.outpoint, hash(&utxo)));
        plan_inputs.push(PlanInput {
            l2_index,
            output: utxo.output,
        });
    }
    let output = Output {
        address: destination,
        content: OutputContent::Value(bitcoin::Amount::from_sat(swept)),
    };
    Ok(Plan {
        transaction: Transaction {
            inputs: inputs.into(),
            proof: Default::default(),
            outputs: vec![output].into(),
        },
        inputs: plan_inputs,
    })
}

/// Signs `plan` after checking that every input is ours and the transaction
/// pays only `destination`, with at most `max_fee_sats` left as fee.
fn sign(
    account: &Xpriv,
    plan: Plan,
    destination: Address,
    max_fee_sats: u64,
) -> anyhow::Result<(AuthorizedTransaction, String)> {
    let Plan {
        transaction,
        inputs,
    } = plan;
    ensure!(
        transaction.inputs.len() == inputs.len(),
        "plan lists {} inputs for {} transaction inputs",
        inputs.len(),
        transaction.inputs.len()
    );
    let xpub = account.xpub();
    let mut total: u64 = 0;
    let mut keys = Vec::with_capacity(inputs.len());
    for ((outpoint, utxo_hash), input) in transaction.inputs.iter().zip(&inputs) {
        // The input commits to the spent output, so this pins its address
        // and value.
        let pointed = PointedOutput {
            outpoint: *outpoint,
            output: input.output.clone(),
        };
        ensure!(
            hash(&pointed) == *utxo_hash,
            "input {outpoint} doesn't match its listed output"
        );
        ensure!(
            xpub.address(input.l2_index)?.0 == input.output.address.0,
            "input {outpoint} isn't paid to receive index {}",
            input.l2_index
        );
        let OutputContent::Value(value) = input.output.content else {
            bail!("input {outpoint} isn't a plain value");
        };
        total = total
            .checked_add(value.to_sat())
            .context("input total overflows")?;
        let secret = account.child_secret(input.l2_index)?;
        let key = SigningKey::deserialize(&secret.to_bytes())
            .map_err(|err| anyhow::anyhow!("signing key: {err}"))?;
        keys.push((input.output.address, key));
    }
    let [output] = transaction.outputs.as_slice() else {
        bail!("plan must have exactly one output");
    };
    ensure!(
        output.address == destination,
        "plan pays {}, not {destination}",
        output.address
    );
    let OutputContent::Value(swept) = output.content else {
        bail!("plan's output isn't a plain value");
    };
    let fee = total
        .checked_sub(swept.to_sat())
        .context("plan spends more than its inputs")?;
    ensure!(
        fee <= max_fee_sats,
        "plan's fee of {fee} sats exceeds --max-fee-sats"
    );

    let keys: Vec<_> = keys.iter().map(|(address, key)| (*address, key)).collect();
    let signed = authorization::authorize(rand::rng(), &keys, transaction)
        .map_err(|err| anyhow::anyhow!("sign: {err}"))?;
    let summary = format!(
        "signed {}: {} inputs, {} sats to {destination}, fee {fee} sats\n{}",
        signed.transaction.txid(),
        inputs.len(),
        swept.to_sat(),
        swept_indexes(&inputs).trim_end()
    );
    Ok((signed, summary))
}

fn read<T: DeserializeOwned>(path: &Path) -> anyhow::Result<T> {
    let file = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    serde_json::from_reader(file).with_context(|| format!("parse {}", path.display()))
}

/// Writes `value` to a new file; never overwrites.
fn write_new<T: Serialize>(path: &Path, value: &T) -> anyhow::Result<()> {
    let file =
        std::fs::File::create_new(path).with_context(|| format!("create {}", path.display()))?;
    serde_json::to_writer_pretty(file, value)?;
    Ok(())
}

/// The receive indexes a sweep spends and their amounts, one per line: check
/// them before signing. A refund should list only the refunded index.
fn swept_indexes(inputs: &[PlanInput]) -> String {
    let mut by_index = std::collections::BTreeMap::<u32, u64>::new();
    for input in inputs {
        *by_index.entry(input.l2_index).or_default() += input.output.get_value().to_sat();
    }
    by_index
        .iter()
        .map(|(index, sats)| format!("  index {index}: {sats} sats\n"))
        .collect()
}

fn report(message: &str) -> anyhow::Result<()> {
    writeln!(std::io::stderr().lock(), "{message}")?;
    Ok(())
}

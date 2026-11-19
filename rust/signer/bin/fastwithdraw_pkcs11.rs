//! Operator tool for the PKCS#11 payout signer. See `docs/pkcs11.md`.
//!
//!     PKCS11_PIN=... fastwithdraw-pkcs11 init --module M --token-label T --out signer.toml
//!     PKCS11_PIN=... fastwithdraw-pkcs11 check --config signer.toml --network bitcoin

use std::{io::Write as _, path::PathBuf};

use anyhow::Context as _;
use clap::Parser as _;
use fastwithdraw_signer::{
    TxSigner as _,
    pkcs11::{self, Pkcs11TxSigner},
};

#[derive(clap::Parser)]
#[command(
    name = "fastwithdraw-pkcs11",
    about = "Set up the PKCS#11 payout signer"
)]
enum Command {
    /// Generates a non-extractable secp256k1 key on the token and writes the
    /// wallet's signer config.
    Init {
        /// Vendor PKCS#11 module, eg. /usr/lib/softhsm/libsofthsm2.so.
        #[arg(long)]
        module: PathBuf,
        #[arg(long)]
        token_label: String,
        #[arg(long, default_value = "fastwithdraw-payout")]
        key_label: String,
        /// Where to write the config. Refuses to overwrite.
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value = "bitcoin")]
        network: bitcoin::Network,
    },
    /// Loads a config, signs a test digest, and prints the payout address.
    Check {
        #[arg(long)]
        config: PathBuf,
        #[arg(long, default_value = "bitcoin")]
        network: bitcoin::Network,
    },
}

fn pin() -> anyhow::Result<String> {
    std::env::var("PKCS11_PIN").context("set the token's user PIN in PKCS11_PIN")
}

fn address(
    public_key: bitcoin::CompressedPublicKey,
    network: bitcoin::Network,
) -> bitcoin::Address {
    bitcoin::Address::p2wpkh(&public_key, network)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut out = std::io::stdout().lock();
    match Command::parse() {
        Command::Init {
            module,
            token_label,
            key_label,
            out: path,
            network,
        } => {
            // Claim the file before touching the token, so a bad path fails
            // before a key exists that nothing records.
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .with_context(|| format!("create {} (refusing to overwrite)", path.display()))?;
            let config = pkcs11::generate(&module, &token_label, &key_label, &pin()?)?;
            writeln!(
                out,
                "generated {key_label:?}, public key {}",
                config.public_key
            )?;
            file.write_all(config.to_toml().as_bytes())?;
            file.sync_all()?;
            writeln!(out, "wrote {}", path.display())?;
            // Proves the new key signs before anyone funds it.
            let signer = Pkcs11TxSigner::open(&config, &pin()?)?;
            signer.sign_digest([0x42; 32]).await?;
            writeln!(
                out,
                "payout address ({network}): {}",
                address(signer.public_key(), network)
            )?;
        }
        Command::Check { config, network } => {
            let config = pkcs11::Config::load(&config)?;
            let signer = Pkcs11TxSigner::open(&config, &pin()?)?;
            signer.sign_digest([0x42; 32]).await?;
            writeln!(out, "ok: token key matches config and signs")?;
            writeln!(
                out,
                "payout address ({network}): {}",
                address(signer.public_key(), network)
            )?;
        }
    }
    Ok(())
}

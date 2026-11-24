//! Signing keys for payouts (secp256k1 ECDSA) and quotes (Ed25519).
//!
//! Production keys live in Google Cloud KMS (the `gcp-kms` feature) or, for
//! payouts, a PKCS#11 HSM; local keys are for development and tests. Every
//! implementation verifies its own signature before returning it, so a faulty
//! backend can't produce an invalid payout or quote.

#[cfg(feature = "gcp-kms")]
mod kms;
pub mod pkcs11;

use async_trait::async_trait;
use bitcoin::secp256k1::{self, Message, Secp256k1, ecdsa};
use ed25519_dalek::{Signer as _, Verifier as _};
use thiserror::Error;

#[cfg(feature = "gcp-kms")]
pub use kms::{KmsQuoteSigner, KmsTxSigner};
pub use pkcs11::Pkcs11TxSigner;

#[derive(Debug, Error)]
pub enum Error {
    #[error("KMS: {0}")]
    Kms(String),
    #[error("PKCS#11: {0}")]
    Pkcs11(String),
    #[error("signer returned an invalid signature")]
    InvalidSignature,
    #[error("signer returned an unexpected public key: {0}")]
    PublicKey(String),
}

/// Signs P2WPKH sighashes for L1 payouts.
#[async_trait]
pub trait TxSigner: Send + Sync {
    fn public_key(&self) -> bitcoin::CompressedPublicKey;

    /// A low-S signature over a 32-byte sighash, verified against
    /// [`Self::public_key`].
    async fn sign_digest(&self, digest: [u8; 32]) -> Result<ecdsa::Signature, Error>;
}

/// Signs withdrawal quotes.
#[async_trait]
pub trait QuoteSigner: Send + Sync {
    fn public_key(&self) -> ed25519_dalek::VerifyingKey;

    async fn sign(&self, message: &[u8]) -> Result<ed25519_dalek::Signature, Error>;
}

/// Normalizes `signature` to low-S and checks it against `public_key`.
fn checked_ecdsa(
    mut signature: ecdsa::Signature,
    digest: [u8; 32],
    public_key: &secp256k1::PublicKey,
) -> Result<ecdsa::Signature, Error> {
    signature.normalize_s();
    Secp256k1::verification_only()
        .verify_ecdsa(&Message::from_digest(digest), &signature, public_key)
        .map_err(|_| Error::InvalidSignature)?;
    Ok(signature)
}

fn checked_ed25519(
    signature: ed25519_dalek::Signature,
    message: &[u8],
    public_key: &ed25519_dalek::VerifyingKey,
) -> Result<ed25519_dalek::Signature, Error> {
    public_key
        .verify(message, &signature)
        .map_err(|_| Error::InvalidSignature)?;
    Ok(signature)
}

/// A secp256k1 key held in memory.
pub struct LocalTxSigner {
    secret: secp256k1::SecretKey,
    public: bitcoin::CompressedPublicKey,
}

impl LocalTxSigner {
    pub fn new(secret: secp256k1::SecretKey) -> Self {
        let public = secret.public_key(&Secp256k1::signing_only());
        Self {
            secret,
            public: bitcoin::CompressedPublicKey(public),
        }
    }
}

#[async_trait]
impl TxSigner for LocalTxSigner {
    fn public_key(&self) -> bitcoin::CompressedPublicKey {
        self.public
    }

    async fn sign_digest(&self, digest: [u8; 32]) -> Result<ecdsa::Signature, Error> {
        let signature =
            Secp256k1::signing_only().sign_ecdsa(&Message::from_digest(digest), &self.secret);
        checked_ecdsa(signature, digest, &self.public.0)
    }
}

/// An Ed25519 key held in memory.
pub struct LocalQuoteSigner(ed25519_dalek::SigningKey);

impl LocalQuoteSigner {
    pub fn new(secret: [u8; 32]) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(&secret))
    }
}

#[async_trait]
impl QuoteSigner for LocalQuoteSigner {
    fn public_key(&self) -> ed25519_dalek::VerifyingKey {
        self.0.verifying_key()
    }

    async fn sign(&self, message: &[u8]) -> Result<ed25519_dalek::Signature, Error> {
        checked_ed25519(self.0.sign(message), message, &self.0.verifying_key())
    }
}

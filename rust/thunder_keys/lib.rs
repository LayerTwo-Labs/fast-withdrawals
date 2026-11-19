//! Thunder's BIP32-style key derivation over ristretto255, as implemented by
//! thunder-rust v0.18.1 (`lib/wallet/bip32.rs` with the `bip32ish` crate).
//!
//! Receive keys live at `m/43'/1899'/0'/9'/0'/i`. The last step is
//! non-hardened, so the account [`Xpub`] derives every receive address without
//! any private key.

use std::{fmt, str::FromStr};

use curve25519_dalek::{
    RistrettoPoint, Scalar, ristretto::CompressedRistretto, traits::Identity as _,
};
use hmac::{Hmac, Mac};
use sha2::{Digest as _, Sha256, Sha512};
use thiserror::Error;
use zeroize::{Zeroize as _, Zeroizing};

/// Thunder's sidechain slot.
const SIDECHAIN: u32 = 9;
const HARDENED: u32 = 1 << 31;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid mnemonic: {0}")]
    Mnemonic(#[from] bip39::Error),
    #[error("invalid xpub: {0}")]
    Xpub(&'static str),
    #[error("index {0} is hardened")]
    HardenedIndex(u32),
}

/// A 20-byte Thunder address, displayed as base58 without checksum.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Address(pub [u8; 20]);

impl Address {
    fn from_pubkey(pubkey: &RistrettoPoint) -> Self {
        let mut hasher = blake3::Hasher::new();
        let mut reader = hasher.update(pubkey.compress().as_bytes()).finalize_xof();
        let mut out = [0u8; 20];
        reader.fill(&mut out);
        Self(out)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&bs58::encode(self.0).into_string())
    }
}

impl FromStr for Address {
    type Err = bs58::decode::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut out = [0u8; 20];
        let n = bs58::decode(s).onto(&mut out)?;
        if n != 20 {
            return Err(bs58::decode::Error::BufferTooSmall);
        }
        Ok(Self(out))
    }
}

/// Clears the top 3 bits of big-endian bytes and reduces mod ℓ.
fn scalar_from_uniform_be(mut bytes: [u8; 32]) -> Scalar {
    bytes[0] &= 0b0001_1111;
    bytes.reverse();
    Scalar::from_bytes_mod_order(bytes)
}

fn hmac_sha512(key: &[u8], parts: &[&[u8]]) -> ([u8; 32], [u8; 32]) {
    let mut mac = Hmac::<Sha512>::new_from_slice(key).expect("HMAC accepts any key length");
    for part in parts {
        mac.update(part);
    }
    let digest = mac.finalize().into_bytes();
    let mut left = [0u8; 32];
    let mut right = [0u8; 32];
    left.copy_from_slice(&digest[..32]);
    right.copy_from_slice(&digest[32..]);
    (left, right)
}

/// An extended private key. Only for offline tools and tests. Wiped from
/// memory when dropped.
#[derive(Clone)]
pub struct Xpriv {
    secret: Scalar,
    chaincode: [u8; 32],
}

impl Drop for Xpriv {
    fn drop(&mut self) {
        self.secret.zeroize();
        self.chaincode.zeroize();
    }
}

impl Xpriv {
    pub fn from_seed(seed: &[u8]) -> Self {
        let (secret, chaincode) = hmac_sha512(b"Bitcoin seed", &[seed]);
        let secret = Zeroizing::new(secret);
        Self {
            secret: scalar_from_uniform_be(*secret),
            chaincode,
        }
    }

    /// The master key for a BIP39 mnemonic with an empty passphrase.
    pub fn from_mnemonic(phrase: &str) -> Result<Self, Error> {
        let mnemonic = bip39::Mnemonic::parse(phrase)?;
        Ok(Self::from_seed(
            Zeroizing::new(mnemonic.to_seed("")).as_slice(),
        ))
    }

    fn derive_hardened(&self, index: u32) -> Self {
        let child = (index | HARDENED).to_be_bytes();
        let (tweak, chaincode) =
            hmac_sha512(&self.chaincode, &[&[0x00], self.secret.as_bytes(), &child]);
        Self {
            secret: self.secret + scalar_from_uniform_be(tweak),
            chaincode,
        }
    }

    /// The account key at `m/43'/1899'/0'/9'/0'`.
    pub fn account(&self) -> Self {
        [43, 1899, 0, SIDECHAIN, 0]
            .into_iter()
            .fold(self.clone(), |key, index| key.derive_hardened(index))
    }

    pub fn xpub(&self) -> Xpub {
        Xpub {
            pubkey: RistrettoPoint::mul_base(&self.secret),
            chaincode: self.chaincode,
        }
    }

    /// The signing scalar for receive index `index` of this account key.
    pub fn child_secret(&self, index: u32) -> Result<Scalar, Error> {
        let pubkey = RistrettoPoint::mul_base(&self.secret);
        Ok(self.secret + Xpub::tweak(&pubkey, &self.chaincode, index)?.0)
    }
}

/// An extended public key: the account key's public point and chain code.
///
/// Serialized like a BIP32 xpub: Base58Check of `version, chain code,
/// compressed point`, with BIP32's 4-byte double SHA-256 checksum, so a
/// mistyped xpub is rejected instead of silently deriving addresses nobody
/// can spend from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Xpub {
    pubkey: RistrettoPoint,
    chaincode: [u8; 32],
}

impl Xpub {
    fn tweak(
        pubkey: &RistrettoPoint,
        chaincode: &[u8; 32],
        index: u32,
    ) -> Result<(Scalar, [u8; 32]), Error> {
        if index & HARDENED != 0 {
            return Err(Error::HardenedIndex(index));
        }
        let (tweak, chaincode) = hmac_sha512(
            chaincode,
            &[pubkey.compress().as_bytes(), &index.to_be_bytes()],
        );
        Ok((scalar_from_uniform_be(tweak), chaincode))
    }

    /// The receive address at non-hardened `index`.
    pub fn address(&self, index: u32) -> Result<Address, Error> {
        let (tweak, _) = Self::tweak(&self.pubkey, &self.chaincode, index)?;
        Ok(Address::from_pubkey(
            &(self.pubkey + RistrettoPoint::mul_base(&tweak)),
        ))
    }
}

/// Marks a serialized Thunder account xpub, as BIP32's version bytes mark
/// Bitcoin's. ASCII "thxp".
const XPUB_VERSION: [u8; 4] = *b"thxp";
const XPUB_LEN: usize = 4 + 32 + 32;

/// BIP32's (and Base58Check's) checksum: double SHA-256, first 4 bytes.
fn checksum(payload: &[u8]) -> [u8; 4] {
    let digest = Sha256::digest(Sha256::digest(payload));
    [digest[0], digest[1], digest[2], digest[3]]
}

impl fmt::Display for Xpub {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut bytes = Vec::with_capacity(XPUB_LEN + 4);
        bytes.extend_from_slice(&XPUB_VERSION);
        bytes.extend_from_slice(&self.chaincode);
        bytes.extend_from_slice(self.pubkey.compress().as_bytes());
        bytes.extend_from_slice(&checksum(&bytes));
        f.write_str(&bs58::encode(bytes).into_string())
    }
}

impl FromStr for Xpub {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = bs58::decode(s)
            .into_vec()
            .map_err(|_| Error::Xpub("not base58"))?;
        let Some((payload, check)) = bytes.split_last_chunk::<4>() else {
            return Err(Error::Xpub("too short"));
        };
        if payload.len() != XPUB_LEN {
            return Err(Error::Xpub("wrong length"));
        }
        if checksum(payload) != *check {
            return Err(Error::Xpub("checksum mismatch: mistyped?"));
        }
        let (version, keys) = payload.split_at(4);
        if version != XPUB_VERSION {
            return Err(Error::Xpub("not a Thunder account xpub"));
        }
        let (chaincode, point) = keys.split_at(32);
        let pubkey = CompressedRistretto::from_slice(point)
            .map_err(|_| Error::Xpub("bad point length"))?
            .decompress()
            .ok_or(Error::Xpub("not a ristretto point"))?;
        // A placeholder all-zero xpub would make every child key public.
        if pubkey == RistrettoPoint::identity() {
            return Err(Error::Xpub("identity point"));
        }
        Ok(Self {
            pubkey,
            chaincode: chaincode.try_into().expect("32 bytes"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The public BIP39 test mnemonic. Its addresses match what Thunder's
    /// own wallet derives (checked live by the integration tests); these pin
    /// them against regressions.
    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const EXPECTED_XPUB: &str = "2if5DyfAoAGDvusYyWEdydrZKiFKUmWGU5LEqLV3gtbdv7tN72Dgz73NfVRTTzTaJzZuyt9T8oykmDLfKa9rkCUXfGfbzENDwju";
    const EXPECTED_ADDRESS_1: &str = "2n9MH4oiBFs4sRby3cC8VBaE71Zw";
    const EXPECTED_ADDRESS_500: &str = "E115Ufg18DCL9M6jhLsaqfwYje2";

    #[test]
    fn known_xpub_and_addresses() {
        let xpub = Xpriv::from_mnemonic(MNEMONIC).unwrap().account().xpub();
        assert_eq!(xpub.to_string(), EXPECTED_XPUB);
        assert_eq!(xpub.address(1).unwrap().to_string(), EXPECTED_ADDRESS_1);
        assert_eq!(xpub.address(500).unwrap().to_string(), EXPECTED_ADDRESS_500);
    }

    #[test]
    fn xpub_round_trips_and_rejects_typos() {
        let xpub = Xpriv::from_mnemonic(MNEMONIC).unwrap().account().xpub();
        let encoded = xpub.to_string();
        assert_eq!(encoded.parse::<Xpub>().unwrap(), xpub);
        for position in [0, encoded.len() / 2, encoded.len() - 1] {
            let mut typo: Vec<char> = encoded.chars().collect();
            typo[position] = if typo[position] == '2' { '3' } else { '2' };
            let typo: String = typo.into_iter().collect();
            assert!(typo.parse::<Xpub>().is_err(), "accepted {typo}");
        }
    }
}

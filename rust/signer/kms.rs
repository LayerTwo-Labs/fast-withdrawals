//! Cloud KMS signers. The payout key is `EC_SIGN_SECP256K1_SHA256` (HSM), the
//! quote key `EC_SIGN_ED25519`.

use async_trait::async_trait;
use bitcoin::secp256k1::{self, ecdsa};
use google_cloud_kms_v1::{client::KeyManagementService, model::Digest};

use crate::{Error, QuoteSigner, TxSigner, checked_ecdsa, checked_ed25519};

fn kms_error(err: impl std::fmt::Display) -> Error {
    Error::Kms(err.to_string())
}

fn crc32c(data: &[u8]) -> i64 {
    i64::from(crc32c::crc32c(data))
}

/// DER SubjectPublicKeyInfo headers: id-ecPublicKey with secp256k1, and
/// id-Ed25519. The key follows as the rest of the BIT STRING.
const SECP256K1_SPKI_PREFIX: &[u8] = &[
    0x30, 0x56, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b,
    0x81, 0x04, 0x00, 0x0a, 0x03, 0x42, 0x00,
];
const ED25519_SPKI_PREFIX: &[u8] = &[
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// Raw key bytes from a PEM SubjectPublicKeyInfo of the expected algorithm.
/// A key of another type or curve is rejected.
fn spki_key(pem: &str, prefix: &[u8]) -> Result<Vec<u8>, Error> {
    use bitcoin::base64::{Engine as _, engine::general_purpose::STANDARD};
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let der = STANDARD
        .decode(body)
        .map_err(|err| Error::PublicKey(err.to_string()))?;
    der.strip_prefix(prefix)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| Error::PublicKey("KMS key has the wrong algorithm".to_owned()))
}

async fn public_key_pem(client: &KeyManagementService, name: &str) -> Result<String, Error> {
    let key = client
        .get_public_key()
        .set_name(name)
        .send()
        .await
        .map_err(kms_error)?;
    Ok(key.pem)
}

async fn asymmetric_sign(
    client: &KeyManagementService,
    name: &str,
    request: impl FnOnce(
        google_cloud_kms_v1::builder::key_management_service::AsymmetricSign,
    ) -> google_cloud_kms_v1::builder::key_management_service::AsymmetricSign,
) -> Result<Vec<u8>, Error> {
    let response = request(client.asymmetric_sign().set_name(name))
        .send()
        .await
        .map_err(kms_error)?;
    if response.signature_crc32c != Some(crc32c(&response.signature)) {
        return Err(Error::Kms("signature failed CRC32C check".to_owned()));
    }
    Ok(response.signature.to_vec())
}

/// Signs sighashes with a KMS secp256k1 key version.
pub struct KmsTxSigner {
    client: KeyManagementService,
    key_version: String,
    public: bitcoin::CompressedPublicKey,
}

impl KmsTxSigner {
    /// `key_version` is a full `projects/.../cryptoKeyVersions/N` name.
    pub async fn new(client: KeyManagementService, key_version: String) -> Result<Self, Error> {
        let pem = public_key_pem(&client, &key_version).await?;
        let point = spki_key(&pem, SECP256K1_SPKI_PREFIX)?;
        let public = secp256k1::PublicKey::from_slice(&point)
            .map_err(|err| Error::PublicKey(err.to_string()))?;
        Ok(Self {
            client,
            key_version,
            public: bitcoin::CompressedPublicKey(public),
        })
    }
}

#[async_trait]
impl TxSigner for KmsTxSigner {
    fn public_key(&self) -> bitcoin::CompressedPublicKey {
        self.public
    }

    async fn sign_digest(&self, digest: [u8; 32]) -> Result<ecdsa::Signature, Error> {
        let der = asymmetric_sign(&self.client, &self.key_version, |request| {
            request
                .set_digest(Digest::new().set_sha256(bytes::Bytes::copy_from_slice(&digest)))
                .set_digest_crc32c(crc32c(&digest))
        })
        .await?;
        let signature = ecdsa::Signature::from_der(&der).map_err(|_| Error::InvalidSignature)?;
        checked_ecdsa(signature, digest, &self.public.0)
    }
}

/// Signs quotes with a KMS Ed25519 key version.
pub struct KmsQuoteSigner {
    client: KeyManagementService,
    key_version: String,
    public: ed25519_dalek::VerifyingKey,
}

impl KmsQuoteSigner {
    pub async fn new(client: KeyManagementService, key_version: String) -> Result<Self, Error> {
        let pem = public_key_pem(&client, &key_version).await?;
        let key: [u8; 32] = spki_key(&pem, ED25519_SPKI_PREFIX)?
            .try_into()
            .map_err(|_| Error::PublicKey("bad Ed25519 key length".to_owned()))?;
        let public = ed25519_dalek::VerifyingKey::from_bytes(&key)
            .map_err(|err| Error::PublicKey(err.to_string()))?;
        Ok(Self {
            client,
            key_version,
            public,
        })
    }
}

#[async_trait]
impl QuoteSigner for KmsQuoteSigner {
    fn public_key(&self) -> ed25519_dalek::VerifyingKey {
        self.public
    }

    async fn sign(&self, message: &[u8]) -> Result<ed25519_dalek::Signature, Error> {
        let raw = asymmetric_sign(&self.client, &self.key_version, |request| {
            request
                .set_data(bytes::Bytes::copy_from_slice(message))
                .set_data_crc32c(crc32c(message))
        })
        .await?;
        let signature =
            ed25519_dalek::Signature::from_slice(&raw).map_err(|_| Error::InvalidSignature)?;
        checked_ed25519(signature, message, &self.public)
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        base64::{Engine as _, engine::general_purpose::STANDARD},
        secp256k1::{Message, Secp256k1, SecretKey},
    };
    use ed25519_dalek::Signer as _;
    use google_cloud_gax::{options::RequestOptions, response::Response};
    use google_cloud_kms_v1::model::{
        AsymmetricSignRequest, AsymmetricSignResponse, GetPublicKeyRequest, PublicKey,
    };

    use super::*;

    const SECP256K1_SPKI_PREFIX: &str = "3056301006072a8648ce3d020106052b8104000a034200";
    const ED25519_SPKI_PREFIX: &str = "302a300506032b6570032100";

    fn pem(prefix: &str, key: &[u8]) -> String {
        let mut der = hex::decode(prefix).unwrap();
        der.extend_from_slice(key);
        format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            STANDARD.encode(der)
        )
    }

    /// `n - s` for a big-endian secp256k1 scalar: the high-S twin.
    fn negate_s(s: &[u8]) -> [u8; 32] {
        const N: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
            0xd0, 0x36, 0x41, 0x41,
        ];
        let mut out = [0u8; 32];
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let mut digit = i16::from(N[i]) - i16::from(s[i]) - borrow;
            borrow = i16::from(digit < 0);
            if digit < 0 {
                digit += 256;
            }
            out[i] = u8::try_from(digit).unwrap();
        }
        out
    }

    #[derive(Clone, Copy, Debug, Default)]
    enum Fault {
        #[default]
        None,
        /// Returns the high-S form of a valid signature.
        HighS,
        /// Returns a signature checksum that doesn't match.
        BadCrc,
        /// Signs with a different key than the published one.
        WrongKey,
    }

    /// A fake KMS holding one secp256k1 and one Ed25519 key.
    #[derive(Debug)]
    struct FakeKms {
        secp: SecretKey,
        ed: ed25519_dalek::SigningKey,
        fault: Fault,
    }

    impl FakeKms {
        fn new(fault: Fault) -> Self {
            Self {
                secp: SecretKey::from_slice(&[3; 32]).unwrap(),
                ed: ed25519_dalek::SigningKey::from_bytes(&[4; 32]),
                fault,
            }
        }

        fn signing_secp(&self) -> SecretKey {
            match self.fault {
                Fault::WrongKey => SecretKey::from_slice(&[5; 32]).unwrap(),
                _ => self.secp,
            }
        }
    }

    impl google_cloud_kms_v1::stub::KeyManagementService for FakeKms {
        async fn get_public_key(
            &self,
            req: GetPublicKeyRequest,
            _options: RequestOptions,
        ) -> google_cloud_kms_v1::Result<Response<PublicKey>> {
            let pem = if req.name.ends_with("secp") {
                pem(
                    SECP256K1_SPKI_PREFIX,
                    &self
                        .secp
                        .public_key(&Secp256k1::new())
                        .serialize_uncompressed(),
                )
            } else {
                pem(ED25519_SPKI_PREFIX, self.ed.verifying_key().as_bytes())
            };
            Ok(Response::from(PublicKey::new().set_pem(pem)))
        }

        async fn asymmetric_sign(
            &self,
            req: AsymmetricSignRequest,
            _options: RequestOptions,
        ) -> google_cloud_kms_v1::Result<Response<AsymmetricSignResponse>> {
            let signature: Vec<u8> = match req.digest.as_ref().and_then(|digest| digest.sha256()) {
                Some(digest) => {
                    assert_eq!(req.digest_crc32c, Some(crc32c(digest)));
                    let digest: [u8; 32] = digest.as_ref().try_into().unwrap();
                    let signature = Secp256k1::new()
                        .sign_ecdsa(&Message::from_digest(digest), &self.signing_secp());
                    let signature = match self.fault {
                        Fault::HighS => {
                            let compact = signature.serialize_compact();
                            let mut high = compact;
                            high[32..].copy_from_slice(&negate_s(&compact[32..]));
                            ecdsa::Signature::from_compact(&high).unwrap()
                        }
                        _ => signature,
                    };
                    signature.serialize_der().to_vec()
                }
                None => {
                    assert_eq!(req.data_crc32c, Some(crc32c(&req.data)));
                    self.ed.sign(&req.data).to_bytes().to_vec()
                }
            };
            let crc = match self.fault {
                Fault::BadCrc => crc32c(&signature) + 1,
                _ => crc32c(&signature),
            };
            Ok(Response::from(
                AsymmetricSignResponse::new()
                    .set_signature(bytes::Bytes::from(signature))
                    .set_signature_crc32c(crc),
            ))
        }
    }

    fn client(fault: Fault) -> KeyManagementService {
        KeyManagementService::from_stub(FakeKms::new(fault))
    }

    #[tokio::test]
    async fn tx_signer_signs_and_verifies() {
        let signer = KmsTxSigner::new(client(Fault::None), "keys/secp".to_owned())
            .await
            .unwrap();
        let expected = SecretKey::from_slice(&[3; 32])
            .unwrap()
            .public_key(&Secp256k1::new());
        assert_eq!(signer.public_key().0, expected);
        let signature = signer.sign_digest([6; 32]).await.unwrap();
        Secp256k1::new()
            .verify_ecdsa(&Message::from_digest([6; 32]), &signature, &expected)
            .unwrap();
    }

    #[tokio::test]
    async fn tx_signer_normalizes_high_s() {
        let signer = KmsTxSigner::new(client(Fault::HighS), "keys/secp".to_owned())
            .await
            .unwrap();
        let signature = signer.sign_digest([7; 32]).await.unwrap();
        let mut normalized = signature;
        normalized.normalize_s();
        assert_eq!(signature, normalized);
    }

    #[tokio::test]
    async fn tx_signer_rejects_bad_crc() {
        let signer = KmsTxSigner::new(client(Fault::BadCrc), "keys/secp".to_owned())
            .await
            .unwrap();
        assert!(matches!(
            signer.sign_digest([8; 32]).await,
            Err(Error::Kms(_))
        ));
    }

    #[tokio::test]
    async fn tx_signer_rejects_foreign_key() {
        let signer = KmsTxSigner::new(client(Fault::WrongKey), "keys/secp".to_owned())
            .await
            .unwrap();
        assert!(matches!(
            signer.sign_digest([9; 32]).await,
            Err(Error::InvalidSignature)
        ));
    }

    #[tokio::test]
    async fn quote_signer_signs_and_verifies() {
        let signer = KmsQuoteSigner::new(client(Fault::None), "keys/ed".to_owned())
            .await
            .unwrap();
        assert_eq!(
            signer.public_key(),
            ed25519_dalek::SigningKey::from_bytes(&[4; 32]).verifying_key()
        );
        signer.sign(b"quote").await.unwrap();
    }

    #[tokio::test]
    async fn quote_signer_rejects_bad_crc() {
        let signer = KmsQuoteSigner::new(client(Fault::BadCrc), "keys/ed".to_owned())
            .await
            .unwrap();
        assert!(matches!(signer.sign(b"quote").await, Err(Error::Kms(_))));
    }

    /// Against real Cloud KMS, with Application Default Credentials:
    ///
    ///     FASTWITHDRAW_KMS_TX_KEY=projects/.../cryptoKeyVersions/1 \
    ///     FASTWITHDRAW_KMS_QUOTE_KEY=projects/.../cryptoKeyVersions/1 \
    ///     cargo test -p fastwithdraw-signer -- --ignored
    #[tokio::test]
    #[ignore = "needs Cloud KMS keys and credentials"]
    async fn real_kms() {
        let client = KeyManagementService::builder().build().await.unwrap();
        let tx_key = std::env::var("FASTWITHDRAW_KMS_TX_KEY").expect("FASTWITHDRAW_KMS_TX_KEY");
        let signer = KmsTxSigner::new(client.clone(), tx_key).await.unwrap();
        for byte in 0..8 {
            signer.sign_digest([byte; 32]).await.unwrap();
        }
        let quote_key =
            std::env::var("FASTWITHDRAW_KMS_QUOTE_KEY").expect("FASTWITHDRAW_KMS_QUOTE_KEY");
        let signer = KmsQuoteSigner::new(client, quote_key).await.unwrap();
        signer.sign(b"fastwithdraw real KMS test").await.unwrap();
    }
}

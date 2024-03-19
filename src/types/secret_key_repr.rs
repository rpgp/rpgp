use std::fmt;

use num_bigint::BigUint;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey};

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::ecc_curve::ECCCurve;
use crate::crypto::hash::HashAlgorithm;
use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::{crypto::checksum, types::KeyParams};

use super::{KeyParamsGet, Mpi, RawDecryptor};

/// The version of the secret key that is actually exposed to users to do crypto operations.
#[allow(clippy::large_enum_variant)] // FIXME
#[derive(Debug, ZeroizeOnDrop)]
pub enum SecretKeyRepr {
    RSA(RsaPrivateKey),
    DSA(DSASecretKey),
    ECDSA(ECDSASecretKey),
    ECDH(ECDHSecretKey),
    EdDSA(EdDSASecretKey),
}

impl<T: RawDecryptor + KeyParamsGet + std::fmt::Debug> crate::types::PgpDecryptor for T {
    fn decrypt(
        &self,
        mpis: &[Mpi],
        fingerprint: &[u8],
    ) -> crate::errors::Result<(Vec<u8>, SymmetricKeyAlgorithm)> {
        let decrypted_key = match self.key_params() {
            KeyParams::Rsa => self.raw_decrypt(&mpis[0])?,
            KeyParams::Ecdh(oid, alg, hash) => {
                crate::crypto::ecdh::decrypt(self, mpis, &fingerprint, &oid, alg, hash)?
            }
        };

        let session_key_algorithm = SymmetricKeyAlgorithm::from(decrypted_key[0]);
        ensure!(
            session_key_algorithm != SymmetricKeyAlgorithm::Plaintext,
            "session key algorithm cannot be plaintext"
        );
        let alg = session_key_algorithm;
        debug!("alg: {:?}", alg);

        let (k, checksum) = match self.key_params() {
            KeyParams::Ecdh(_, _, _) => {
                let dec_len = decrypted_key.len();
                (
                    &decrypted_key[1..dec_len - 2],
                    &decrypted_key[dec_len - 2..],
                )
            }
            _ => {
                let key_size = session_key_algorithm.key_size();
                (
                    &decrypted_key[1..=key_size],
                    &decrypted_key[key_size + 1..key_size + 3],
                )
            }
        };

        let key = k.to_vec();
        checksum::simple(checksum, k)?;
        Ok((key, alg))
    }
}

impl KeyParamsGet for SecretKeyRepr {
    fn key_params(&self) -> KeyParams {
        match *self {
            SecretKeyRepr::RSA(_) => KeyParams::Rsa,
            SecretKeyRepr::ECDH(ref secret) => {
                KeyParams::Ecdh(secret.oid.clone(), secret.alg_sym, secret.hash)
            }
            _ => unimplemented!(),
        }
    }
}

impl RawDecryptor for SecretKeyRepr {
    fn raw_decrypt(&self, value: &[u8]) -> crate::errors::Result<Vec<u8>> {
        Ok(match self {
            SecretKeyRepr::RSA(ref priv_key) => priv_key.decrypt(Pkcs1v15Encrypt, value)?,
            SecretKeyRepr::DSA(_) => todo!(),
            SecretKeyRepr::ECDSA(_) => todo!(),
            SecretKeyRepr::ECDH(priv_key) => priv_key.raw_decrypt(value)?,
            SecretKeyRepr::EdDSA(_) => todo!(),
        })
    }
}

/// Secret key for ECDH with Curve25519, the only combination we currently support.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ECDHSecretKey {
    /// The secret point.
    pub secret: [u8; 32],
    pub hash: HashAlgorithm,
    pub oid: Vec<u8>,
    pub alg_sym: SymmetricKeyAlgorithm,
}

impl fmt::Debug for ECDHSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ECDHSecretKey")
            .field("secret", &"[..]")
            .field("hash", &self.hash)
            .field("oid", &hex::encode(&self.oid))
            .field("alg_sym", &self.alg_sym)
            .finish()
    }
}

/// Secret key for EdDSA with Curve25519, the only combination we currently support.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct EdDSASecretKey {
    /// The secret point.
    pub secret: [u8; 32],
    pub oid: Vec<u8>,
}

impl fmt::Debug for EdDSASecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EdDSASecretKey")
            .field("secret", &"[..]")
            .field("oid", &hex::encode(&self.oid))
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub enum ECDSASecretKey {
    P256(p256::SecretKey),
    P384(p384::SecretKey),
    P521(p521::SecretKey),
    Secp256k1(k256::SecretKey),
    Unsupported {
        /// The secret point.
        x: Mpi,
        #[zeroize(skip)]
        curve: ECCCurve,
    },
}

impl fmt::Debug for ECDSASecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ECDSASecretKey::P256(_) => write!(f, "ECDSASecretKey::P256([..])"),
            ECDSASecretKey::P384(_) => write!(f, "ECDSASecretKey::P384([..])"),
            ECDSASecretKey::P521(_) => write!(f, "ECDSASecretKey::P521([..])"),
            ECDSASecretKey::Secp256k1(_) => write!(f, "ECDSASecretKey::Secp256k1([..])"),
            ECDSASecretKey::Unsupported { curve, .. } => f
                .debug_struct("ECDSASecretKey::Unsupported")
                .field("x", &"[..]")
                .field("curve", &curve)
                .finish(),
        }
    }
}

impl ECDSASecretKey {
    pub(crate) fn secret_key_length(&self) -> Option<usize> {
        match self {
            ECDSASecretKey::P256 { .. } => Some(32),
            ECDSASecretKey::P384 { .. } => Some(48),
            ECDSASecretKey::P521 { .. } => Some(66),
            ECDSASecretKey::Secp256k1 { .. } => Some(32),
            ECDSASecretKey::Unsupported { .. } => None,
        }
    }
}

/// Secret key for DSA.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct DSASecretKey {
    pub x: BigUint,
}

impl fmt::Debug for DSASecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DSASecretKey").field("x", &"[..]").finish()
    }
}

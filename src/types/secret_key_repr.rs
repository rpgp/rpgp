use zeroize::ZeroizeOnDrop;

use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::crypto::{checksum, dsa, ecdh, ecdsa, eddsa, rsa, Decryptor};
use crate::errors::Result;

use super::Mpi;

/// The version of the secret key that is actually exposed to users to do crypto operations.
#[allow(clippy::large_enum_variant)] // FIXME
#[derive(Debug, ZeroizeOnDrop)]
pub enum SecretKeyRepr {
    RSA(rsa::PrivateKey),
    DSA(dsa::SecretKey),
    ECDSA(ecdsa::SecretKey),
    ECDH(ecdh::SecretKey),
    EdDSA(eddsa::SecretKey),
}

impl SecretKeyRepr {
    pub fn decrypt(
        &self,
        mpis: &[Mpi],
        fingerprint: &[u8],
    ) -> Result<(Vec<u8>, SymmetricKeyAlgorithm)> {
        let decrypted_key = match self {
            SecretKeyRepr::RSA(ref priv_key) => priv_key.decrypt(mpis, fingerprint)?,
            SecretKeyRepr::DSA(_) => bail!("DSA is only used for signing"),
            SecretKeyRepr::ECDSA(_) => bail!("ECDSA is only used for signing"),
            SecretKeyRepr::ECDH(ref priv_key) => priv_key.decrypt(mpis, fingerprint)?,
            SecretKeyRepr::EdDSA(_) => unimplemented_err!("EdDSA"),
        };

        let session_key_algorithm = SymmetricKeyAlgorithm::from(decrypted_key[0]);
        ensure!(
            session_key_algorithm != SymmetricKeyAlgorithm::Plaintext,
            "session key algorithm cannot be plaintext"
        );
        let alg = session_key_algorithm;
        debug!("alg: {:?}", alg);

        let (k, checksum) = match self {
            SecretKeyRepr::ECDH(_) => {
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

        checksum::simple(checksum, k)?;

        Ok((k.to_vec(), alg))
    }
}

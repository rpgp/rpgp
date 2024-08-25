use log::debug;
use zeroize::ZeroizeOnDrop;

use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::crypto::{checksum, dsa, ecdh, ecdsa, eddsa, rsa, x25519, Decryptor};
use crate::errors::Result;
use crate::message::EskBytes;
use crate::types::{EskType, PublicKeyTrait, PublicParams};
use crate::PlainSessionKey;

/// The version of the secret key that is actually exposed to users to do crypto operations.
#[allow(clippy::large_enum_variant)] // FIXME
#[derive(Debug, ZeroizeOnDrop)]
pub enum SecretKeyRepr {
    RSA(rsa::PrivateKey),
    DSA(dsa::SecretKey),
    ECDSA(ecdsa::SecretKey),
    ECDH(ecdh::SecretKey),
    EdDSA(eddsa::SecretKey),
    X25519(x25519::SecretKey),
    X448(crate::crypto::x448::SecretKey),
}

impl SecretKeyRepr {
    pub fn decrypt<P>(
        &self,
        values: &EskBytes,
        typ: EskType,
        recipient: &P,
    ) -> Result<PlainSessionKey>
    where
        P: PublicKeyTrait,
    {
        let decrypted_key = match (self, values) {
            (SecretKeyRepr::RSA(ref priv_key), EskBytes::Rsa { mpi }) => priv_key.decrypt(mpi)?,
            (SecretKeyRepr::DSA(_), _) => bail!("DSA is only used for signing"),
            (SecretKeyRepr::ECDSA(_), _) => bail!("ECDSA is only used for signing"),
            (
                SecretKeyRepr::ECDH(ref priv_key),
                EskBytes::Ecdh {
                    public_point,
                    encrypted_session_key,
                },
            ) => priv_key.decrypt(ecdh::EncryptionFields {
                public_point,
                encrypted_session_key,
                fingerprint: recipient.fingerprint().as_bytes(),
            })?,

            (
                SecretKeyRepr::X25519(ref priv_key),
                EskBytes::X25519 {
                    ephemeral,
                    session_key,
                    sym_alg,
                },
            ) => {
                // Recipient public key (32 bytes)
                let PublicParams::X25519 { public } = recipient.public_params() else {
                    bail!(
                        "Unexpected recipient public_params {:?} for X25519",
                        recipient.public_params()
                    );
                };

                let data = x25519::EncryptionFields {
                    ephemeral_public_point: ephemeral.to_owned(),
                    recipient_public: *public,
                    encrypted_session_key: session_key,
                };

                let key = priv_key.decrypt(data)?;

                return match (&typ, *sym_alg) {
                    // We expect `sym_alg` to be set for v3 PKESK, and unset for v6 PKESK
                    (EskType::V3_4, Some(sym_alg)) => Ok(PlainSessionKey::V4 { key, sym_alg }),
                    (EskType::V6, None) => Ok(PlainSessionKey::V6 { key }),
                    _ => bail!("unexpected: sym_alg {:?} for {:?}", sym_alg, typ),
                };
            }

            (
                SecretKeyRepr::X448(ref priv_key),
                EskBytes::X448 {
                    ephemeral,
                    session_key,
                    sym_alg,
                },
            ) => {
                // Recipient public key (56 bytes)
                let PublicParams::X448 { public } = recipient.public_params() else {
                    bail!(
                        "Unexpected recipient public_params {:?} for X448",
                        recipient.public_params()
                    );
                };

                let data = crate::crypto::x448::EncryptionFields {
                    ephemeral_public_point: ephemeral.to_owned(),
                    recipient_public: *public,
                    encrypted_session_key: session_key,
                };

                let key = priv_key.decrypt(data)?;

                // We expect `algo` to be set for v3 PKESK, and unset for v6 PKESK
                return if let Some(sym_alg) = *sym_alg {
                    Ok(PlainSessionKey::V4 { key, sym_alg })
                } else {
                    Ok(PlainSessionKey::V6 { key })
                };
            }

            (SecretKeyRepr::EdDSA(_), _) => bail!("EdDSA is only used for signing"),
            _ => todo!(),
        };

        match typ {
            EskType::V3_4 => {
                let session_key_algorithm = SymmetricKeyAlgorithm::from(decrypted_key[0]);
                ensure!(
                    session_key_algorithm != SymmetricKeyAlgorithm::Plaintext,
                    "session key algorithm cannot be plaintext"
                );
                let alg = session_key_algorithm;
                debug!("alg: {:?}", alg);

                let (k, checksum) = match self {
                    // TODO: this distinction seems unnecessary. remove?
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

                Ok(PlainSessionKey::V4 {
                    key: k.to_vec(),
                    sym_alg: alg,
                })
            }

            EskType::V6 => {
                let (k, checksum) = {
                    let dec_len = decrypted_key.len();
                    (
                        &decrypted_key[0..dec_len - 2],
                        &decrypted_key[dec_len - 2..],
                    )
                };

                checksum::simple(checksum, k)?;

                Ok(PlainSessionKey::V6 { key: k.to_vec() })
            }
        }
    }
}

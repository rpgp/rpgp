#[macro_export]
macro_rules! impl_secret_key {
    ($name:ident, $tag:expr) => {
        #[derive(Debug, PartialEq, Eq)]
        pub struct $name {
            version: $crate::types::KeyVersion,
            algorithm: $crate::crypto::public_key::PublicKeyAlgorithm,
            created_at: chrono::DateTime<chrono::Utc>,
            expiration: Option<u16>,
            public_params: $crate::crypto::public_key::PublicParams,
            secret_params: $crate::types::EncryptedSecretParams,
        }

        impl $name {
            /// Parses a `SecretKey` packet from the given slice.
            pub fn from_slice(input: &[u8]) -> $crate::errors::Result<Self> {
                let (_, pk) = $crate::packet::secret_key_parser::parse(input)?;

                Ok(pk.into())
            }

            pub fn new(
                version: $crate::types::KeyVersion,
                algorithm: $crate::crypto::public_key::PublicKeyAlgorithm,
                created_at: chrono::DateTime<chrono::Utc>,
                expiration: Option<u16>,
                public_params: $crate::crypto::public_key::PublicParams,
                secret_params: $crate::types::EncryptedSecretParams,
            ) -> $name {
                info!(
                    "creating priv key: {:?} {:?} {:?} {:?} {:?} {:?}",
                    version, algorithm, created_at, expiration, public_params, secret_params
                );
                $name {
                    version,
                    algorithm,
                    created_at,
                    expiration,
                    public_params,
                    secret_params,
                }
            }

            /// Unlock the raw data in the secret parameters.
            pub fn unlock<F, G>(&self, pw: F, work: G) -> $crate::errors::Result<()>
            where
                F: FnOnce() -> String,
                G: FnOnce(&$crate::types::SecretKeyRepr) -> $crate::errors::Result<()>,
            {
                let decrypted = if self.secret_params.is_encrypted() {
                    self.repr_from_ciphertext(pw, self.secret_params.data.as_slice())
                } else {
                    self.repr_from_plaintext(self.secret_params.data.as_slice())
                }?;

                work(&decrypted)
            }

            fn repr_from_ciphertext<F>(
                &self,
                pw: F,
                ciphertext: &[u8],
            ) -> $crate::errors::Result<$crate::types::SecretKeyRepr>
            where
                F: FnOnce() -> String,
            {
                use $crate::crypto::checksum;
                use $crate::crypto::kdf::s2k;

                let sym_alg = self
                    .secret_params
                    .encryption_algorithm
                    .as_ref()
                    .ok_or_else(|| format_err!("missing encryption algorithm"))?;
                let typ = self
                    .secret_params
                    .string_to_key
                    .as_ref()
                    .ok_or_else(|| format_err!("missing s2k method"))?;
                let hash_alg = self
                    .secret_params
                    .string_to_key_hash
                    .as_ref()
                    .ok_or_else(|| format_err!("missing hash algorithm"))?;
                let key = s2k(
                    pw,
                    *sym_alg,
                    *typ,
                    *hash_alg,
                    self.secret_params.string_to_key_salt.as_ref(),
                    self.secret_params.string_to_key_count.as_ref(),
                )?;

                let iv = self
                    .secret_params
                    .iv
                    .as_ref()
                    .ok_or_else(|| format_err!("missing IV"))?;

                // Actual decryption
                let mut plaintext = ciphertext.to_vec();
                sym_alg.decrypt_with_iv_regular(&key, iv, &mut plaintext)?;

                // Validate checksum
                if self.has_checksum() {
                    let split = plaintext.len() - 20;
                    checksum::sha1(&plaintext[split..], &plaintext[..split])?;
                } else if let Some(ref actual_checksum) = self.secret_params.checksum {
                    // we already parsed the checksum when reading the s2k.
                    checksum::simple(actual_checksum, &plaintext)?;
                } else {
                    bail!("missing checksum");
                }

                // Construct details from the now decrypted plaintext information
                self.repr_from_plaintext(&plaintext)
            }

            fn repr_from_plaintext(
                &self,
                plaintext: &[u8],
            ) -> $crate::errors::Result<$crate::types::SecretKeyRepr> {
                use rsa::RSAPrivateKey;
                use $crate::crypto::ecc_curve::ECCCurve;
                use $crate::crypto::public_key::{PublicKeyAlgorithm, PublicParams};
                use $crate::packet::secret_key_parser::{ecc_secret_params, rsa_secret_params};
                use $crate::types::{ECDHSecretKey, EdDSASecretKey, SecretKeyRepr};

                match self.algorithm {
                    PublicKeyAlgorithm::RSA
                    | PublicKeyAlgorithm::RSAEncrypt
                    | PublicKeyAlgorithm::RSASign => {
                        let (_, (d, p, q, _)) = rsa_secret_params(plaintext)?;
                        match self.public_params {
                            PublicParams::RSA { ref n, ref e } => {
                                let secret_key = RSAPrivateKey::from_components(
                                    n.clone(),
                                    e.clone(),
                                    d,
                                    vec![p, q],
                                );
                                secret_key.validate()?;
                                Ok(SecretKeyRepr::RSA(secret_key))
                            }
                            _ => unreachable!("inconsistent key state"),
                        }
                    }
                    PublicKeyAlgorithm::DSA => {
                        unimplemented_err!("DSA");
                    }
                    PublicKeyAlgorithm::ECDH => match self.public_params {
                        PublicParams::ECDH {
                            ref curve,
                            ref hash,
                            ref alg_sym,
                            ..
                        } => match *curve {
                            ECCCurve::Curve25519 => {
                                let (_, d) = ecc_secret_params(plaintext)?;
                                ensure_eq!(d.len(), 32, "invalid secret");

                                let mut secret = [0u8; 32];
                                secret.copy_from_slice(d);

                                Ok(SecretKeyRepr::ECDH(ECDHSecretKey {
                                    oid: curve.oid(),
                                    hash: *hash,
                                    alg_sym: *alg_sym,
                                    secret,
                                }))
                            }
                            _ => unsupported_err!("curve {:?} for ECDH", curve.to_string()),
                        },
                        _ => unreachable!("inconsistent key state"),
                    },
                    PublicKeyAlgorithm::ECDSA => {
                        unimplemented_err!("ECDSA");
                    }
                    PublicKeyAlgorithm::EdDSA => match self.public_params {
                        PublicParams::EdDSA { ref curve, .. } => match *curve {
                            ECCCurve::Ed25519 => {
                                let (_, d) = ecc_secret_params(plaintext)?;
                                ensure_eq!(d.len(), 32, "invalid secret");

                                let mut secret = [0u8; 32];
                                secret.copy_from_slice(d);

                                Ok(SecretKeyRepr::EdDSA(EdDSASecretKey {
                                    oid: curve.oid(),
                                    secret,
                                }))
                            }
                            _ => unsupported_err!("curve {:?} for EdDSA", curve.to_string()),
                        },
                        _ => unreachable!("inconsistent key state"),
                    },
                    PublicKeyAlgorithm::Elgamal => {
                        unimplemented_err!("Elgamal");
                    }
                    _ => unsupported_err!("algorithm: {:?}", self.algorithm),
                }
            }

            pub fn secret_params(&self) -> &$crate::types::EncryptedSecretParams {
                &self.secret_params
            }

            /// Checks if we should expect a SHA1 checksum in the encrypted part.
            fn has_checksum(&self) -> bool {
                self.secret_params.string_to_key_id == 254
            }
        }

        impl_key!($name);
    };
}

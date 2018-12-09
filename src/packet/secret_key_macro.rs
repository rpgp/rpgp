#[macro_export]
macro_rules! impl_secret_key {
    ($name:ident, $tag:expr, $details:ident) => {
        #[derive(Debug, PartialEq, Eq)]
        pub struct $name {
            details: $crate::packet::$details,
            secret_params: $crate::types::EncryptedSecretParams,
        }

        impl $name {
            /// Parses a `SecretKey` packet from the given slice.
            pub fn from_slice(
                packet_version: $crate::types::Version,
                input: &[u8],
            ) -> $crate::errors::Result<Self> {
                let (_, details) = $crate::packet::secret_key_parser::parse(input)?;
                let (version, algorithm, created_at, expiration, public_params, secret_params) =
                    details;
                Ok($name {
                    details: $crate::packet::$details {
                        packet_version,
                        version,
                        algorithm,
                        created_at,
                        expiration,
                        public_params,
                    },
                    secret_params,
                })
            }

            pub fn version(&self) -> $crate::types::KeyVersion {
                self.details.version()
            }

            pub fn algorithm(&self) -> &$crate::crypto::public_key::PublicKeyAlgorithm {
                &self.details.algorithm()
            }

            pub fn created_at(&self) -> &chrono::DateTime<chrono::Utc> {
                &self.details.created_at()
            }

            pub fn expiration(&self) -> Option<u16> {
                self.details.expiration()
            }

            pub fn public_params(&self) -> &$crate::crypto::public_key::PublicParams {
                &self.details.public_params()
            }

            pub fn verify(&self) -> $crate::errors::Result<()> {
                unimplemented!("verify");
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
                let s2k_details = self
                    .secret_params
                    .string_to_key
                    .as_ref()
                    .ok_or_else(|| format_err!("missing s2k"))?;
                let key = s2k(
                    pw,
                    *sym_alg,
                    s2k_details.typ,
                    s2k_details.hash,
                    s2k_details.salt.as_ref(),
                    s2k_details.count().as_ref(),
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

                match self.algorithm() {
                    PublicKeyAlgorithm::RSA
                    | PublicKeyAlgorithm::RSAEncrypt
                    | PublicKeyAlgorithm::RSASign => {
                        let (_, (d, p, q, _)) = rsa_secret_params(plaintext)?;
                        match self.public_params() {
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
                    PublicKeyAlgorithm::ECDH => match self.public_params() {
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
                    PublicKeyAlgorithm::EdDSA => match self.public_params() {
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
                    _ => unsupported_err!("algorithm: {:?}", self.algorithm()),
                }
            }

            pub fn secret_params(&self) -> &$crate::types::EncryptedSecretParams {
                &self.secret_params
            }

            /// Checks if we should expect a SHA1 checksum in the encrypted part.
            fn has_checksum(&self) -> bool {
                self.secret_params.string_to_key_id == 254
            }

            fn to_writer_old<W: std::io::Write>(
                &self,
                writer: &mut W,
            ) -> $crate::errors::Result<()> {
                use $crate::ser::Serialize;

                self.details.to_writer_old(writer)?;
                self.secret_params.to_writer(writer)?;

                Ok(())
            }

            fn to_writer_new<W: std::io::Write>(
                &self,
                writer: &mut W,
            ) -> $crate::errors::Result<()> {
                use $crate::ser::Serialize;

                self.details.to_writer_new(writer)?;
                self.secret_params.to_writer(writer)?;

                Ok(())
            }
        }

        impl $crate::types::SecretKeyTrait for $name {
            /// Unlock the raw data in the secret parameters.
            fn unlock<F, G>(&self, pw: F, work: G) -> $crate::errors::Result<()>
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
        }

        impl $crate::ser::Serialize for $name {
            fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> $crate::errors::Result<()> {
                writer.write_all(&[self.version() as u8])?;

                match self.version() {
                    $crate::types::KeyVersion::V2 | $crate::types::KeyVersion::V3 => {
                        self.to_writer_old(writer)
                    }
                    $crate::types::KeyVersion::V4 => self.to_writer_new(writer),
                }
            }
        }

        impl $crate::packet::PacketTrait for $name {
            fn packet_version(&self) -> $crate::types::Version {
                self.details.packet_version()
            }

            fn tag(&self) -> $crate::types::Tag {
                $tag
            }
        }

        impl $crate::types::KeyTrait for $name {
            /// Returns the fingerprint of this key.
            fn fingerprint(&self) -> Vec<u8> {
                use byteorder::{BigEndian, ByteOrder};
                use md5::Md5;
                use num_bigint::BigUint;
                use sha1::{Digest, Sha1};
                use $crate::crypto::public_key::PublicParams;
                use $crate::types::KeyVersion;
                use $crate::util::bignum_to_mpi;

                match self.version() {
                    KeyVersion::V4 => {
                        // A one-octet version number (4).
                        let mut packet = Vec::new();
                        packet.push(4);

                        // A four-octet number denoting the time that the key was created.
                        let mut time_buf: [u8; 4] = [0; 4];
                        BigEndian::write_u32(&mut time_buf, self.created_at().timestamp() as u32);
                        packet.extend_from_slice(&time_buf);

                        // A one-octet number denoting the public-key algorithm of this key.
                        packet.push(*self.algorithm() as u8);

                        // A series of multiprecision integers comprising the key material.
                        match &self.public_params() {
                            PublicParams::RSA { n, e } => {
                                packet.extend(bignum_to_mpi(n));
                                packet.extend(bignum_to_mpi(e));
                            }
                            PublicParams::DSA { p, q, g, y } => {
                                packet.extend(bignum_to_mpi(p));
                                packet.extend(bignum_to_mpi(q));
                                packet.extend(bignum_to_mpi(g));
                                packet.extend(bignum_to_mpi(y));
                            }
                            PublicParams::ECDSA { curve, p } => {
                                // a one-octet size of the following field
                                packet.push(curve.oid().len() as u8);
                                // octets representing a curve OID
                                packet.extend(curve.oid().iter().cloned());
                                // MPI of an EC point representing a public key
                                packet.extend(bignum_to_mpi(&BigUint::from_bytes_be(&p)));
                            }
                            PublicParams::ECDH {
                                curve,
                                p,
                                hash,
                                alg_sym,
                            } => {
                                //a one-octet size of the following field
                                packet.push(curve.oid().len() as u8);
                                //the octets representing a curve OID
                                packet.extend(curve.oid().iter().cloned());
                                //MPI of an EC point representing a public key
                                packet.extend(bignum_to_mpi(&BigUint::from_bytes_be(&p)));
                                //a one-octet size of the following fields
                                packet.push(3); // Always 3??
                                                //a one-octet value 01
                                packet.push(1);
                                //a one-octet hash function ID used with a KDF
                                packet.push(*hash as u8);
                                //a one-octet algorithm ID
                                packet.push(*alg_sym as u8);
                            }
                            PublicParams::Elgamal { p, g, y } => {
                                packet.extend(bignum_to_mpi(p));
                                packet.extend(bignum_to_mpi(g));
                                packet.extend(bignum_to_mpi(y));
                            }
                            PublicParams::EdDSA { curve, q } => {
                                // a one-octet size of the following field
                                packet.push(curve.oid().len() as u8);
                                // octets representing a curve OID
                                packet.extend(curve.oid().iter().cloned());
                                // MPI of an EC point representing a public key
                                packet.extend(bignum_to_mpi(&BigUint::from_bytes_be(&q)));
                            }
                        }

                        let mut length_buf: [u8; 2] = [0; 2];
                        BigEndian::write_uint(&mut length_buf, packet.len() as u64, 2);

                        let mut h = Sha1::new();
                        h.input(&[0x99]);
                        h.input(&length_buf);
                        h.input(&packet);

                        h.result().to_vec()
                    }

                    KeyVersion::V2 | KeyVersion::V3 => {
                        let mut h = Md5::new();

                        let mut packet = Vec::new();

                        match &self.public_params() {
                            PublicParams::RSA { n, e } => {
                                packet.extend(bignum_to_mpi(n));
                                packet.extend(bignum_to_mpi(e));
                            }
                            PublicParams::DSA { p, q, g, y } => {
                                packet.extend(bignum_to_mpi(p));
                                packet.extend(bignum_to_mpi(q));
                                packet.extend(bignum_to_mpi(g));
                                packet.extend(bignum_to_mpi(y));
                            }
                            PublicParams::ECDSA { curve, p } => {
                                // a one-octet size of the following field
                                packet.push(curve.oid().len() as u8);
                                // octets representing a curve OID
                                packet.extend(curve.oid().iter().cloned());
                                // MPI of an EC point representing a public key
                                packet.extend(bignum_to_mpi(&BigUint::from_bytes_be(&p)));
                            }
                            PublicParams::ECDH {
                                curve,
                                p,
                                hash,
                                alg_sym,
                            } => {
                                //a one-octet size of the following field
                                packet.push(curve.oid().len() as u8);
                                //the octets representing a curve OID
                                packet.extend(curve.oid().iter().cloned());
                                //MPI of an EC point representing a public key
                                packet.extend(bignum_to_mpi(&BigUint::from_bytes_be(&p)));
                                //a one-octet size of the following fields
                                packet.push(3); // Always 3??
                                                //a one-octet value 01
                                packet.push(1);
                                //a one-octet hash function ID used with a KDF
                                packet.push(*hash as u8);
                                //a one-octet algorithm ID
                                packet.push(*alg_sym as u8);
                            }
                            PublicParams::Elgamal { p, g, y } => {
                                packet.extend(bignum_to_mpi(p));
                                packet.extend(bignum_to_mpi(g));
                                packet.extend(bignum_to_mpi(y));
                            }
                            PublicParams::EdDSA { curve, q } => {
                                // a one-octet size of the following field
                                packet.push(curve.oid().len() as u8);
                                // octets representing a curve OID
                                packet.extend(curve.oid().iter().cloned());
                                // MPI of an EC point representing a public key
                                packet.extend(bignum_to_mpi(&BigUint::from_bytes_be(&q)));
                            }
                        }

                        h.input(&packet);

                        h.result().to_vec()
                    }
                }
            }

            fn key_id(&self) -> Option<$crate::types::KeyId> {
                use $crate::crypto::public_key::PublicParams;
                use $crate::types::{KeyId, KeyVersion};

                match self.version() {
                    KeyVersion::V4 => {
                        // Lower 64 bits
                        let f = self.fingerprint();
                        let offset = f.len() - 8;

                        KeyId::from_slice(&f[offset..]).ok()
                    }
                    KeyVersion::V2 | KeyVersion::V3 => match &self.public_params() {
                        PublicParams::RSA { n, .. } => {
                            let n = n.to_bytes_be();
                            let offset = n.len() - 8;

                            KeyId::from_slice(&n[offset..]).ok()
                        }
                        _ => None,
                    },
                }
            }
        }

        impl $crate::types::PublicKeyTrait for $name {
            fn verify_signature(
                &self,
                hash: $crate::crypto::hash::HashAlgorithm,
                hashed: &[u8],
                sig: &[Vec<u8>],
            ) -> $crate::errors::Result<()> {
                self.details.verify_signature(hash, hashed, sig)
            }

            fn to_writer_old(
                &self,
                writer: &mut impl std::io::Write,
            ) -> $crate::errors::Result<()> {
                use $crate::ser::Serialize;

                let mut key_buf = Vec::new();
                self.details.to_writer(&mut key_buf)?;

                // old style packet header for the key
                writer.write_all(&[0x99, (key_buf.len() >> 8) as u8, key_buf.len() as u8])?;
                writer.write_all(&key_buf)?;

                Ok(())
            }
        }
    };
}

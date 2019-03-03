#[macro_export]
macro_rules! impl_secret_key {
    ($name:ident, $tag:expr, $details:ident) => {
        #[derive(Debug, PartialEq, Eq, Clone)]
        pub struct $name {
            pub(crate) details: $crate::packet::$details,
            pub(crate) secret_params: $crate::types::SecretParams,
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
                ciphertext: &$crate::types::EncryptedSecretParams,
            ) -> $crate::errors::Result<$crate::types::SecretKeyRepr>
            where
                F: FnOnce() -> String,
            {
                let plain = ciphertext.unlock(pw, self.details.algorithm)?;
                self.repr_from_plaintext(&plain)
            }

            fn repr_from_plaintext(
                &self,
                plaintext: &$crate::types::PlainSecretParams,
            ) -> $crate::errors::Result<$crate::types::SecretKeyRepr> {
                plaintext.as_repr(self.public_params())
            }

            pub fn secret_params(&self) -> &$crate::types::SecretParams {
                &self.secret_params
            }

            /// Checks if we should expect a SHA1 checksum in the encrypted part.
            pub fn has_sha1_checksum(&self) -> bool {
                self.secret_params.string_to_key_id() == 254
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

            pub fn sign<F>(
                &self,
                key: &impl $crate::types::SecretKeyTrait,
                key_pw: F,
            ) -> $crate::errors::Result<$crate::packet::Signature>
            where
                F: FnOnce() -> String,
            {
                use chrono::SubsecRound;
                let mut config = $crate::packet::SignatureConfigBuilder::default();
                match $tag {
                    $crate::types::Tag::SecretKey => {
                        config.typ($crate::packet::SignatureType::KeyBinding);
                    }
                    $crate::types::Tag::SecretSubkey => {
                        config.typ($crate::packet::SignatureType::SubkeyBinding);
                    }
                    _ => panic!("invalid tag"),
                };

                config
                    .pub_alg(key.algorithm())
                    .hashed_subpackets(vec![$crate::packet::Subpacket::SignatureCreationTime(
                        chrono::Utc::now().trunc_subsecs(0),
                    )])
                    .unhashed_subpackets(vec![$crate::packet::Subpacket::Issuer(key.key_id())])
                    .build()?
                    .sign_key(key, key_pw, &self)
            }
        }

        impl $crate::types::SecretKeyTrait for $name {
            type PublicKey = $details;

            /// Unlock the raw data in the secret parameters.
            fn unlock<F, G>(&self, pw: F, work: G) -> $crate::errors::Result<()>
            where
                F: FnOnce() -> String,
                G: FnOnce(&$crate::types::SecretKeyRepr) -> $crate::errors::Result<()>,
            {
                use $crate::types::SecretParams;

                let decrypted = match self.secret_params {
                    SecretParams::Plain(ref k) => self.repr_from_plaintext(k),
                    SecretParams::Encrypted(ref k) => self.repr_from_ciphertext(pw, k),
                }?;

                work(&decrypted)
            }

            fn create_signature<F>(
                &self,
                key_pw: F,
                hash: $crate::crypto::hash::HashAlgorithm,
                data: &[u8],
            ) -> $crate::errors::Result<Vec<Vec<u8>>>
            where
                F: FnOnce() -> String,
            {
                use $crate::crypto::ecc_curve::ECCCurve;
                use $crate::crypto::public_key::PublicParams;
                use $crate::types::SecretKeyRepr;

                info!("signing data: {}", hex::encode(&data));

                let mut signature: Option<Vec<Vec<u8>>> = None;
                self.unlock(key_pw, |priv_key| {
                    info!("unlocked key");
                    let sig = match *priv_key {
                        SecretKeyRepr::RSA(ref priv_key) => {
                            $crate::crypto::signature::sign_rsa(priv_key, hash, data)
                        }
                        SecretKeyRepr::DSA(_) => unimplemented_err!("sign DSA"),
                        SecretKeyRepr::ECDSA => unimplemented_err!("sign ECDSA"),
                        SecretKeyRepr::ECDH(_) => {
                            bail!("ECDH can not be used to for signing operations")
                        }
                        SecretKeyRepr::EdDSA(ref priv_key) => match self.public_params() {
                            PublicParams::EdDSA { ref curve, ref q } => match *curve {
                                ECCCurve::Ed25519 => {
                                    $crate::crypto::signature::sign_eddsa(q, priv_key, hash, data)
                                }
                                _ => unsupported_err!("curve {:?} for EdDSA", curve.to_string()),
                            },
                            _ => unreachable!("inconsistent key state"),
                        },
                    }?;

                    signature = Some(sig);
                    Ok(())
                })?;

                signature.ok_or_else(|| unreachable!())
            }

            fn public_key(&self) -> $details {
                self.details.clone()
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
                    $crate::types::KeyVersion::V5 => unimplemented_err!("V5 keys"),
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
                    KeyVersion::V5 => unimplemented!("V5 keys"),
                    KeyVersion::V4 => {
                        // A one-octet version number (4).
                        let mut packet = Vec::new();
                        packet.push(4);

                        // A four-octet number denoting the time that the key was created.
                        let mut time_buf: [u8; 4] = [0; 4];
                        BigEndian::write_u32(&mut time_buf, self.created_at().timestamp() as u32);
                        packet.extend_from_slice(&time_buf);

                        // A one-octet number denoting the public-key algorithm of this key.
                        packet.push(self.algorithm() as u8);

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

            fn key_id(&self) -> $crate::types::KeyId {
                use $crate::crypto::public_key::PublicParams;
                use $crate::types::{KeyId, KeyVersion};

                match self.version() {
                    KeyVersion::V5 => unimplemented!("V5 keys"),
                    KeyVersion::V4 => {
                        // Lower 64 bits
                        let f = self.fingerprint();
                        let offset = f.len() - 8;

                        KeyId::from_slice(&f[offset..]).expect("fixed size slice")
                    }
                    KeyVersion::V2 | KeyVersion::V3 => match &self.public_params() {
                        PublicParams::RSA { n, .. } => {
                            let n = n.to_bytes_be();
                            let offset = n.len() - 8;

                            KeyId::from_slice(&n[offset..]).expect("fixed size slice")
                        }
                        _ => panic!("invalid key constructed: {:?}", &self.public_params()),
                    },
                }
            }

            fn algorithm(&self) -> $crate::crypto::public_key::PublicKeyAlgorithm {
                self.details.algorithm()
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

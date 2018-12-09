#[macro_export]
macro_rules! impl_public_key {
    ($name:ident, $tag:expr) => {
        #[derive(Debug, PartialEq, Eq)]
        pub struct $name {
            packet_version: $crate::types::Version,
            version: $crate::types::KeyVersion,
            algorithm: $crate::crypto::public_key::PublicKeyAlgorithm,
            created_at: chrono::DateTime<chrono::Utc>,
            expiration: Option<u16>,
            public_params: $crate::crypto::public_key::PublicParams,
        }

        impl $name {
            /// Parses a `PublicKeyKey` packet from the given slice.
            pub fn from_slice(
                packet_version: $crate::types::Version,
                input: &[u8],
            ) -> $crate::errors::Result<Self> {
                let (_, details) = $crate::packet::public_key_parser::parse(input)?;
                let (version, algorithm, created_at, expiration, public_params) = details;
                Ok($name {
                    packet_version,
                    version,
                    algorithm,
                    created_at,
                    expiration,
                    public_params,
                })
            }

            pub fn version(&self) -> $crate::types::KeyVersion {
                self.version
            }

            pub fn algorithm(&self) -> &$crate::crypto::public_key::PublicKeyAlgorithm {
                &self.algorithm
            }

            pub fn created_at(&self) -> &chrono::DateTime<chrono::Utc> {
                &self.created_at
            }

            pub fn expiration(&self) -> Option<u16> {
                self.expiration
            }

            pub fn public_params(&self) -> &$crate::crypto::public_key::PublicParams {
                &self.public_params
            }

            pub fn verify(&self) -> $crate::errors::Result<()> {
                unimplemented!("verify");
            }

            fn to_writer_old<W: std::io::Write>(
                &self,
                writer: &mut W,
            ) -> $crate::errors::Result<()> {
                use byteorder::{BigEndian, WriteBytesExt};
                use $crate::ser::Serialize;

                writer.write_u32::<BigEndian>(self.created_at.timestamp() as u32)?;
                writer.write_u16::<BigEndian>(
                    self.expiration
                        .expect("old key versions have an expiration"),
                )?;
                writer.write_all(&[self.algorithm as u8])?;
                self.public_params.to_writer(writer)?;

                Ok(())
            }

            fn to_writer_new<W: std::io::Write>(
                &self,
                writer: &mut W,
            ) -> $crate::errors::Result<()> {
                use byteorder::{BigEndian, WriteBytesExt};
                use $crate::ser::Serialize;

                writer.write_u32::<BigEndian>(self.created_at.timestamp() as u32)?;
                writer.write_all(&[self.algorithm as u8])?;
                self.public_params.to_writer(writer)?;

                Ok(())
            }
        }

        impl $crate::ser::Serialize for $name {
            fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> $crate::errors::Result<()> {
                writer.write_all(&[self.version as u8])?;

                match self.version {
                    $crate::types::KeyVersion::V2 | $crate::types::KeyVersion::V3 => {
                        self.to_writer_old(writer)
                    }
                    $crate::types::KeyVersion::V4 => self.to_writer_new(writer),
                }
            }
        }

        impl $crate::packet::PacketTrait for $name {
            fn packet_version(&self) -> $crate::types::Version {
                self.packet_version
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
                        match &self.public_params {
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

                        match &self.public_params {
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
                    KeyVersion::V2 | KeyVersion::V3 => match &self.public_params {
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
                use $crate::crypto::public_key::PublicParams;

                info!("verify data: {}", hex::encode(&hashed));
                info!("verify sig: {}", hex::encode(&sig.concat()));

                match self.public_params {
                    PublicParams::RSA { ref n, ref e } => {
                        $crate::crypto::signature::verify_rsa(n, e, hash, hashed, &sig.concat())
                    }
                    PublicParams::EdDSA { ref curve, ref q } => {
                        $crate::crypto::signature::verify_eddsa(curve, q, hash, hashed, sig)
                    }
                    PublicParams::ECDSA { ref curve, .. } => {
                        unimplemented_err!("verify ECDSA: {:?}", curve);
                    }
                    PublicParams::ECDH {
                        ref curve,
                        ref hash,
                        ref alg_sym,
                        ..
                    } => {
                        unimplemented_err!("verify ECDH: {:?} {:?} {:?}", curve, hash, alg_sym);
                    }
                    PublicParams::Elgamal { .. } => {
                        unimplemented_err!("verify Elgamal");
                    }
                    PublicParams::DSA { .. } => {
                        unimplemented_err!("verify DSA");
                    }
                }
            }

            fn to_writer_old(
                &self,
                writer: &mut impl std::io::Write,
            ) -> $crate::errors::Result<()> {
                use $crate::ser::Serialize;

                let mut key_buf = Vec::new();
                self.to_writer(&mut key_buf)?;

                // old style packet header for the key
                writer.write_all(&[0x99, (key_buf.len() >> 8) as u8, key_buf.len() as u8])?;
                writer.write_all(&key_buf)?;

                Ok(())
            }
        }
    };
}

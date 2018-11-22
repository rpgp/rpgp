#[macro_export]
macro_rules! impl_key {
    ($name:ty) => {
        impl $name {
            pub fn version(&self) -> &$crate::types::KeyVersion {
                &self.version
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
        }
        impl<'a> $crate::types::KeyTrait for &'a $name {
            fn fingerprint(&self) -> Vec<u8> {
                (*self).fingerprint()
            }
            fn key_id(&self) -> Option<$crate::types::KeyId> {
                (*self).key_id()
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
    };
}

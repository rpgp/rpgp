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

            fn verify(&self) -> $crate::errors::Result<()> {
                unimplemented!("verify");
            }
        }

        impl $crate::types::PublicKeyTrait for $name {
            fn verify_signature(
                &self,
                hash: $crate::crypto::hash::HashAlgorithm,
                hashed: &[u8],
                sig: &[Vec<u8>],
            ) -> $crate::errors::Result<()> {
                use try_from::TryInto;
                use $crate::crypto::public_key::PublicParams;

                info!("verify data: {}", hex::encode(&hashed));
                info!("verify sig: {}", hex::encode(&sig.concat()));

                match self.public_params {
                    PublicParams::RSA { ref n, ref e } => {
                        use rsa::padding::PaddingScheme;

                        let sig = sig.concat();
                        let key = rsa::RSAPublicKey::new(n.clone(), e.clone())?;
                        let rsa_hash: Option<rsa::hash::Hashes> = hash.try_into().ok();

                        info!("n: {}", hex::encode(n.to_bytes_be()));
                        info!("e: {}", hex::encode(e.to_bytes_be()));
                        key.verify(
                            PaddingScheme::PKCS1v15,
                            rsa_hash.as_ref(),
                            &hashed[..],
                            &sig,
                        )
                        .map_err(|err| err.into())
                    }
                    PublicParams::EdDSA { ref curve, ref q } => match *curve {
                        $crate::crypto::ecc_curve::ECCCurve::Ed25519 => {
                            ensure_eq!(sig.len(), 2);

                            let r = &sig[0];
                            let s = &sig[1];

                            ensure_eq!(r.len(), 32);
                            ensure_eq!(s.len(), 32);
                            ensure_eq!(q.len(), 33);
                            ensure_eq!(q[0], 0x40);

                            // TODO: unwraps to ? and implement the errors
                            let pk = ed25519_dalek::PublicKey::from_bytes(&q[1..])
                                .expect("invalid pubkey");
                            let sig = ed25519_dalek::Signature::from_bytes(&sig.concat())
                                .expect("malformed sig");

                            pk.verify::<sha2::Sha512>(hashed, &sig)
                                .expect("invalid sig");
                            Ok(())
                        }
                        _ => unsupported_err!("curve {:?} for EdDSA", curve.to_string()),
                    },
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
        }
    };
}

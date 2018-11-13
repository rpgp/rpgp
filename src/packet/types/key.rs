use std::fmt;

use byteorder::{BigEndian, ByteOrder};
use md5::Md5;
use num_bigint::BigUint;
use rsa::RSAPrivateKey;
use sha1::{Digest, Sha1};

use super::ecc_curve::ECCCurve;
use super::packet::{KeyVersion, PublicKeyAlgorithm, StringToKeyType};
use crypto::checksum;
use crypto::hash::HashAlgorithm;
use crypto::kdf::s2k;
use crypto::sym::SymmetricKeyAlgorithm;
use errors::Result;
use packet::tags::privkey::{ecc_private_params, rsa_private_params};
use util::bignum_to_mpi;

/// Represents a KeyID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyID([u8; 8]);

impl KeyID {
    pub fn from_slice(input: &[u8]) -> Result<KeyID> {
        ensure_eq!(input.len(), 8, "invalid input length");
        let mut r = [0u8; 8];
        r.copy_from_slice(input);

        Ok(KeyID(r))
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

/// Represents a single private key packet.
#[derive(Debug, PartialEq, Eq)]
pub struct PrivateKey {
    version: KeyVersion,
    algorithm: PublicKeyAlgorithm,
    created_at: u32,
    expiration: Option<u16>,
    public_params: PublicParams,
    private_params: EncryptedPrivateParams,
}

/// Represents a single public key packet.
#[derive(Debug, PartialEq, Eq)]
pub struct PublicKey {
    version: KeyVersion,
    algorithm: PublicKeyAlgorithm,
    created_at: u32,
    expiration: Option<u16>,
    public_params: PublicParams,
}

/// Represent the public paramaters for the different algorithms.
#[derive(Debug, PartialEq, Eq)]
pub enum PublicParams {
    RSA {
        n: BigUint,
        e: BigUint,
    },
    DSA {
        p: BigUint,
        q: BigUint,
        g: BigUint,
        y: BigUint,
    },
    ECDSA {
        curve: ECCCurve,
        p: Vec<u8>,
    },
    ECDH {
        curve: ECCCurve,
        p: Vec<u8>,
        hash: HashAlgorithm,
        alg_sym: SymmetricKeyAlgorithm,
    },
    Elgamal {
        p: BigUint,
        g: BigUint,
        y: BigUint,
    },
    EdDSA {
        curve: ECCCurve,
        q: Vec<u8>,
    },
}

/// The version of the private key that is actually exposed to users to
/// do crypto operations.
pub enum PrivateKeyRepr {
    RSA(RSAPrivateKey),
    DSA,
    ECDSA,
    ECDH(ECDHPrivateKey),
    EdDSA(EdDSAPrivateKey),
}

/// Private key for ECDH with Curve25519, the only combination we
// currently support.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ECDHPrivateKey {
    /// The secret point.
    pub secret: [u8; 32],
    pub hash: HashAlgorithm,
    pub oid: Vec<u8>,
    pub alg_sym: SymmetricKeyAlgorithm,
}

/// Private key for EdDSA with Curve25519, the only combination we
// currently support.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdDSAPrivateKey {
    /// The secret point.
    pub secret: [u8; 32],
    pub oid: Vec<u8>,
}

impl fmt::Debug for PrivateKeyRepr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PrivateKeyRepr::RSA(_) => write!(f, "PrivateKeyRepr(RSA)"),
            PrivateKeyRepr::DSA => write!(f, "PrivateKeyRepr(DSA)"),
            PrivateKeyRepr::ECDSA => write!(f, "PrivateKeyRepr(ECDSA)"),
            PrivateKeyRepr::ECDH(_) => write!(f, "PrivateKeyRepr(ECDH)"),
            PrivateKeyRepr::EdDSA(_) => write!(f, "PrivateKeyRepr(EdDSA)"),
        }
    }
}

/// A list of params that are used to represent the values of possibly encrypted key, from imports and exports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedPrivateParams {
    /// The raw data as generated when imported.
    pub data: Vec<u8>,
    /// Hash or checksum of the raw data.
    pub checksum: Option<Vec<u8>>,
    /// IV, exist encrypted raw data.
    pub iv: Option<Vec<u8>>,
    /// If raw is encrypted, the encryption algorithm used.
    pub encryption_algorithm: Option<SymmetricKeyAlgorithm>,
    /// If raw is encrypted, the string-to-key method used.
    pub string_to_key: Option<StringToKeyType>,
    /// If raw is encrypted, the hash algorithm for the s2k method.
    pub string_to_key_hash: Option<HashAlgorithm>,
    /// If raw is encrypted, and a salt is used the salt for the s2k method.
    pub string_to_key_salt: Option<Vec<u8>>,
    /// If raw is encrypted, and a count is used the hash algorithm for the s2k method.
    pub string_to_key_count: Option<usize>,
    /// The identifier for how this data is stored.
    pub string_to_key_id: u8,
}

impl EncryptedPrivateParams {
    pub fn new_plaintext(data: Vec<u8>, checksum: Option<Vec<u8>>) -> EncryptedPrivateParams {
        EncryptedPrivateParams {
            data,
            checksum,
            iv: None,
            encryption_algorithm: None,
            string_to_key: None,
            string_to_key_id: 0,
            string_to_key_hash: None,
            string_to_key_salt: None,
            string_to_key_count: None,
        }
    }

    pub fn is_encrypted(&self) -> bool {
        self.string_to_key_id != 0
    }
}

impl PublicKey {
    pub fn new(
        version: KeyVersion,
        algorithm: PublicKeyAlgorithm,
        created_at: u32,
        expiration: Option<u16>,
        public_params: PublicParams,
    ) -> PublicKey {
        PublicKey {
            version,
            algorithm,
            created_at,
            expiration,
            public_params,
        }
    }
}

impl PrivateKey {
    pub fn new(
        version: KeyVersion,
        algorithm: PublicKeyAlgorithm,
        created_at: u32,
        expiration: Option<u16>,
        public_params: PublicParams,
        private_params: EncryptedPrivateParams,
    ) -> PrivateKey {
        info!(
            "creating priv key: {:?} {:?} {:?} {:?} {:?} {:?}",
            version, algorithm, created_at, expiration, public_params, private_params
        );
        PrivateKey {
            version,
            algorithm,
            created_at,
            expiration,
            public_params,
            private_params,
        }
    }

    /// Unlock the raw data in the secret parameters.
    pub fn unlock<F, G>(&self, pw: F, work: G) -> Result<()>
    where
        F: FnOnce() -> String,
        G: FnOnce(&PrivateKeyRepr) -> Result<()>,
    {
        let decrypted = if self.private_params.is_encrypted() {
            self.repr_from_ciphertext(pw, self.private_params.data.as_slice())
        } else {
            self.repr_from_plaintext(self.private_params.data.as_slice())
        }?;

        work(&decrypted)
    }

    fn repr_from_ciphertext<F>(&self, pw: F, ciphertext: &[u8]) -> Result<PrivateKeyRepr>
    where
        F: FnOnce() -> String,
    {
        let sym_alg = self
            .private_params
            .encryption_algorithm
            .as_ref()
            .ok_or_else(|| format_err!("missing encryption algorithm"))?;
        let typ = self
            .private_params
            .string_to_key
            .as_ref()
            .ok_or_else(|| format_err!("missing s2k method"))?;
        let hash_alg = self
            .private_params
            .string_to_key_hash
            .as_ref()
            .ok_or_else(|| format_err!("missing hash algorithm"))?;
        let key = s2k(
            pw,
            *sym_alg,
            *typ,
            *hash_alg,
            self.private_params.string_to_key_salt.as_ref(),
            self.private_params.string_to_key_count.as_ref(),
        )?;

        let iv = self
            .private_params
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
        } else if let Some(ref actual_checksum) = self.private_params.checksum {
            // we already parsed the checksum when reading the s2k.
            checksum::simple(actual_checksum, &plaintext)?;
        } else {
            bail!("missing checksum");
        }

        // Construct details from the now decrypted plaintext information
        self.repr_from_plaintext(&plaintext)
    }

    fn repr_from_plaintext(&self, plaintext: &[u8]) -> Result<PrivateKeyRepr> {
        match self.algorithm {
            PublicKeyAlgorithm::RSA
            | PublicKeyAlgorithm::RSAEncrypt
            | PublicKeyAlgorithm::RSASign => {
                let (_, (d, p, q, _)) = rsa_private_params(plaintext)?;
                match self.public_params {
                    PublicParams::RSA { ref n, ref e } => {
                        let private_key =
                            RSAPrivateKey::from_components(n.clone(), e.clone(), d, vec![p, q]);
                        private_key.validate()?;
                        Ok(PrivateKeyRepr::RSA(private_key))
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
                        let (_, d) = ecc_private_params(plaintext)?;
                        ensure_eq!(d.len(), 32, "invalid secret");

                        let mut secret = [0u8; 32];
                        secret.copy_from_slice(d);

                        Ok(PrivateKeyRepr::ECDH(ECDHPrivateKey {
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
                        let (_, d) = ecc_private_params(plaintext)?;
                        ensure_eq!(d.len(), 32, "invalid secret");

                        let mut secret = [0u8; 32];
                        secret.copy_from_slice(d);

                        Ok(PrivateKeyRepr::EdDSA(EdDSAPrivateKey {
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

    pub fn private_params(&self) -> &EncryptedPrivateParams {
        &self.private_params
    }

    /// Checks if we should expect a SHA1 checksum in the encrypted part.
    fn has_checksum(&self) -> bool {
        self.private_params.string_to_key_id == 254
    }
}

macro_rules! key {
    ($name:ident) => {
        impl $name {
            pub fn version(&self) -> &KeyVersion {
                &self.version
            }

            pub fn algorithm(&self) -> &PublicKeyAlgorithm {
                &self.algorithm
            }

            pub fn created_at(&self) -> u32 {
                self.created_at
            }

            pub fn expiration(&self) -> Option<u16> {
                self.expiration
            }

            pub fn public_params(&self) -> &PublicParams {
                &self.public_params
            }

            /// Returns the fingerprint of this key.
            pub fn fingerprint(&self) -> Vec<u8> {
                match self.version() {
                    KeyVersion::V4 => {
                        // A one-octet version number (4).
                        let mut packet = Vec::new();
                        packet.push(4);

                        // A four-octet number denoting the time that the key was created.
                        let mut time_buf: [u8; 4] = [0; 4];
                        BigEndian::write_u32(&mut time_buf, self.created_at());
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

            pub fn key_id(&self) -> Option<KeyID> {
                match self.version() {
                    KeyVersion::V4 => {
                        // Lower 64 bits
                        let f = self.fingerprint();
                        let offset = f.len() - 8;

                        KeyID::from_slice(&f[offset..]).ok()
                    }
                    KeyVersion::V2 | KeyVersion::V3 => match &self.public_params {
                        PublicParams::RSA { n, .. } => {
                            let n = n.to_bytes_be();
                            let offset = n.len() - 8;

                            KeyID::from_slice(&n[offset..]).ok()
                        }
                        _ => None,
                    },
                }
            }
        }
    };
}

key!(PublicKey);
key!(PrivateKey);

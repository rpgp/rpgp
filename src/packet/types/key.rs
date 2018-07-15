use std::fmt;

use openssl::bn::{BigNum, BigNumContext};
use openssl::dsa::Dsa;
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::pkey;
use openssl::rsa::{Rsa, RsaPrivateKeyBuilder};

use super::ecc_curve::ECCCurve;
use super::packet::{KeyVersion, PublicKeyAlgorithm, StringToKeyType};
use crypto::hash::HashAlgorithm;
use crypto::kdf::s2k;
use crypto::sym::SymmetricKeyAlgorithm;
use errors::Result;
use packet::tags::privkey::{ecc_private_params, rsa_private_params};

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
        n: BigNum,
        e: BigNum,
    },
    DSA {
        p: BigNum,
        q: BigNum,
        g: BigNum,
        y: BigNum,
    },
    ECDSA {
        curve: ECCCurve,
        p: Vec<u8>,
    },
    ECDH {
        curve: ECCCurve,
        p: BigNum,
        hash: u8,
        alg_sym: u8,
    },
    Elgamal {
        p: BigNum,
        g: BigNum,
        y: BigNum,
    },
}

/// The version of the private key that is actually exposed to users to
/// do crypto operations.
pub enum PrivateKeyRepr {
    RSA(Rsa<pkey::Private>),
    DSA(Dsa<pkey::Private>),
    ECDSA(EcKey<pkey::Private>),
}

impl fmt::Debug for PrivateKeyRepr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PrivateKeyRepr::RSA(_) => write!(f, "PrivateKeyRepr(RSA)"),
            PrivateKeyRepr::DSA(_) => write!(f, "PrivateKeyRepr(DSA)"),
            PrivateKeyRepr::ECDSA(_) => write!(f, "PrivateKeyRepr(ECDSA)"),
        }
    }
}

/// A list of params that are used to represent the values of possibly encrypted key, from imports and exports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedPrivateParams {
    /// The raw data as generated when imported.
    pub data: Vec<u8>,
    /// Hash or checksum of the raw data.
    pub checksum: Vec<u8>,
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
    pub fn new_plaintext(data: Vec<u8>, checksum: Vec<u8>) -> EncryptedPrivateParams {
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
    pub fn unlock<'a, F, G>(&self, pw: F, work: G) -> Result<()>
    where
        F: FnOnce() -> String,
        G: FnOnce(&PrivateKeyRepr) -> Result<()>,
    {
        let decrypted = if self.private_params.is_encrypted() {
            self.from_ciphertext(pw, self.private_params.data.as_slice())
        } else {
            self.from_plaintext(self.private_params.data.as_slice())
        }?;

        work(&decrypted)
    }

    fn from_ciphertext<'a, F>(&self, pw: F, ciphertext: &[u8]) -> Result<PrivateKeyRepr>
    where
        F: FnOnce() -> String,
    {
        match self.algorithm {
            PublicKeyAlgorithm::RSA
            | PublicKeyAlgorithm::RSAEncrypt
            | PublicKeyAlgorithm::RSASign => {
                let sym_alg = self
                    .private_params
                    .encryption_algorithm
                    .as_ref()
                    .expect("missing encryption alg");
                let typ = self
                    .private_params
                    .string_to_key
                    .as_ref()
                    .expect("missing s2k method");
                let hash_alg = self
                    .private_params
                    .string_to_key_hash
                    .as_ref()
                    .expect("missing hash algorithm");
                let key = s2k(
                    pw,
                    sym_alg,
                    typ,
                    hash_alg,
                    self.private_params.string_to_key_salt.as_ref(),
                    self.private_params.string_to_key_count.as_ref(),
                )?;

                println!("key: {:?}", key);

                let plaintext = vec![];
                // TODO: decrypt
                self.from_plaintext(&plaintext)
            }
            PublicKeyAlgorithm::DSA => {
                unimplemented!("implement me");
            }
            PublicKeyAlgorithm::ECDH => {
                unimplemented!("implement me");
            }
            PublicKeyAlgorithm::ECDSA => {
                unimplemented!("implement me");
            }
            PublicKeyAlgorithm::EdDSA => {
                unimplemented!("implement me");
            }
            PublicKeyAlgorithm::Elgamal => {
                unimplemented!("implement me");
            }
            _ => panic!("unsupported algoritm: {:?}", self.algorithm),
        }
    }

    fn from_plaintext(&self, plaintext: &[u8]) -> Result<PrivateKeyRepr> {
        match self.algorithm {
            PublicKeyAlgorithm::RSA
            | PublicKeyAlgorithm::RSAEncrypt
            | PublicKeyAlgorithm::RSASign => {
                let (_, (d, p, q, _)) = rsa_private_params(plaintext)?;
                match self.public_params {
                    PublicParams::RSA { ref n, ref e } => {
                        // create an actual openssl key
                        // Sad but true
                        let n = BigNum::from_slice(n.to_vec().as_slice())?;
                        let e = BigNum::from_slice(e.to_vec().as_slice())?;
                        let private_key = RsaPrivateKeyBuilder::new(n, e, d)?
                            .set_factors(p, q)?
                            .build();
                        println!("got a private key :) {:?}", private_key);

                        Ok(PrivateKeyRepr::RSA(private_key))
                    }
                    _ => unreachable!("inconsistent key state"),
                }
            }
            PublicKeyAlgorithm::DSA => {
                unimplemented!("implement me");
            }
            PublicKeyAlgorithm::ECDH => {
                unimplemented!("implement me");
            }
            PublicKeyAlgorithm::ECDSA => {
                let (_, private_key) = ecc_private_params(plaintext)?;

                match self.public_params {
                    PublicParams::ECDSA { ref curve, ref p } => {
                        println!("parsed: {:?}", curve);
                        if let Some(nid) = curve.to_nid() {
                            let group = EcGroup::from_curve_name(nid)?;
                            let mut ctx = BigNumContext::new()?;
                            let pub_point = EcPoint::from_bytes(&group, p, &mut ctx)?;
                            let key =
                                EcKey::from_private_components(&group, &private_key, &pub_point)?;

                            Ok(PrivateKeyRepr::ECDSA(key))
                        } else {
                            panic!("unsupported curve: {:?}", curve);
                        }
                    }
                    _ => unreachable!("inconsistent key state"),
                }
            }
            PublicKeyAlgorithm::EdDSA => {
                unimplemented!("implement me");
            }
            PublicKeyAlgorithm::Elgamal => {
                unimplemented!("implement me");
            }
            _ => panic!("unsupported algoritm: {:?}", self.algorithm),
        }
    }

    pub fn private_params(&self) -> &EncryptedPrivateParams {
        &self.private_params
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
                unimplemented!("implement me please")
            }
        }
    };
}

key!(PublicKey);
key!(PrivateKey);

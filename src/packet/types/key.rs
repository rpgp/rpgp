use super::ecc_curve::ECCCurve;
use super::packet::{KeyVersion, PublicKeyAlgorithm, StringToKeyType, SymmetricKeyAlgorithm};
use errors::Result;
use packet::tags::privkey::rsa_private_params;

/// Represents a single private key packet.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PrivateKey {
    version: KeyVersion,
    algorithm: PublicKeyAlgorithm,
    created_at: u32,
    expiration: Option<u16>,
    public_params: PublicParams,
    private_params: EncryptedPrivateParams,
}

/// Represents a single public key packet.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PublicKey {
    version: KeyVersion,
    algorithm: PublicKeyAlgorithm,
    created_at: u32,
    expiration: Option<u16>,
    public_params: PublicParams,
}

/// Represent the public paramaters for the different algorithms.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PublicParams {
    RSA {
        n: Vec<u8>,
        e: Vec<u8>,
    },
    DSA {
        p: Vec<u8>,
        q: Vec<u8>,
        g: Vec<u8>,
        y: Vec<u8>,
    },
    ECDSA {
        curve: ECCCurve,
        p: Vec<u8>,
    },
    ECDH {
        curve: ECCCurve,
        p: Vec<u8>,
        hash: u8,
        alg_sym: u8,
    },
    Elgamal {
        p: Vec<u8>,
        g: Vec<u8>,
        y: Vec<u8>,
    },
}

/// Represents the private, encrypted paramters for the various algorithms.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PrivateParams {
    RSA {
        /// Secret exponent d
        d: Vec<u8>,
        /// Secret prime value p
        p: Vec<u8>,
        /// Secret prime value q (p < q)
        q: Vec<u8>,
        /// The multiplicative inverse of p, mod q
        u: Vec<u8>,
    },
    DSA {
        /// Secret exponent x.
        x: Vec<u8>,
    },
    ECDSA {},
    ECDH {},
    Elgamal {
        /// Secret exponent x.
        x: Vec<u8>,
    },
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
    /// If raw is encrypted, the params for the string-to-key method.
    pub string_to_key_params: Option<Vec<u8>>,
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
            string_to_key_params: None,
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
    pub fn unlock<'a>(
        &self,
        pw: fn() -> &'a str,
        work: fn(&PrivateParams) -> Result<()>,
    ) -> Result<()> {
        let decrypted = if self.private_params.is_encrypted() {
            self.from_ciphertext(pw, self.private_params.data.as_slice())
        } else {
            self.from_plaintext(self.private_params.data.as_slice())
        }?;

        work(&decrypted)
    }

    fn from_ciphertext<'a>(
        &self,
        _pw: fn() -> &'a str,
        _ciphertext: &[u8],
    ) -> Result<PrivateParams> {
        match self.algorithm {
            PublicKeyAlgorithm::RSA
            | PublicKeyAlgorithm::RSAEncrypt
            | PublicKeyAlgorithm::RSASign => {
                unimplemented!("implement me");
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

    fn from_plaintext(&self, plaintext: &[u8]) -> Result<PrivateParams> {
        match self.algorithm {
            PublicKeyAlgorithm::RSA
            | PublicKeyAlgorithm::RSAEncrypt
            | PublicKeyAlgorithm::RSASign => {
                let (_, (d, p, q, u)) = rsa_private_params(plaintext)?;

                Ok(PrivateParams::RSA { d, p, q, u })
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
        }
    };
}

key!(PublicKey);
key!(PrivateKey);

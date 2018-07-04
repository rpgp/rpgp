use super::ecc_curve::ECCCurve;
use super::packet::{KeyVersion, PublicKeyAlgorithm, StringToKeyType, SymmetricKeyAlgorithm};
use errors::Result;
use packet::tags::privkey::rsa_private_params;

pub trait Key: Sized {
    fn version(&self) -> &KeyVersion;
    fn algorithm(&self) -> &PublicKeyAlgorithm;
}

pub trait PublicParams {}

pub trait PrivateParams
where
    Self: Sized,
{
    fn from_ciphertext<'a>(fn() -> &'a str, &[u8]) -> Result<Self>;

    fn from_plaintext(&[u8]) -> Result<Self>;
}

pub trait PrivateKey: Key {}

pub trait PublicKey: Key {}

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
    pub fn is_encrypted(&self) -> bool {
        self.string_to_key_id != 0
    }
}

macro_rules! key {
    ($name:ident, $priv_name:ident, $pub:ident, $priv:ident) => {
        /// The $name public key
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name {
            version: KeyVersion,
            algorithm: PublicKeyAlgorithm,
            public_params: $pub,
        }

        impl Key for $name {
            fn version(&self) -> &KeyVersion {
                &self.version
            }

            fn algorithm(&self) -> &PublicKeyAlgorithm {
                &self.algorithm
            }
        }

        impl PublicKey for $name {}
        impl $name {
            fn new(
                version: KeyVersion,
                algorithm: PublicKeyAlgorithm,
                public_params: $pub,
            ) -> Self {
                $name {
                    version,
                    algorithm,
                    public_params,
                }
            }
        }

        /// Private thing
        pub struct $priv_name {
            version: KeyVersion,
            algorithm: PublicKeyAlgorithm,
            public_params: $pub,
            private_params: EncryptedPrivateParams,
        }

        impl Key for $priv_name {
            fn version(&self) -> &KeyVersion {
                &self.version
            }

            fn algorithm(&self) -> &PublicKeyAlgorithm {
                &self.algorithm
            }
        }

        impl PrivateKey for $priv_name {}

        impl $priv_name {
            fn new(
                version: KeyVersion,
                algorithm: PublicKeyAlgorithm,
                public_params: $pub,
                private_params: EncryptedPrivateParams,
            ) -> Self {
                $name {
                    version,
                    algorithm,
                    public_params,
                    private_params,
                }
            }

            /// Unlock the raw data in the secret parameters.
            fn unlock<'a>(&self, pw: fn() -> &'a str, work: fn($priv) -> Result<()>) -> Result<()> {
                match self.private_params {
                    Some(ref raw) => {
                        let decrypted = if raw.is_encrypted() {
                            $priv::from_ciphertext(pw, raw)
                        } else {
                            $priv::from_plaintext(pw, raw)
                        }?;

                        work(&decrypted)
                    }
                    None => panic!("not actually a private key, missing the private part"),
                }
            }
        }

        impl PublicParams for $pub {}
    };
}

// -- RSA

key!(RSAPublic, RSAPrivate, RSAPublicParams, RSAPrivateParams);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RSAPublicParams {
    pub n: Vec<u8>,
    pub e: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RSAPrivateParams {
    /// Secret exponent d
    pub d: Vec<u8>,
    /// Secret prime value p
    pub p: Vec<u8>,
    /// Secret prime value q (p < q)
    pub q: Vec<u8>,
    /// The multiplicative inverse of p, mod q
    pub u: Vec<u8>,
}

impl PrivateParams for RSAPrivateParams {
    fn from_ciphertext<'a>(_pw: fn() -> &'a str, _ciphertext: &[u8]) -> Result<Self> {
        unimplemented!("make me");
    }

    fn from_plaintext(plaintext: &[u8]) -> Result<Self> {
        let (_, (d, p, q, u)) = rsa_private_params(plaintext)?;

        Ok(RSAPrivateParams { d, p, q, u })
    }
}

// -- DSA

key!(DSAPublic, DSAPrivate, DSAPublicParams, DSAPrivateParams);
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DSAPublicParams {
    pub p: Vec<u8>,
    pub q: Vec<u8>,
    pub g: Vec<u8>,
    pub y: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DSAPrivateParams {
    /// Secret exponent x.
    pub x: Vec<u8>,
}

impl PrivateParams for DSAPrivateParams {
    fn from_ciphertext<'a>(_pw: fn() -> &'a str, _ciphertext: &[u8]) -> Result<Self> {
        unimplemented!("make me");
    }

    fn from_plaintext(_plaintext: &[u8]) -> Result<Self> {
        unimplemented!("make me");
    }
}

// -- ECDSA

key!(
    ECDSAPublic,
    ECDSAPrivate,
    ECDSAPublicParams,
    ECDSAPrivateParams
);
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ECDSAPublicParams {
    pub curve: ECCCurve,
    pub p: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ECDSAPrivateParams {}

impl PrivateParams for ECDSAPrivateParams {
    fn from_ciphertext<'a>(_pw: fn() -> &'a str, _ciphertext: &[u8]) -> Result<Self> {
        unimplemented!("make me");
    }

    fn from_plaintext(_plaintext: &[u8]) -> Result<Self> {
        unimplemented!("make me");
    }
}

// -- ECDH

key!(ECDHPublic, ECDHPrivate, ECDHPublicParams, ECDHPrivateParams);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ECDHPublicParams {
    pub curve: ECCCurve,
    pub p: Vec<u8>,
    pub hash: u8,
    pub alg_sym: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ECDHPrivateParams {}

impl PrivateParams for ECDHPrivateParams {
    fn from_ciphertext<'a>(_pw: fn() -> &'a str, _ciphertext: &[u8]) -> Result<Self> {
        unimplemented!("make me");
    }

    fn from_plaintext(_plaintext: &[u8]) -> Result<Self> {
        unimplemented!("make me");
    }
}

// -- Elgamal

key!(
    ElgamalPublic,
    ElgamalPrivate,
    ElgamalPublicParams,
    ElgamalPrivateParams
);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElgamalPublicParams {
    pub p: Vec<u8>,
    pub g: Vec<u8>,
    pub y: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElgamalPrivateParams {
    /// Secret exponent x.
    pub x: Vec<u8>,
}

impl PrivateParams for ElgamalPrivateParams {
    fn from_ciphertext<'a>(_pw: fn() -> &'a str, _ciphertext: &[u8]) -> Result<Self> {
        unimplemented!("make me");
    }

    fn from_plaintext(_plaintext: &[u8]) -> Result<Self> {
        unimplemented!("make me");
    }
}

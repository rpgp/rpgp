use super::ecc_curve::ECCCurve;
use super::packet::{KeyVersion, PublicKeyAlgorithm, StringToKeyType, SymmetricKeyAlgorithm};
use errors::Result;
use packet::tags::privkey::rsa_private_params;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Key<T>
where
    T: ::std::fmt::Debug + Clone,
{
    RSA(RSA<T>),
    DSA(DSA<T>),
    ECDSA(ECDSA<T>),
    ECDH(ECDH<T>),
    Elgamal(Elgamal<T>),
}

macro_rules! proxy_call {
    ( $method:ident, $typ:ty ) => {
        pub fn $method(&self) -> $typ {
            match self {
                Key::RSA(k) => k.$method(),
                Key::DSA(k) => k.$method(),
                Key::ECDSA(k) => k.$method(),
                Key::ECDH(k) => k.$method(),
                Key::Elgamal(k) => k.$method(),
            }
        }
    };
}

impl<T> Key<T>
where
    T: ::std::fmt::Debug + Clone,
{
    proxy_call!(version, &KeyVersion);
    proxy_call!(algorithm, &PublicKeyAlgorithm);
}

impl Key<Private> {
    proxy_call!(private_params, &PrivateParams);

    pub fn decrypt<'a>(&mut self, pw: fn() -> &'a str) -> Result<()> {
        match self {
            Key::RSA(k) => k.decrypt(pw),
            Key::DSA(k) => k.decrypt(pw),
            Key::ECDSA(k) => k.decrypt(pw),
            Key::ECDH(k) => k.decrypt(pw),
            Key::Elgamal(k) => k.decrypt(pw),
        }
    }
}

/// A tag type indicating that a key has only public components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Public {}

/// A tag type indicating that a key has only public components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Private {}

pub trait PublicParams {}
pub trait PrivateParams {
    /// Returns all parameter values as a vector.
    fn to_vec(&self) -> Vec<&[u8]>;

    /// Decrypt the raw key data.
    fn decrypt<'a>(&mut self, fn() -> &'a str) -> Result<()>;
}

macro_rules! key {
    ($name:ident, $pub:ident, $priv:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name<T: ::std::fmt::Debug + Clone> {
            version: KeyVersion,
            algorithm: PublicKeyAlgorithm,
            public_params: $pub,
            private_params: Option<$priv>,
            _marker: ::std::marker::PhantomData<T>,
        }

        impl $name<Public> {
            pub fn new(version: KeyVersion, algorithm: PublicKeyAlgorithm, params: $pub) -> Self {
                $name::<Public> {
                    version,
                    algorithm,
                    public_params: params,
                    private_params: None,
                    _marker: ::std::marker::PhantomData,
                }
            }
        }

        impl $name<Private> {
            pub fn new(
                version: KeyVersion,
                algorithm: PublicKeyAlgorithm,
                pub_params: $pub,
                priv_params: $priv,
            ) -> Self {
                $name::<Private> {
                    version,
                    algorithm,
                    public_params: pub_params,
                    private_params: Some(priv_params),
                    _marker: ::std::marker::PhantomData,
                }
            }

            pub fn private_params(&self) -> &$priv {
                // safe to unwrap, because this is a private key
                self.private_params.as_ref().unwrap()
            }

            /// Decrypt the raw data in the secret parameters.
            /// The passed in closure is used to get a password. Just parses the raw values into the struct, if not encrypted.
            pub fn decrypt<'a>(&mut self, pw: fn() -> &'a str) -> Result<()> {
                match self.private_params {
                    Some(ref mut pp) => pp.decrypt(pw),
                    None => {
                        // TODO: should this be an error or a noop?
                        panic!("no data for encyrption")
                    }
                }
            }
        }

        impl<T> $name<T>
        where
            T: ::std::fmt::Debug + Clone,
        {
            pub fn version(&self) -> &KeyVersion {
                &self.version
            }

            pub fn algorithm(&self) -> &PublicKeyAlgorithm {
                &self.algorithm
            }

            pub fn into(self) -> Key<T> {
                // can't define this generic, as only some can be converted
                Key::$name(self)
            }

            pub fn public_params(&self) -> &$pub {
                &self.public_params
            }
        }

        impl PublicParams for $pub {}
    };
}

key!(RSA, RSAPublicParams, RSAPrivateParams);

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
    /// If this key was imported, this holds the raw and possibly encrypted version matching to packets.
    pub raw: Option<EncryptedPrivateParams>,
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
    pub fn is_encrypted(&self) -> bool {
        self.string_to_key_id != 0
    }
}

impl PrivateParams for RSAPrivateParams {
    fn to_vec(&self) -> Vec<&[u8]> {
        vec![&self.d, &self.p, &self.q, &self.u]
    }

    fn decrypt<'a>(&mut self, pw: fn() -> &'a str) -> Result<()> {
        match self.raw {
            Some(ref mut raw) => {
                let decrypted_data = if raw.is_encrypted() {
                    // TODO: actualy decrypt
                    unimplemented!("can not encrypt this yet yet:(");
                } else {
                    raw.data.as_slice()
                };

                let (_, (d, p, q, u)) = rsa_private_params(decrypted_data)?;
                self.d = d;
                self.p = p;
                self.q = q;
                self.u = u;

                Ok(())
            }
            None => panic!("missing raw data to decrypt"),
        }
    }
}

key!(DSA, DSAPublicParams, DSAPrivateParams);
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
    fn to_vec(&self) -> Vec<&[u8]> {
        vec![&self.x]
    }

    fn decrypt<'a>(&mut self, _pw: fn() -> &'a str) -> Result<()> {
        unimplemented!("");
    }
}

key!(ECDSA, ECDSAPublicParams, ECDSAPrivateParams);
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ECDSAPublicParams {
    pub curve: ECCCurve,
    pub p: Vec<u8>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ECDSAPrivateParams {}

impl PrivateParams for ECDSAPrivateParams {
    fn to_vec(&self) -> Vec<&[u8]> {
        vec![]
    }

    fn decrypt<'a>(&mut self, _pw: fn() -> &'a str) -> Result<()> {
        unimplemented!("");
    }
}

key!(ECDH, ECDHPublicParams, ECDHPrivateParams);
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
    fn to_vec(&self) -> Vec<&[u8]> {
        vec![]
    }

    fn decrypt<'a>(&mut self, _pw: fn() -> &'a str) -> Result<()> {
        unimplemented!("");
    }
}

key!(Elgamal, ElgamalPublicParams, ElgamalPrivateParams);
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
    fn to_vec(&self) -> Vec<&[u8]> {
        vec![&self.x]
    }

    fn decrypt<'a>(&mut self, _pw: fn() -> &'a str) -> Result<()> {
        unimplemented!("");
    }
}

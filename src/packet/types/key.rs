use super::ecc_curve::ECCCurve;
use super::packet::{KeyVersion, PublicKeyAlgorithm};

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

impl<T> Key<T>
where
    T: ::std::fmt::Debug + Clone,
{
    pub fn version(&self) -> &KeyVersion {
        match self {
            Key::RSA(k) => k.version(),
            Key::DSA(k) => k.version(),
            Key::ECDSA(k) => k.version(),
            Key::ECDH(k) => k.version(),
            Key::Elgamal(k) => k.version(),
        }
    }

    pub fn algorithm(&self) -> &PublicKeyAlgorithm {
        match self {
            Key::RSA(k) => k.algorithm(),
            Key::DSA(k) => k.algorithm(),
            Key::ECDSA(k) => k.algorithm(),
            Key::ECDH(k) => k.algorithm(),
            Key::Elgamal(k) => k.algorithm(),
        }
    }
}

/// A tag type indicating that a key has only public components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Public {}

/// A tag type indicating that a key has only public components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Private {}

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
        }
    };
}

key!(RSA, RSAPublicParams, RSAPrivateParams);
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RSAPublicParams {
    pub n: Vec<u8>,
    pub e: Vec<u8>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RSAPrivateParams {}

key!(DSA, DSAPublicParams, DSAPrivateParams);
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DSAPublicParams {
    pub p: Vec<u8>,
    pub q: Vec<u8>,
    pub g: Vec<u8>,
    pub y: Vec<u8>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DSAPrivateParams {}

key!(ECDSA, ECDSAPublicParams, ECDSAPrivateParams);
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ECDSAPublicParams {
    pub curve: ECCCurve,
    pub p: Vec<u8>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ECDSAPrivateParams {}

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

key!(Elgamal, ElgamalPublicParams, ElgamalPrivateParams);
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElgamalPublicParams {
    pub p: Vec<u8>,
    pub g: Vec<u8>,
    pub y: Vec<u8>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElgamalPrivateParams {}

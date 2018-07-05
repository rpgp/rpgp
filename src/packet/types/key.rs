use std::ops::Deref;

use super::super::super::byteorder::{BigEndian, ByteOrder};
use super::super::super::openssl::hash::{Hasher, MessageDigest};
use super::ecc_curve::ECCCurve;
use super::packet::Tag::{PublicKey, SecretKey};
use super::packet::{KeyVersion, Packet, PublicKeyAlgorithm, Version};

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

    pub fn creation_time(&self) -> &u32 {
        match self {
            Key::RSA(k) => k.creation_time(),
            Key::DSA(k) => k.creation_time(),
            Key::ECDSA(k) => k.creation_time(),
            Key::ECDH(k) => k.creation_time(),
            Key::Elgamal(k) => k.creation_time(),
        }
    }

    // Ref: https://tools.ietf.org/html/rfc4880.html#section-12.2
    pub fn fingerprint(&self) -> Vec<u8> {
        match self.version() {
            KeyVersion::V4 => {
                // A one-octet version number (4).
                let mut packet = Vec::new();
                packet.push(4);

                // A four-octet number denoting the time that the key was created.
                let mut time_buf: [u8; 4] = [0; 4];
                BigEndian::write_u32(&mut time_buf, *self.creation_time());
                packet.extend_from_slice(&time_buf);

                // A one-octet number denoting the public-key algorithm of this key.
                packet.push(*self.algorithm() as u8);

                // ???
                packet.push(16);
                packet.push(0);

                // A series of multiprecision integers comprising the key material.
                match self {
                    Key::RSA(k) => {
                        packet.extend(&k.public_params.n);
                        packet.extend(&k.public_params.e);
                    }
                    Key::DSA(k) => {
                        packet.extend(&k.public_params.p);
                        packet.extend(&k.public_params.q);
                        packet.extend(&k.public_params.g);
                        packet.extend(&k.public_params.y);
                    }
                    Key::ECDSA(k) => {
                        packet.extend(&k.public_params.curve.oid());
                        packet.extend(&k.public_params.p);
                    }
                    Key::ECDH(k) => {
                        packet.extend(&k.public_params.curve.oid());
                        packet.extend(&k.public_params.p);
                        packet.push(k.public_params.hash);
                        packet.push(k.public_params.alg_sym);
                    }
                    Key::Elgamal(k) => {
                        packet.extend(&k.public_params.p);
                        packet.extend(&k.public_params.g);
                        packet.extend(&k.public_params.y);
                    }
                }

                println!("{:?}", packet);

                let mut length_buf: [u8; 2] = [0; 2];
                BigEndian::write_uint(&mut length_buf, packet.len() as u64, 2);

                let mut h = Hasher::new(MessageDigest::sha1()).unwrap();

                h.update(&[0x99]).unwrap();
                h.update(&length_buf).unwrap();
                h.update(&packet).unwrap();

                h.finish().unwrap().deref().to_vec()
            }

            KeyVersion::V2 | KeyVersion::V3 => {
                let mut h = Hasher::new(MessageDigest::md5()).unwrap();

                let mut packet = Vec::new();

                match self {
                    Key::RSA(k) => {
                        packet.extend(&k.public_params.n);
                        packet.extend(&k.public_params.e);
                    }
                    Key::DSA(k) => {
                        packet.extend(&k.public_params.p);
                        packet.extend(&k.public_params.q);
                        packet.extend(&k.public_params.g);
                        packet.extend(&k.public_params.y);
                    }
                    Key::ECDSA(k) => {
                        packet.extend(&k.public_params.curve.oid());
                        packet.extend(&k.public_params.p);
                    }
                    Key::ECDH(k) => {
                        packet.extend(&k.public_params.curve.oid());
                        packet.extend(&k.public_params.p);
                        packet.push(k.public_params.hash);
                        packet.push(k.public_params.alg_sym);
                    }
                    Key::Elgamal(k) => {
                        packet.extend(&k.public_params.p);
                        packet.extend(&k.public_params.g);
                        packet.extend(&k.public_params.y);
                    }
                }

                h.update(&packet).unwrap();

                h.finish().unwrap().deref().to_vec()
            }
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
            creation_time: u32,
            algorithm: PublicKeyAlgorithm,
            public_params: $pub,
            private_params: Option<$priv>,
            _marker: ::std::marker::PhantomData<T>,
        }

        impl $name<Public> {
            pub fn new(
                version: KeyVersion,
                creation_time: u32,
                algorithm: PublicKeyAlgorithm,
                params: $pub,
            ) -> Self {
                $name::<Public> {
                    version,
                    creation_time,
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
                creation_time: u32,
                algorithm: PublicKeyAlgorithm,
                pub_params: $pub,
                priv_params: $priv,
            ) -> Self {
                $name::<Private> {
                    version,
                    creation_time,
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

            pub fn creation_time(&self) -> &u32 {
                &self.creation_time
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

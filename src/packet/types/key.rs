use std::ops::Deref;

use super::super::super::byteorder::{BigEndian, ByteOrder};
use super::super::super::openssl::hash::{Hasher, MessageDigest};
use super::ecc_curve::ECCCurve;
use super::packet::Tag::{PublicKey, SecretKey};
use super::packet::{KeyVersion, Packet, PublicKeyAlgorithm, Version};

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
            _ => panic!("unsupported algoritm: {:?}", self.algorithm),
        }
    }

    fn from_plaintext(&self, plaintext: &[u8]) -> Result<PrivateParams> {
        match self.algorithm {
            PublicKeyAlgorithm::RSA
            | PublicKeyAlgorithm::RSAEncrypt
            | PublicKeyAlgorithm::RSASign => {
                let (_, (d, p, q, u)) = rsa_private_params(plaintext)?;

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

            pub fn creation_time(&self) -> &u32 {
                &self.creation_time
            }

            pub fn algorithm(&self) -> &PublicKeyAlgorithm {
                &self.algorithm
            }

            pub fn created_at(&self) -> u32 {
                self.created_at
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

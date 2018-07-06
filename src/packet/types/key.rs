use byteorder::{BigEndian, ByteOrder};
use openssl::bn::BigNum;
use openssl::dsa::Dsa;
use openssl::hash::{Hasher, MessageDigest};
use openssl::pkey;
use openssl::rsa::{Rsa, RsaPrivateKeyBuilder};

use std::ops::Deref;

use super::ecc_curve::ECCCurve;
use super::packet::{KeyVersion, PublicKeyAlgorithm, StringToKeyType, SymmetricKeyAlgorithm};
use errors::Result;
use packet::tags::privkey::rsa_private_params;

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
        p: BigNum,
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

/// this is the version of the private key that is actually exposed to users to
/// do crypto operations.
#[derive(Debug)]
pub enum PrivateKeyRepr {
    RSA(Rsa<pkey::Private>),
    DSA(Dsa<pkey::Private>),
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
        work: fn(&PrivateKeyRepr) -> Result<()>,
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
    ) -> Result<PrivateKeyRepr> {
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

    fn from_plaintext(&self, plaintext: &[u8]) -> Result<PrivateKeyRepr> {
        match self.algorithm {
            PublicKeyAlgorithm::RSA
            | PublicKeyAlgorithm::RSAEncrypt
            | PublicKeyAlgorithm::RSASign => {
                let (_, (d, p, q, u)) = rsa_private_params(plaintext)?;
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

                        // ???
                        packet.push(16);
                        packet.push(0);

                        // A series of multiprecision integers comprising the key material.
                        match &self.public_params {
                            PublicParams::RSA { n, e } => {
                                packet.extend(n.to_vec().iter().cloned());

                                // ???
                                packet.push(0);
                                packet.push(17);

                                packet.extend(e.to_vec().iter().cloned());
                            }
                            PublicParams::DSA { p, q, g, y } => {
                                packet.extend(p.to_vec().iter().cloned());
                                packet.extend(q.to_vec().iter().cloned());
                                packet.extend(g.to_vec().iter().cloned());
                                packet.extend(y.to_vec().iter().cloned());
                            }
                            PublicParams::ECDSA { curve, p } => {
                                packet.extend(curve.oid().iter().cloned());
                                packet.extend(p.to_vec().iter().cloned());
                            }
                            PublicParams::ECDH {
                                curve,
                                p,
                                hash,
                                alg_sym,
                            } => {
                                packet.extend(curve.oid().iter().cloned());
                                packet.extend(p.to_vec().iter().cloned());
                                packet.push(*hash);
                                packet.push(*alg_sym);
                            }
                            PublicParams::Elgamal { p, g, y } => {
                                packet.extend(p.to_vec().iter().cloned());
                                packet.extend(g.to_vec().iter().cloned());
                                packet.extend(y.to_vec().iter().cloned());
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

                        /*
                                match self {
                                    PublicKeyAlgorithm::RSA(k) => {
                                        packet.extend(&k.public_params.n);
                                        packet.extend(&k.public_params.e);
                                    }
                                    PublicKeyAlgorithm::DSA(k) => {
                                        packet.extend(&k.public_params.p);
                                        packet.extend(&k.public_params.q);
                                        packet.extend(&k.public_params.g);
                                        packet.extend(&k.public_params.y);
                                    }
                                    PublicKeyAlgorithm::ECDSA(k) => {
                                        packet.extend(&k.public_params.curve.oid());
                                        packet.extend(&k.public_params.p);
                                    }
                                    PublicKeyAlgorithm::ECDH(k) => {
                                        packet.extend(&k.public_params.curve.oid());
                                        packet.extend(&k.public_params.p);
                                        packet.push(k.public_params.hash);
                                        packet.push(k.public_params.alg_sym);
                                    }
                                    PublicKeyAlgorithm::Elgamal(k) => {
                                        packet.extend(&k.public_params.p);
                                        packet.extend(&k.public_params.g);
                                        packet.extend(&k.public_params.y);
                                    }
                                }
                                */
                        h.update(&packet).unwrap();

                        h.finish().unwrap().deref().to_vec()
                    }
                }
            }
        }
    };
}

key!(PublicKey);
key!(PrivateKey);

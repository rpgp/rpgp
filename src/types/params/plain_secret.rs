use std::hash::Hasher;
use std::io;

use byteorder::{BigEndian, ByteOrder};
use nom::combinator::map;
use nom::sequence::tuple;
use rsa::RsaPrivateKey;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::checksum;
use crate::crypto::ecc_curve::ECCCurve;
use crate::crypto::public_key::PublicKeyAlgorithm;
use crate::errors::{IResult, Result};
use crate::ser::Serialize;
use crate::types::*;
use crate::util::TeeWriter;

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop, derive_more::Debug)]
pub enum PlainSecretParams {
    RSA {
        #[debug("..")]
        d: Mpi,
        #[debug("..")]
        p: Mpi,
        #[debug("..")]
        q: Mpi,
        #[debug("..")]
        u: Mpi,
    },
    DSA(#[debug("..")] Mpi),
    ECDSA(#[debug("..")] Mpi),
    ECDH(#[debug("..")] Mpi),
    Elgamal(#[debug("..")] Mpi),
    EdDSALegacy(#[debug("..")] Mpi),
}

#[derive(Clone, PartialEq, Eq, derive_more::Debug)]
pub enum PlainSecretParamsRef<'a> {
    RSA {
        #[debug("..")]
        d: MpiRef<'a>,
        #[debug("..")]
        p: MpiRef<'a>,
        #[debug("..")]
        q: MpiRef<'a>,
        #[debug("..")]
        u: MpiRef<'a>,
    },
    DSA(#[debug("..")] MpiRef<'a>),
    ECDSA(#[debug("..")] MpiRef<'a>),
    ECDH(#[debug("..")] MpiRef<'a>),
    Elgamal(#[debug("..")] MpiRef<'a>),
    EdDSALegacy(#[debug("..")] MpiRef<'a>),
}

impl<'a> PlainSecretParamsRef<'a> {
    pub fn to_owned(&self) -> PlainSecretParams {
        match self {
            PlainSecretParamsRef::RSA { d, p, q, u } => PlainSecretParams::RSA {
                d: (*d).to_owned(),
                p: (*p).to_owned(),
                q: (*q).to_owned(),
                u: (*u).to_owned(),
            },
            PlainSecretParamsRef::DSA(v) => PlainSecretParams::DSA((*v).to_owned()),
            PlainSecretParamsRef::ECDSA(v) => PlainSecretParams::ECDSA((*v).to_owned()),
            PlainSecretParamsRef::ECDH(v) => PlainSecretParams::ECDH((*v).to_owned()),
            PlainSecretParamsRef::Elgamal(v) => PlainSecretParams::Elgamal((*v).to_owned()),
            PlainSecretParamsRef::EdDSALegacy(v) => PlainSecretParams::EdDSALegacy((*v).to_owned()),
        }
    }

    pub fn string_to_key_id(&self) -> u8 {
        0
    }

    fn to_writer_raw<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            PlainSecretParamsRef::RSA { d, p, q, u } => {
                (*d).to_writer(writer)?;
                (*p).to_writer(writer)?;
                (*q).to_writer(writer)?;
                (*u).to_writer(writer)?;
            }
            PlainSecretParamsRef::DSA(x) => {
                (*x).to_writer(writer)?;
            }
            PlainSecretParamsRef::ECDSA(x) => {
                (*x).to_writer(writer)?;
            }
            PlainSecretParamsRef::ECDH(x) => {
                (*x).to_writer(writer)?;
            }
            PlainSecretParamsRef::Elgamal(d) => {
                (*d).to_writer(writer)?;
            }
            PlainSecretParamsRef::EdDSALegacy(x) => {
                (*x).to_writer(writer)?;
            }
        }

        Ok(())
    }

    pub fn compare_checksum_simple(&self, other: Option<&[u8]>) -> Result<()> {
        if let Some(other) = other {
            let mut hasher = checksum::SimpleChecksum::default();
            self.to_writer_raw(&mut hasher)?;
            ensure_eq!(
                BigEndian::read_u16(other),
                hasher.finish() as u16,
                "Invalid checksum"
            );
            Ok(())
        } else {
            bail!("Missing checksum");
        }
    }

    pub fn checksum_simple(&self) -> Vec<u8> {
        let mut hasher = checksum::SimpleChecksum::default();
        self.to_writer_raw(&mut hasher).expect("known write target");
        hasher.finalize().to_vec()
    }

    /// Uses sha1_checked
    pub fn checksum_sha1(&self) -> Result<[u8; 20]> {
        let mut buf = Vec::new();
        self.to_writer_raw(&mut buf).expect("known write target");
        checksum::calculate_sha1([&buf])
    }

    fn pad_key<const SIZE: usize>(val: &[u8]) -> Result<[u8; SIZE]> {
        ensure!(val.len() <= SIZE, "invalid secret key size");

        let mut key = [0u8; SIZE];
        key[SIZE - val.len()..].copy_from_slice(val);
        Ok(key)
    }

    pub fn as_repr(&self, public_params: &PublicParams) -> Result<SecretKeyRepr> {
        match self {
            PlainSecretParamsRef::RSA { d, p, q, .. } => match public_params {
                PublicParams::RSA { ref n, ref e } => {
                    let secret_key = RsaPrivateKey::from_components(
                        n.into(),
                        e.into(),
                        d.into(),
                        vec![p.into(), q.into()],
                    )?;
                    secret_key.validate()?;
                    Ok(SecretKeyRepr::RSA(crate::crypto::rsa::PrivateKey(
                        secret_key,
                    )))
                }
                _ => unreachable!("inconsistent key state"),
            },
            PlainSecretParamsRef::ECDH(d) => match public_params {
                PublicParams::ECDH {
                    ref curve,
                    ref hash,
                    ref alg_sym,
                    ..
                } => match curve {
                    ECCCurve::Curve25519 => {
                        const SIZE: usize = ECCCurve::Curve25519.secret_key_length();

                        Ok(SecretKeyRepr::ECDH(
                            crate::crypto::ecdh::SecretKey::Curve25519 {
                                secret: Self::pad_key::<SIZE>(d)?,
                                hash: *hash,
                                alg_sym: *alg_sym,
                            },
                        ))
                    }
                    ECCCurve::P256 => {
                        const SIZE: usize = ECCCurve::P256.secret_key_length();

                        Ok(SecretKeyRepr::ECDH(crate::crypto::ecdh::SecretKey::P256 {
                            secret: Self::pad_key::<SIZE>(d)?,
                            hash: *hash,
                            alg_sym: *alg_sym,
                        }))
                    }
                    ECCCurve::P384 => {
                        const SIZE: usize = ECCCurve::P384.secret_key_length();

                        Ok(SecretKeyRepr::ECDH(crate::crypto::ecdh::SecretKey::P384 {
                            secret: Self::pad_key::<SIZE>(d)?,
                            hash: *hash,
                            alg_sym: *alg_sym,
                        }))
                    }
                    ECCCurve::P521 => {
                        const SIZE: usize = ECCCurve::P521.secret_key_length();

                        Ok(SecretKeyRepr::ECDH(crate::crypto::ecdh::SecretKey::P521 {
                            secret: Self::pad_key::<SIZE>(d)?,
                            hash: *hash,
                            alg_sym: *alg_sym,
                        }))
                    }
                    _ => unsupported_err!("curve {:?} for ECDH", curve.to_string()),
                },
                _ => unreachable!("inconsistent key state"),
            },
            PlainSecretParamsRef::EdDSALegacy(d) => match public_params {
                PublicParams::EdDSALegacy { ref curve, .. } => match *curve {
                    ECCCurve::Ed25519 => {
                        const SIZE: usize = ECCCurve::Ed25519.secret_key_length();

                        Ok(SecretKeyRepr::EdDSA(crate::crypto::eddsa::SecretKey {
                            oid: curve.oid(),
                            secret: Self::pad_key::<SIZE>(d)?,
                        }))
                    }
                    _ => unsupported_err!("curve {:?} for EdDSA", curve.to_string()),
                },
                _ => unreachable!("inconsistent key state"),
            },
            PlainSecretParamsRef::DSA(x) => Ok(SecretKeyRepr::DSA(crate::crypto::dsa::SecretKey {
                x: x.into(),
            })),
            PlainSecretParamsRef::Elgamal(_) => {
                unimplemented_err!("Elgamal");
            }
            PlainSecretParamsRef::ECDSA(d) => match public_params {
                PublicParams::ECDSA(params) => match params {
                    EcdsaPublicParams::P256 { .. } => {
                        let secret = p256::SecretKey::from_slice(d.as_bytes())?;

                        Ok(SecretKeyRepr::ECDSA(crate::crypto::ecdsa::SecretKey::P256(
                            secret,
                        )))
                    }
                    EcdsaPublicParams::P384 { .. } => {
                        let secret = p384::SecretKey::from_slice(d.as_bytes())?;

                        Ok(SecretKeyRepr::ECDSA(crate::crypto::ecdsa::SecretKey::P384(
                            secret,
                        )))
                    }
                    EcdsaPublicParams::P521 { .. } => {
                        let secret = p521::SecretKey::from_slice(d.as_bytes())?;

                        Ok(SecretKeyRepr::ECDSA(crate::crypto::ecdsa::SecretKey::P521(
                            secret,
                        )))
                    }
                    EcdsaPublicParams::Secp256k1 { .. } => {
                        let secret = k256::SecretKey::from_slice(d.as_bytes())?;

                        Ok(SecretKeyRepr::ECDSA(
                            crate::crypto::ecdsa::SecretKey::Secp256k1(secret),
                        ))
                    }
                    EcdsaPublicParams::Unsupported { curve, .. } => {
                        unsupported_err!("curve {:?} for ECDSA", curve.to_string())
                    }
                },
                _ => unreachable!("inconsistent key state"),
            },
        }
    }
}

impl PlainSecretParams {
    pub fn from_slice(
        data: &[u8],
        alg: PublicKeyAlgorithm,
        _params: &PublicParams,
    ) -> Result<Self> {
        let (_, repr) = parse_secret_params(alg)(data)?;
        Ok(repr)
    }

    pub fn string_to_key_id(&self) -> u8 {
        self.as_ref().string_to_key_id()
    }

    pub fn checksum_simple(&self) -> Vec<u8> {
        self.as_ref().checksum_simple()
    }

    /// Uses sha1_checked
    pub fn checksum_sha1(&self) -> Result<[u8; 20]> {
        self.as_ref().checksum_sha1()
    }

    pub fn as_ref(&self) -> PlainSecretParamsRef<'_> {
        match self {
            PlainSecretParams::RSA { d, p, q, u } => PlainSecretParamsRef::RSA {
                d: d.as_ref(),
                p: p.as_ref(),
                q: q.as_ref(),
                u: u.as_ref(),
            },
            PlainSecretParams::DSA(v) => PlainSecretParamsRef::DSA(v.as_ref()),
            PlainSecretParams::ECDSA(v) => PlainSecretParamsRef::ECDSA(v.as_ref()),
            PlainSecretParams::ECDH(v) => PlainSecretParamsRef::ECDH(v.as_ref()),
            PlainSecretParams::Elgamal(v) => PlainSecretParamsRef::Elgamal(v.as_ref()),
            PlainSecretParams::EdDSALegacy(v) => PlainSecretParamsRef::EdDSALegacy(v.as_ref()),
        }
    }

    pub fn encrypt(
        self,
        passphrase: &str,
        s2k_params: S2kParams,
        version: KeyVersion,
    ) -> Result<EncryptedSecretParams> {
        match &s2k_params {
            S2kParams::Unprotected => bail!("cannot encrypt to uprotected"),
            S2kParams::Cfb { sym_alg, s2k, iv } => {
                let key = s2k.derive_key(passphrase, sym_alg.key_size())?;
                let enc_data = match version {
                    KeyVersion::V2 => unsupported_err!("Encryption for V2 keys is not available"),
                    KeyVersion::V3 => unimplemented_err!("v3 encryption"),
                    KeyVersion::V4 => {
                        let mut data = Vec::new();
                        self.as_ref()
                            .to_writer_raw(&mut data)
                            .expect("preallocated vector");

                        data.extend_from_slice(&self.checksum_sha1()?[..]);
                        sym_alg.encrypt_with_iv_regular(&key, iv, &mut data)?;

                        data
                    }
                    KeyVersion::V5 => unimplemented_err!("v5 encryption"),
                    KeyVersion::Other(v) => unimplemented_err!("encryption for key version {}", v),
                };

                Ok(EncryptedSecretParams::new(enc_data, s2k_params))
            }
            _ => unimplemented_err!("{:?} not implemented yet", s2k_params),
        }
    }
}

impl Serialize for PlainSecretParams {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        self.as_ref().to_writer(writer)
    }
}

impl<'a> Serialize for PlainSecretParamsRef<'a> {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&[self.string_to_key_id()])?;
        let mut hasher = checksum::SimpleChecksum::default();
        {
            let mut tee = TeeWriter::new(&mut hasher, writer);
            self.to_writer_raw(&mut tee)?;
        }
        hasher.to_writer(writer)?;

        Ok(())
    }
}

fn parse_secret_params(
    alg: PublicKeyAlgorithm,
) -> impl Fn(&[u8]) -> IResult<&[u8], PlainSecretParams> {
    move |i: &[u8]| match alg {
        PublicKeyAlgorithm::RSA | PublicKeyAlgorithm::RSAEncrypt | PublicKeyAlgorithm::RSASign => {
            rsa_secret_params(i)
        }
        PublicKeyAlgorithm::DSA => map(mpi, |m| PlainSecretParams::DSA(m.to_owned()))(i),
        PublicKeyAlgorithm::Elgamal => map(mpi, |m| PlainSecretParams::Elgamal(m.to_owned()))(i),
        PublicKeyAlgorithm::ECDH => map(mpi, |m| PlainSecretParams::ECDH(m.to_owned()))(i),
        PublicKeyAlgorithm::ECDSA => map(mpi, |m| PlainSecretParams::ECDSA(m.to_owned()))(i),
        PublicKeyAlgorithm::EdDSALegacy => {
            map(mpi, |m| PlainSecretParams::EdDSALegacy(m.to_owned()))(i)
        }
        _ => Err(nom::Err::Error(crate::errors::Error::ParsingError(
            nom::error::ErrorKind::Switch,
        ))),
    }
}

// Parse the decrpyted private params of an RSA private key.
fn rsa_secret_params(i: &[u8]) -> IResult<&[u8], PlainSecretParams> {
    map(tuple((mpi, mpi, mpi, mpi)), |(d, p, q, u)| {
        PlainSecretParams::RSA {
            d: d.to_owned(),
            p: p.to_owned(),
            q: q.to_owned(),
            u: u.to_owned(),
        }
    })(i)
}

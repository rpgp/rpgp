use std::hash::Hasher;
use std::{fmt, io};

use byteorder::{BigEndian, ByteOrder};
use nom::combinator::map;
use nom::sequence::tuple;
use rand::{CryptoRng, Rng};
use rsa::RsaPrivateKey;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::checksum;
use crate::crypto::ecc_curve::ECCCurve;
use crate::crypto::public_key::PublicKeyAlgorithm;
use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::errors::{IResult, Result};
use crate::ser::Serialize;
use crate::types::*;
use crate::util::TeeWriter;

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub enum PlainSecretParams {
    RSA { d: Mpi, p: Mpi, q: Mpi, u: Mpi },
    DSA(Mpi),
    ECDSA(Mpi),
    ECDH(Mpi),
    Elgamal(Mpi),
    EdDSA(Mpi),
}

#[derive(Clone, PartialEq, Eq)]
pub enum PlainSecretParamsRef<'a> {
    RSA {
        d: MpiRef<'a>,
        p: MpiRef<'a>,
        q: MpiRef<'a>,
        u: MpiRef<'a>,
    },
    DSA(MpiRef<'a>),
    ECDSA(MpiRef<'a>),
    ECDH(MpiRef<'a>),
    Elgamal(MpiRef<'a>),
    EdDSA(MpiRef<'a>),
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
            PlainSecretParamsRef::EdDSA(v) => PlainSecretParams::EdDSA((*v).to_owned()),
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
                (*x).strip_trailing_zeroes().to_writer(writer)?;
            }
            PlainSecretParamsRef::ECDH(x) => {
                (*x).to_writer(writer)?;
            }
            PlainSecretParamsRef::Elgamal(d) => {
                (*d).to_writer(writer)?;
            }
            PlainSecretParamsRef::EdDSA(x) => {
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

    pub fn checksum_sha1(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.to_writer_raw(&mut buf).expect("known write target");
        checksum::calculate_sha1([&buf])
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
                    Ok(SecretKeyRepr::RSA(secret_key))
                }
                _ => unreachable!("inconsistent key state"),
            },
            PlainSecretParamsRef::ECDH(d) => match public_params {
                PublicParams::ECDH {
                    ref curve,
                    ref hash,
                    ref alg_sym,
                    ..
                } => match *curve {
                    ECCCurve::Curve25519 => {
                        ensure!(d.len() <= 32, "invalid secret");

                        let mut secret = [0u8; 32];
                        secret[32 - d.len()..].copy_from_slice(d.as_bytes());

                        Ok(SecretKeyRepr::ECDH(ECDHSecretKey {
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
            PlainSecretParamsRef::EdDSA(d) => match public_params {
                PublicParams::EdDSA { ref curve, .. } => match *curve {
                    ECCCurve::Ed25519 => {
                        ensure!(d.len() <= 32, "invalid secret");

                        let mut secret = [0u8; 32];
                        secret[32 - d.len()..].copy_from_slice(d.as_bytes());

                        Ok(SecretKeyRepr::EdDSA(EdDSASecretKey {
                            oid: curve.oid(),
                            secret,
                        }))
                    }
                    _ => unsupported_err!("curve {:?} for EdDSA", curve.to_string()),
                },
                _ => unreachable!("inconsistent key state"),
            },
            PlainSecretParamsRef::DSA(_) => {
                unimplemented_err!("DSA");
            }
            PlainSecretParamsRef::Elgamal(_) => {
                unimplemented_err!("Elgamal");
            }
            PlainSecretParamsRef::ECDSA(d) => match public_params {
                PublicParams::ECDSA(params) => match params {
                    EcdsaPublicParams::P256 { .. } => {
                        let secret = p256::SecretKey::from_slice(d.as_bytes())?;

                        Ok(SecretKeyRepr::ECDSA(ECDSASecretKey::P256(secret)))
                    }
                    EcdsaPublicParams::P384 { .. } => {
                        let secret = p384::SecretKey::from_slice(d.as_bytes())?;

                        Ok(SecretKeyRepr::ECDSA(ECDSASecretKey::P384(secret)))
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
    pub fn from_slice(data: &[u8], alg: PublicKeyAlgorithm, params: &PublicParams) -> Result<Self> {
        let (_, mut repr) = parse_secret_params(alg)(data)?;
        repr.normalize(params);
        Ok(repr)
    }

    /// Normalize internal storage.
    #[allow(clippy::single_match)]
    fn normalize(&mut self, params: &PublicParams) {
        match (self, params) {
            (PlainSecretParams::ECDSA(secret_mpi), PublicParams::ECDSA(pub_params)) => {
                // ECDSA varies in its storage of padded vs unpadded.
                // This normalizes it to store the padded version in memory.
                if let Some(len) = pub_params.secret_key_length() {
                    secret_mpi.pad_right(len);
                }
            }
            _ => {}
        }
    }

    pub fn string_to_key_id(&self) -> u8 {
        self.as_ref().string_to_key_id()
    }

    pub fn checksum_simple(&self) -> Vec<u8> {
        self.as_ref().checksum_simple()
    }

    pub fn checksum_sha1(&self) -> Vec<u8> {
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
            PlainSecretParams::EdDSA(v) => PlainSecretParamsRef::EdDSA(v.as_ref()),
        }
    }

    pub fn encrypt<R: CryptoRng + Rng>(
        self,
        rng: &mut R,
        passphrase: &str,
        alg: SymmetricKeyAlgorithm,
        s2k: StringToKey,
        version: KeyVersion,
        id: u8,
    ) -> Result<EncryptedSecretParams> {
        let key = s2k.derive_key(passphrase, alg.key_size())?;
        let mut iv = vec![0u8; alg.block_size()];
        rng.fill(&mut iv[..]);

        let enc_data = match version {
            KeyVersion::V2 => unsupported_err!("Encryption for V2 keys is not available"),
            KeyVersion::V3 => unimplemented_err!("v3 encryption"),
            KeyVersion::V4 => {
                let mut data = Vec::new();
                self.as_ref()
                    .to_writer_raw(&mut data)
                    .expect("preallocated vector");
                match id {
                    254 => {
                        data.extend_from_slice(&self.checksum_sha1()[..]);
                    }
                    _ => unimplemented_err!("id: {} not implemented yet", id),
                }

                alg.encrypt_with_iv_regular(&key, &iv, &mut data)?;

                data
            }
            KeyVersion::V5 => unimplemented_err!("v5 encryption"),
        };

        Ok(EncryptedSecretParams::new(enc_data, iv, alg, s2k, id))
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

impl fmt::Debug for PlainSecretParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_ref().fmt(f)
    }
}

impl<'a> fmt::Debug for PlainSecretParamsRef<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlainSecretParamsRef::RSA { .. } => write!(f, "PlainSecretParams(RSA)"),
            PlainSecretParamsRef::DSA(_) => write!(f, "PlainSecretParams(DSA)"),
            PlainSecretParamsRef::Elgamal(_) => write!(f, "PlainSecretParams(Elgamal)"),
            PlainSecretParamsRef::ECDSA(x) => {
                write!(f, "PlainSecretParams(ECDSA {})", hex::encode(x.as_bytes()))
            }
            PlainSecretParamsRef::ECDH(_) => write!(f, "PlainSecretParams(ECDH)"),
            PlainSecretParamsRef::EdDSA(_) => write!(f, "PlainSecretParams(EdDSA)"),
        }
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
        PublicKeyAlgorithm::EdDSA => map(mpi, |m| PlainSecretParams::EdDSA(m.to_owned()))(i),
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

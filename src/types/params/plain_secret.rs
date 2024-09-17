use std::hash::Hasher;
use std::io;

use byteorder::{BigEndian, ByteOrder};
use hkdf::Hkdf;
use nom::combinator::map;
use nom::sequence::tuple;
use rsa::RsaPrivateKey;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::aead::AeadAlgorithm;
use crate::crypto::checksum;
use crate::crypto::ecc_curve::ECCCurve;
use crate::crypto::public_key::PublicKeyAlgorithm;
use crate::crypto::sym::SymmetricKeyAlgorithm;
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
    Ed25519(#[debug("..")] [u8; 32]),
    X25519(#[debug("..")] [u8; 32]),
    X448(#[debug("..")] [u8; 56]),
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
    Ed25519(#[debug("..")] &'a [u8; 32]),
    X25519(#[debug("..")] &'a [u8; 32]),
    X448(#[debug("..")] &'a [u8; 56]),
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
            PlainSecretParamsRef::Ed25519(s) => PlainSecretParams::Ed25519((*s).to_owned()),
            PlainSecretParamsRef::X25519(s) => PlainSecretParams::X25519((*s).to_owned()),
            PlainSecretParamsRef::X448(s) => PlainSecretParams::X448((*s).to_owned()),
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
            PlainSecretParamsRef::Ed25519(s) => {
                writer.write_all(&s[..])?;
            }
            PlainSecretParamsRef::X25519(s) => {
                writer.write_all(&s[..])?;
            }
            PlainSecretParamsRef::X448(s) => {
                writer.write_all(&s[..])?;
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
            PlainSecretParamsRef::Ed25519(d) => {
                Ok(SecretKeyRepr::EdDSA(crate::crypto::eddsa::SecretKey {
                    oid: ECCCurve::Ed25519.oid(),
                    secret: **d,
                }))
            }
            PlainSecretParamsRef::X25519(d) => {
                Ok(SecretKeyRepr::X25519(crate::crypto::x25519::SecretKey {
                    secret: **d,
                }))
            }
            PlainSecretParamsRef::X448(d) => {
                Ok(SecretKeyRepr::X448(crate::crypto::x448::SecretKey {
                    secret: **d,
                }))
            }
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
            PlainSecretParams::Ed25519(s) => PlainSecretParamsRef::Ed25519(s),
            PlainSecretParams::X25519(s) => PlainSecretParamsRef::X25519(s),
            PlainSecretParams::X448(s) => PlainSecretParamsRef::X448(s),
        }
    }

    pub fn encrypt(
        &self,
        passphrase: &str,
        s2k_params: S2kParams,
        pub_key: &(impl PublicKeyTrait + Serialize),
        secret_tag: Option<Tag>,
    ) -> Result<EncryptedSecretParams> {
        let version = pub_key.version();

        match &s2k_params {
            S2kParams::Unprotected => bail!("cannot encrypt to unprotected"),
            S2kParams::Cfb { sym_alg, s2k, iv } => {
                // An implementation MUST NOT create [..] any Secret Key packet where the S2K usage
                // octet is not AEAD (253) and the S2K Specifier Type is Argon2.
                ensure!(
                    !matches!(s2k, StringToKey::Argon2 { .. }),
                    "Argon2 not allowed with Cfb"
                );

                let key = s2k.derive_key(passphrase, sym_alg.key_size())?;
                let enc_data = match version {
                    KeyVersion::V2 | KeyVersion::V3 => {
                        unimplemented_err!("Encryption for V2/V3 keys is not available")
                    }
                    KeyVersion::V4 | KeyVersion::V6 => {
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
            S2kParams::Aead {
                sym_alg,
                aead_mode,
                s2k,
                nonce,
            } => {
                let key = s2k.derive_key(passphrase, sym_alg.key_size())?;

                let enc_data = match version {
                    KeyVersion::V2 | KeyVersion::V3 => {
                        unimplemented_err!("Encryption for V2/V3 keys is not available")
                    }
                    KeyVersion::V4 | KeyVersion::V6 => {
                        let mut data = Vec::new();
                        self.as_ref()
                            .to_writer_raw(&mut data)
                            .expect("preallocated vector");

                        let Some(secret_tag) = secret_tag else {
                            bail!("no secret_tag provided");
                        };

                        let (okm, ad) =
                            s2k_usage_aead(&key, secret_tag, pub_key, *sym_alg, *aead_mode)?;

                        // AEAD encrypt
                        let tag =
                            aead_mode.encrypt_in_place(sym_alg, &okm, nonce, &ad, &mut data)?;

                        // append tag to now encrypted secret params
                        data.extend_from_slice(&tag);

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

    pub fn to_writer<W: io::Write>(&self, writer: &mut W, version: KeyVersion) -> Result<()> {
        writer.write_all(&[self.string_to_key_id()])?;

        let mut hasher = checksum::SimpleChecksum::default();
        {
            let mut tee = TeeWriter::new(&mut hasher, writer);
            self.as_ref().to_writer_raw(&mut tee)?;
        }

        if version == KeyVersion::V3 || version == KeyVersion::V4 {
            // Only for a version 3 or 4 packet where the string-to-key usage octet is zero, a
            // two-octet checksum of the algorithm-specific portion (sum of all octets, mod 65536).
            //
            // https://www.rfc-editor.org/rfc/rfc9580.html#section-5.5.3-3.6.1
            hasher.to_writer(writer)?;
        }

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
        PublicKeyAlgorithm::Ed25519 => {
            let (i, s) = nom::bytes::complete::take(32u8)(i)?;
            Ok((i, PlainSecretParams::Ed25519(s.try_into().expect("32"))))
        }
        PublicKeyAlgorithm::X25519 => {
            let (i, s) = nom::bytes::complete::take(32u8)(i)?;
            Ok((i, PlainSecretParams::X25519(s.try_into().expect("32"))))
        }
        PublicKeyAlgorithm::X448 => {
            let (i, s) = nom::bytes::complete::take(56u8)(i)?;
            Ok((i, PlainSecretParams::X448(s.try_into().expect("56"))))
        }
        _ => Err(nom::Err::Error(crate::errors::Error::ParsingError(
            nom::error::ErrorKind::Switch,
        ))),
    }
}

// Parse the decrypted private params of an RSA private key.
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

/// Derive output keying material and associated data for the s2k usage method AEAD.
///
/// https://www.rfc-editor.org/rfc/rfc9580.html#name-secret-key-packet-formats
pub(crate) fn s2k_usage_aead(
    derived: &[u8],
    secret_tag: Tag,
    pub_key: &(impl PublicKeyTrait + Serialize),
    sym_alg: SymmetricKeyAlgorithm,
    aead_mode: AeadAlgorithm,
) -> Result<([u8; 32], Vec<u8>)> {
    // HKDF to derive output keying material
    let hk = Hkdf::<Sha256>::new(None, derived);
    let mut okm = [0u8; 32];

    let type_id = u8::from(secret_tag) | 0xc0;

    // HKDF info parameter
    let info = [
        type_id,
        pub_key.version().into(),
        sym_alg.into(),
        aead_mode.into(),
    ];

    hk.expand(&info, &mut okm)
        .expect("32 is a valid length for Sha256 to output");

    // Additional data:
    // - the Packet Type ID in OpenPGP format encoding
    // - followed by the public key packet fields, starting with the packet version number
    let mut ad = vec![type_id];
    pub_key.to_writer(&mut ad)?;

    Ok((okm, ad))
}

use std::hash::Hasher;
use std::io;

use byteorder::{BigEndian, ByteOrder};
use hkdf::Hkdf;
use nom::combinator::map;
use nom::sequence::tuple;
use num_bigint::ModInverse;
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::RsaPrivateKey;
use sha2::Sha256;
use zeroize::ZeroizeOnDrop;

use crate::crypto::aead::AeadAlgorithm;
use crate::crypto::checksum;
use crate::crypto::ecc_curve::ECCCurve;
use crate::crypto::public_key::PublicKeyAlgorithm;
use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::errors::{IResult, Result};
use crate::ser::Serialize;
use crate::types::*;
use crate::util::TeeWriter;

#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop, derive_more::Debug)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct PlainSecretParams(pub SecretKeyRepr);

#[derive(Clone, PartialEq, Eq, derive_more::Debug)]
enum PlainSecretParamsRef<'a> {
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
    #[cfg(feature = "unstable-curve448")]
    X448(#[debug("..")] &'a [u8; 56]),
}

impl PlainSecretParamsRef<'_> {
    fn pad_key<const SIZE: usize>(val: &[u8]) -> Result<[u8; SIZE]> {
        ensure!(val.len() <= SIZE, "invalid secret key size");

        let mut key = [0u8; SIZE];
        key[SIZE - val.len()..].copy_from_slice(val);
        Ok(key)
    }

    pub fn as_repr(&self, public_params: &PublicParams) -> Result<SecretKeyRepr> {
        match self {
            PlainSecretParamsRef::RSA { d, p, q, .. } => match public_params {
                PublicParams::RSA(public_params) => {
                    let secret_key = RsaPrivateKey::from_components(
                        public_params.key.n().clone(),
                        public_params.key.e().clone(),
                        d.into(),
                        vec![p.into(), q.into()],
                    )?;
                    Ok(SecretKeyRepr::RSA(crate::crypto::rsa::PrivateKey::from(
                        secret_key,
                    )))
                }
                _ => unreachable!("inconsistent key state"),
            },
            PlainSecretParamsRef::ECDH(d) => {
                match public_params {
                    PublicParams::ECDH(EcdhPublicParams::Curve25519 { .. }) => {
                        const SIZE: usize = ECCCurve::Curve25519.secret_key_length();

                        Ok(SecretKeyRepr::ECDH(
                            crate::crypto::ecdh::SecretKey::Curve25519 {
                                secret: Self::pad_key::<SIZE>(d)?,
                            },
                        ))
                    }
                    PublicParams::ECDH(EcdhPublicParams::P256 { .. }) => {
                        const SIZE: usize = ECCCurve::P256.secret_key_length();
                        let raw = Self::pad_key::<SIZE>(d)?;
                        let secret =
                            elliptic_curve::SecretKey::<p256::NistP256>::from_bytes(&raw.into())?;

                        Ok(SecretKeyRepr::ECDH(crate::crypto::ecdh::SecretKey::P256 {
                            secret,
                        }))
                    }
                    PublicParams::ECDH(EcdhPublicParams::P384 { .. }) => {
                        const SIZE: usize = ECCCurve::P384.secret_key_length();
                        let raw = Self::pad_key::<SIZE>(d)?;
                        let secret =
                            elliptic_curve::SecretKey::<p384::NistP384>::from_bytes(&raw.into())?;

                        Ok(SecretKeyRepr::ECDH(crate::crypto::ecdh::SecretKey::P384 {
                            secret,
                        }))
                    }
                    PublicParams::ECDH(EcdhPublicParams::P521 { .. }) => {
                        const SIZE: usize = 66; //ECCCurve::P521.secret_key_length();
                        let raw = Self::pad_key::<SIZE>(d)?;
                        let arr =
                        generic_array::GenericArray::<u8, generic_array::typenum::U66>::from_slice(&raw[..]);
                        let secret = elliptic_curve::SecretKey::<p521::NistP521>::from_bytes(&arr)?;

                        Ok(SecretKeyRepr::ECDH(crate::crypto::ecdh::SecretKey::P521 {
                            secret,
                        }))
                    }
                    PublicParams::ECDH(EcdhPublicParams::Unsupported { ref curve, .. }) => {
                        unsupported_err!("curve {:?} for ECDH", curve)
                    }
                    _ => unreachable!("inconsistent key state"),
                }
            }
            PlainSecretParamsRef::EdDSALegacy(d) => match public_params {
                PublicParams::EdDSALegacy(EddsaLegacyPublicParams::Ed25519 { .. }) => {
                    const SIZE: usize = ECCCurve::Ed25519.secret_key_length();
                    let raw = Self::pad_key::<SIZE>(d)?;
                    let secret = ed25519_dalek::SigningKey::from_bytes(&raw);

                    Ok(SecretKeyRepr::EdDSA(crate::crypto::eddsa::SecretKey {
                        secret,
                    }))
                }
                PublicParams::EdDSALegacy(EddsaLegacyPublicParams::Unsupported {
                    curve, ..
                }) => {
                    unsupported_err!("curve {:?} for EdDSA", curve.to_string());
                }
                _ => unreachable!("inconsistent key state"),
            },
            PlainSecretParamsRef::Ed25519(d) => {
                let secret = ed25519_dalek::SigningKey::from_bytes(*d);

                Ok(SecretKeyRepr::EdDSA(crate::crypto::eddsa::SecretKey {
                    secret,
                }))
            }
            PlainSecretParamsRef::X25519(d) => {
                let secret = x25519_dalek::StaticSecret::from(**d);

                Ok(SecretKeyRepr::X25519(crate::crypto::x25519::SecretKey {
                    secret,
                }))
            }
            #[cfg(feature = "unstable-curve448")]
            PlainSecretParamsRef::X448(d) => {
                Ok(SecretKeyRepr::X448(crate::crypto::x448::SecretKey {
                    secret: **d,
                }))
            }
            PlainSecretParamsRef::DSA(x) => match public_params {
                PublicParams::DSA(params) => {
                    let secret = dsa::SigningKey::from_components(params.key.clone(), x.into())?;

                    Ok(SecretKeyRepr::DSA(crate::crypto::dsa::SecretKey {
                        key: secret,
                    }))
                }
                _ => unreachable!("inconsistent key state"),
            },
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
    pub fn try_from_slice(
        data: &[u8],
        alg: PublicKeyAlgorithm,
        public_params: &PublicParams,
    ) -> Result<Self> {
        let (_, params) = parse_secret_params(alg)(data)?;
        let repr = params.as_repr(public_params)?;
        Ok(Self(repr))
    }

    pub fn string_to_key_id(&self) -> u8 {
        0
    }

    pub fn checksum_simple(&self) -> Vec<u8> {
        let mut hasher = checksum::SimpleChecksum::default();
        self.to_writer_raw(&mut hasher).expect("known write target");
        hasher.finalize().to_vec()
    }

    /// Uses sha1_checked
    pub fn checksum_sha1(&self) -> Result<[u8; 20]> {
        let mut buf = Vec::with_capacity(self.write_len_raw());
        self.to_writer_raw(&mut buf).expect("known write target");
        checksum::calculate_sha1([&buf])
    }

    pub fn encrypt(
        &self,
        passphrase: &str,
        s2k_params: S2kParams,
        pub_key: &(impl PublicKeyTrait + Serialize),
        secret_tag: Option<Tag>,
    ) -> Result<EncryptedSecretParams> {
        let version = pub_key.version();

        // forbid weak hash algo in s2k

        match &s2k_params {
            S2kParams::Cfb { s2k, .. }
            | S2kParams::Aead { s2k, .. }
            | S2kParams::MalleableCfb { s2k, .. } => {
                // Implementations MUST NOT generate packets using MD5, SHA-1, or RIPEMD-160 as a hash function in an S2K KDF.
                // (See https://www.rfc-editor.org/rfc/rfc9580.html#section-9.5-3)
                ensure!(
                    !s2k.known_weak_hash_algo(),
                    "Weak hash algorithm in S2K not allowed for v6 {:?}",
                    s2k
                )
            }
            _ => {}
        }

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
                        let mut data = Vec::with_capacity(self.write_len_raw());
                        self.to_writer_raw(&mut data).expect("preallocated vector");

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
                        let mut data = Vec::with_capacity(self.write_len_raw());
                        self.to_writer_raw(&mut data).expect("preallocated vector");

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
            self.to_writer_raw(&mut tee)?;
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

    pub fn write_len(&self, version: KeyVersion) -> usize {
        let mut sum = 1;
        sum += self.write_len_raw();
        if version == KeyVersion::V3 || version == KeyVersion::V4 {
            // checksum
            sum += 2;
        }
        sum
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

    fn to_writer_raw<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        match &self.0 {
            SecretKeyRepr::RSA(key) => {
                let d = key.d();
                let p = &key.primes()[0];
                let q = &key.primes()[1];

                let u = p
                    .clone()
                    .mod_inverse(q)
                    .expect("invalid prime")
                    .to_biguint()
                    .expect("invalid prime");

                Mpi::from(d).to_writer(writer)?;
                Mpi::from(p).to_writer(writer)?;
                Mpi::from(q).to_writer(writer)?;
                Mpi::from(u).to_writer(writer)?;
            }
            SecretKeyRepr::DSA(key) => {
                let x = key.x();
                Mpi::from(x).to_writer(writer)?;
            }
            SecretKeyRepr::ECDSA(key) => {
                let x = key.as_mpi();
                x.to_writer(writer)?;
            }
            SecretKeyRepr::ECDH(key) => {
                let x = key.as_mpi();
                x.to_writer(writer)?;
            }
            SecretKeyRepr::X25519(key) => {
                let x = key.as_mpi();
                x.to_writer(writer)?
            }
            SecretKeyRepr::EdDSA(key) => {
                let x = key.as_mpi();
                x.to_writer(writer)?;
            }
            #[cfg(feature = "unstable-curve448")]
            SecretKeyRepr::X448(key) => {
                let x = key.as_mpi();
                x.to_writer(writer)?;
            }
        }

        Ok(())
    }

    fn write_len_raw(&self) -> usize {
        match &self.0 {
            SecretKeyRepr::RSA(key) => {
                let d = key.d();
                let p = &key.primes()[0];
                let q = &key.primes()[1];

                let u = p
                    .clone()
                    .mod_inverse(q)
                    .expect("invalid prime")
                    .to_biguint()
                    .expect("invalid prime");

                let mut sum = 0;
                sum += Mpi::from(d).write_len();
                sum += Mpi::from(p).write_len();
                sum += Mpi::from(q).write_len();
                sum += Mpi::from(u).write_len();
                sum
            }
            SecretKeyRepr::DSA(key) => {
                let x = key.x();
                Mpi::from(x).write_len()
            }
            SecretKeyRepr::ECDSA(key) => {
                let x = key.as_mpi();
                x.write_len()
            }
            SecretKeyRepr::ECDH(key) => {
                let x = key.as_mpi();
                x.write_len()
            }
            SecretKeyRepr::EdDSA(key) => {
                let x = key.as_mpi();
                x.write_len()
            }
            SecretKeyRepr::X25519(key) => {
                let x = key.as_mpi();
                x.write_len()
            }
            #[cfg(feature = "unstable-curve448")]
            SecretKeyRepr::X448(key) => {
                let x = key.as_mpi();
                x.write_len()
            }
        }
    }
}

fn parse_secret_params(
    alg: PublicKeyAlgorithm,
) -> impl Fn(&[u8]) -> IResult<&[u8], PlainSecretParamsRef> {
    move |i: &[u8]| match alg {
        PublicKeyAlgorithm::RSA | PublicKeyAlgorithm::RSAEncrypt | PublicKeyAlgorithm::RSASign => {
            map(tuple((mpi, mpi, mpi, mpi)), |(d, p, q, u)| {
                PlainSecretParamsRef::RSA { d, p, q, u }
            })(i)
        }
        PublicKeyAlgorithm::DSA => map(mpi, |m| PlainSecretParamsRef::DSA(m))(i),
        PublicKeyAlgorithm::Elgamal => map(mpi, |m| PlainSecretParamsRef::Elgamal(m))(i),
        PublicKeyAlgorithm::ECDH => map(mpi, |m| PlainSecretParamsRef::ECDH(m))(i),
        PublicKeyAlgorithm::ECDSA => map(mpi, |m| PlainSecretParamsRef::ECDSA(m))(i),
        PublicKeyAlgorithm::EdDSALegacy => map(mpi, |m| PlainSecretParamsRef::EdDSALegacy(m))(i),
        PublicKeyAlgorithm::Ed25519 => {
            let (i, s) = nom::bytes::complete::take(32u8)(i)?;
            Ok((i, PlainSecretParamsRef::Ed25519(s.try_into().expect("32"))))
        }
        PublicKeyAlgorithm::X25519 => {
            let (i, s) = nom::bytes::complete::take(32u8)(i)?;
            Ok((i, PlainSecretParamsRef::X25519(s.try_into().expect("32"))))
        }
        #[cfg(feature = "unstable-curve448")]
        PublicKeyAlgorithm::X448 => {
            let (i, s) = nom::bytes::complete::take(56u8)(i)?;
            Ok((i, PlainSecretParamsRef::X448(s.try_into().expect("56"))))
        }
        _ => Err(nom::Err::Error(crate::errors::Error::ParsingError(
            nom::error::ErrorKind::Switch,
        ))),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;

    proptest! {
        #[test]
        #[ignore]
        fn params_write_len_v3(params: PlainSecretParams) {
            let mut buf = Vec::new();
            params.to_writer(&mut buf, KeyVersion::V3)?;
            prop_assert_eq!(buf.len(), params.write_len(KeyVersion::V3));
        }

        #[test]
        #[ignore]
        fn params_write_len_v4(params: PlainSecretParams) {
            let mut buf = Vec::new();
            params.to_writer(&mut buf, KeyVersion::V4)?;
            prop_assert_eq!(buf.len(), params.write_len(KeyVersion::V4));
        }

        #[test]
        #[ignore]
        fn params_write_len_v6(params: PlainSecretParams) {
            let mut buf = Vec::new();
            params.to_writer(&mut buf, KeyVersion::V6)?;
            prop_assert_eq!(buf.len(), params.write_len(KeyVersion::V6));
        }

        // #[test]
        // #[ignore]
        // fn params_roundtrip(params: PlainSecretParams) {
        //     let mut buf = Vec::new();
        //     params.to_writer(&mut buf, KeyVersion::V3)?;
        //     let (i, new_params) = PlainSecretParams::try_from_slice(&buf, alg, public_params)?;
        //     assert!(i.is_empty());
        //     prop_assert_eq!(params, new_params);
        // }
    }
}

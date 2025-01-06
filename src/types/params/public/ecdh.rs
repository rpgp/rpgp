use std::io;

use byteorder::WriteBytesExt;
use nom::bytes::streaming::{tag, take};
use nom::combinator::{map, map_opt, map_res};
use nom::multi::length_data;
use nom::number::streaming::be_u8;

use crate::crypto::ecc_curve::{ecc_curve_from_oid, ECCCurve};
use crate::crypto::hash::HashAlgorithm;
use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::errors::{IResult, Result};
use crate::ser::Serialize;
use crate::types::{mpi, Mpi, MpiRef};

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum EcdhPublicParams {
    /// ECDH public parameters for a curve that we know uses Mpi representation
    Curve25519 {
        #[cfg_attr(test, proptest(strategy = "tests::ecdh_curve25519_gen()"))]
        p: x25519_dalek::PublicKey,
        hash: HashAlgorithm,
        alg_sym: SymmetricKeyAlgorithm,
    },
    P256 {
        #[cfg_attr(test, proptest(strategy = "tests::ecdh_p256_gen()"))]
        p: elliptic_curve::PublicKey<p256::NistP256>,
        hash: HashAlgorithm,
        alg_sym: SymmetricKeyAlgorithm,
    },
    P384 {
        #[cfg_attr(test, proptest(strategy = "tests::ecdh_p384_gen()"))]
        p: elliptic_curve::PublicKey<p384::NistP384>,
        hash: HashAlgorithm,
        alg_sym: SymmetricKeyAlgorithm,
    },
    P521 {
        #[cfg_attr(test, proptest(strategy = "tests::ecdh_p521_gen()"))]
        p: elliptic_curve::PublicKey<p521::NistP521>,
        hash: HashAlgorithm,
        alg_sym: SymmetricKeyAlgorithm,
    },

    /// Public parameters for a curve that we don't know about (which might not use Mpi representation).
    #[cfg_attr(test, proptest(skip))]
    Unsupported { curve: ECCCurve, opaque: Vec<u8> },
}

impl Serialize for EcdhPublicParams {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        let oid = self.curve().oid();
        writer.write_u8(oid.len().try_into()?)?;
        writer.write_all(&oid)?;

        let tags = match self {
            Self::Curve25519 { p, hash, alg_sym } => {
                let mut mpi = Vec::with_capacity(33);
                mpi.push(0x40);
                mpi.extend_from_slice(p.as_bytes());
                let mpi = MpiRef::from_slice(&mpi);
                mpi.to_writer(writer)?;
                Some((hash, alg_sym))
            }
            Self::P256 { p, hash, alg_sym } => {
                let p = Mpi::from_slice(p.to_sec1_bytes().as_ref());
                p.to_writer(writer)?;
                Some((hash, alg_sym))
            }
            Self::P384 { p, hash, alg_sym } => {
                let p = Mpi::from_slice(p.to_sec1_bytes().as_ref());
                p.to_writer(writer)?;
                Some((hash, alg_sym))
            }
            Self::P521 { p, hash, alg_sym } => {
                let p = Mpi::from_slice(p.to_sec1_bytes().as_ref());
                p.to_writer(writer)?;
                Some((hash, alg_sym))
            }
            Self::Unsupported { opaque, .. } => {
                writer.write_all(&opaque)?;
                None
            }
        };

        if let Some((hash, alg_sym)) = tags {
            writer.write_u8(0x03)?; // len of the following fields
            writer.write_u8(0x01)?; // fixed tag

            writer.write_u8((*hash).into())?;
            writer.write_u8((*alg_sym).into())?;
        }

        Ok(())
    }

    fn write_len(&self) -> usize {
        let mut sum = 1; // oid len

        match self {
            Self::Curve25519 { p, .. } => {
                sum += self.curve().oid().len();
                let mut mpi = Vec::with_capacity(33);
                mpi.push(0x40);
                mpi.extend_from_slice(p.as_bytes());
                let mpi = MpiRef::from_slice(&mpi);
                sum += mpi.write_len();
            }
            Self::P256 { p, .. } => {
                let p = Mpi::from_slice(p.to_sec1_bytes().as_ref());
                sum += self.curve().oid().len();
                sum += p.write_len();
            }
            Self::P384 { p, .. } => {
                let p = Mpi::from_slice(p.to_sec1_bytes().as_ref());
                sum += self.curve().oid().len();
                sum += p.write_len();
            }
            Self::P521 { p, .. } => {
                let p = Mpi::from_slice(p.to_sec1_bytes().as_ref());
                sum += self.curve().oid().len();
                sum += p.write_len();
            }
            Self::Unsupported { curve, opaque, .. } => {
                let oid = curve.oid();
                sum += oid.len();
                sum += opaque.len();
            }
        };

        if !matches!(self, Self::Unsupported { .. }) {
            // fields and tags
            sum += 1 + 1 + 1 + 1;
        }
        sum
    }
}

impl EcdhPublicParams {
    pub fn is_supported(&self) -> bool {
        !matches!(self, Self::Unsupported { .. })
    }

    pub fn curve(&self) -> ECCCurve {
        match self {
            Self::Curve25519 { .. } => ECCCurve::Curve25519,
            Self::P256 { .. } => ECCCurve::P256,
            Self::P384 { .. } => ECCCurve::P384,
            Self::P521 { .. } => ECCCurve::P521,
            Self::Unsupported { curve, .. } => curve.clone(),
        }
    }

    /// Ref: <https://www.rfc-editor.org/rfc/rfc9580.html#name-algorithm-specific-part-for-ecd>
    pub fn try_from_slice(i: &[u8], len: Option<usize>) -> IResult<&[u8], Self> {
        // a one-octet size of the following field
        // octets representing a curve OID
        let (i, curve) = map_opt(length_data(be_u8), ecc_curve_from_oid)(i)?;

        match curve {
            ECCCurve::Curve25519 | ECCCurve::P256 | ECCCurve::P384 | ECCCurve::P521 => {
                // MPI of an EC point representing a public key
                let (i, p) = mpi(i)?;

                // a one-octet size of the following fields
                let (i, _len2) = be_u8(i)?;

                // a one-octet value 01, reserved for future extensions
                let (i, _tag) = tag(&[1][..])(i)?;

                // a one-octet hash function ID used with a KDF
                let (i, hash) = map(be_u8, HashAlgorithm::from)(i)?;

                // a one-octet algorithm ID for the symmetric algorithm used to wrap
                // the symmetric key used for the message encryption
                let (i, alg_sym) = map_res(be_u8, SymmetricKeyAlgorithm::try_from)(i)?;

                let params = Self::try_from_mpi(p, curve, hash, alg_sym)?;
                Ok((i, params))
            }
            _ => {
                let (i, data) = if let Some(pub_len) = len {
                    let (i, data) = take(pub_len)(i)?;
                    (i, data.to_vec())
                } else {
                    (i, vec![])
                };
                Ok((
                    i,
                    EcdhPublicParams::Unsupported {
                        curve,
                        opaque: data,
                    },
                ))
            }
        }
    }

    fn try_from_mpi(
        p: MpiRef<'_>,
        curve: ECCCurve,
        hash: HashAlgorithm,
        alg_sym: SymmetricKeyAlgorithm,
    ) -> Result<Self> {
        match curve {
            ECCCurve::Curve25519 => {
                ensure_eq!(p.len(), 33, "invalid public key length");
                // public part of the ephemeral key (removes 0x40 prefix)
                let public_key = &p[1..];

                // create montgomery point
                let mut public_key_arr = [0u8; 32];
                public_key_arr[..].copy_from_slice(public_key);

                let p = x25519_dalek::PublicKey::from(public_key_arr);
                Ok(EcdhPublicParams::Curve25519 { p, hash, alg_sym })
            }
            ECCCurve::P256 => {
                let p = p256::PublicKey::from_sec1_bytes(&p)?;
                Ok(EcdhPublicParams::P256 { p, hash, alg_sym })
            }
            ECCCurve::P384 => {
                let p = p384::PublicKey::from_sec1_bytes(&p)?;
                Ok(EcdhPublicParams::P384 { p, hash, alg_sym })
            }
            ECCCurve::P521 => {
                let p = p521::PublicKey::from_sec1_bytes(&p)?;
                Ok(EcdhPublicParams::P521 { p, hash, alg_sym })
            }
            _ => bail!("unexpected ecdh curve: {:?}", curve),
        }
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    use rand::RngCore;
    use rand::SeedableRng;

    use proptest::prelude::*;

    proptest::prop_compose! {
        pub fn ecdh_curve25519_gen()(seed: u64) -> x25519_dalek::PublicKey {
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed);
            let mut secret_key_bytes = [0u8; ECCCurve::Curve25519.secret_key_length()];
            rng.fill_bytes(&mut secret_key_bytes);

            let secret = x25519_dalek::StaticSecret::from(secret_key_bytes);
            x25519_dalek::PublicKey::from(&secret)
        }
    }

    proptest::prop_compose! {
        pub fn ecdh_p256_gen()(seed: u64) -> elliptic_curve::PublicKey<p256::NistP256> {
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed);
            elliptic_curve::SecretKey::<p256::NistP256>::random(&mut rng).public_key()
        }
    }

    proptest::prop_compose! {
        pub fn ecdh_p384_gen()(seed: u64) -> elliptic_curve::PublicKey<p384::NistP384> {
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed);
            elliptic_curve::SecretKey::<p384::NistP384>::random(&mut rng).public_key()
        }
    }

    proptest::prop_compose! {
        pub fn ecdh_p521_gen()(seed: u64) -> elliptic_curve::PublicKey<p521::NistP521> {
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed);
            elliptic_curve::SecretKey::<p521::NistP521>::random(&mut rng).public_key()
        }
    }

    proptest! {
        #[test]
        fn params_write_len(params: EcdhPublicParams) {
            let mut buf = Vec::new();
            params.to_writer(&mut buf)?;
            prop_assert_eq!(buf.len(), params.write_len());
        }

        #[test]
        fn params_roundtrip(params: EcdhPublicParams) {
            let mut buf = Vec::new();
            params.to_writer(&mut buf)?;
            let (i, new_params) = EcdhPublicParams::try_from_slice(&buf, None)?;
            assert!(i.is_empty());
            prop_assert_eq!(params, new_params);
        }
    }
}

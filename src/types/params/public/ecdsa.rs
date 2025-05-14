use std::io::{self, BufRead};

use byteorder::WriteBytesExt;
use bytes::Bytes;
use elliptic_curve::sec1::ToEncodedPoint;

use crate::{
    crypto::ecc_curve::{ecc_curve_from_oid, ECCCurve},
    errors::{ensure, format_err, Result},
    parsing_reader::BufReadParsing,
    ser::Serialize,
    types::Mpi,
};

#[derive(derive_more::Debug, PartialEq, Eq, Clone)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum EcdsaPublicParams {
    P256 {
        #[cfg_attr(test, proptest(strategy = "tests::p256_pub_gen()"))]
        key: p256::PublicKey,
    },
    P384 {
        #[cfg_attr(test, proptest(strategy = "tests::p384_pub_gen()"))]
        key: p384::PublicKey,
    },
    P521 {
        #[cfg_attr(test, proptest(strategy = "tests::p521_pub_gen()"))]
        key: p521::PublicKey,
    },
    Secp256k1 {
        #[cfg_attr(test, proptest(strategy = "tests::k256_pub_gen()"))]
        key: k256::PublicKey,
    },
    #[cfg_attr(test, proptest(skip))]
    Unsupported {
        curve: ECCCurve,
        #[debug("{}", hex::encode(opaque))]
        opaque: Bytes,
    },
}

impl EcdsaPublicParams {
    /// Is this key based on a curve that we know how to parse?
    ///
    /// Unsupported curves are modeled as [`Self::Unsupported`].
    /// Key packets that use such curves are handled as opaque blobs.
    pub fn is_supported(&self) -> bool {
        !matches!(self, Self::Unsupported { .. })
    }

    /// Get the `ECCCurve` that this key is based on
    pub fn curve(&self) -> ECCCurve {
        match self {
            Self::P256 { .. } => ECCCurve::P256,
            Self::P384 { .. } => ECCCurve::P384,
            Self::P521 { .. } => ECCCurve::P521,
            Self::Secp256k1 { .. } => ECCCurve::Secp256k1,
            Self::Unsupported { curve, .. } => curve.clone(),
        }
    }

    /// Ref: <https://www.rfc-editor.org/rfc/rfc9580.html#name-algorithm-specific-part-for-ec>
    pub fn try_from_reader<B: BufRead>(mut i: B, len: Option<usize>) -> Result<Self> {
        // a one-octet size of the following field
        let curve_len = i.read_u8()?;
        // octets representing a curve OID
        let curve = ecc_curve_from_oid(&i.take_bytes(curve_len.into())?)
            .ok_or_else(|| format_err!("invalid curve"))?;

        match curve {
            ECCCurve::P256 => {
                let p = Mpi::try_from_reader(&mut i)?;
                ensure!(p.len() <= 65, "invalid public key length");
                let mut key = [0u8; 65];
                key[..p.len()].copy_from_slice(p.as_ref());

                let public = p256::PublicKey::from_sec1_bytes(&key)?;
                Ok(EcdsaPublicParams::P256 { key: public })
            }
            ECCCurve::P384 => {
                let p = Mpi::try_from_reader(&mut i)?;
                ensure!(p.len() <= 97, "invalid public key length");
                let mut key = [0u8; 97];
                key[..p.len()].copy_from_slice(p.as_ref());

                let public = p384::PublicKey::from_sec1_bytes(&key)?;
                Ok(EcdsaPublicParams::P384 { key: public })
            }
            ECCCurve::P521 => {
                let p = Mpi::try_from_reader(&mut i)?;
                ensure!(p.len() <= 133, "invalid public key length");
                let mut key = [0u8; 133];
                key[..p.len()].copy_from_slice(p.as_ref());

                let public = p521::PublicKey::from_sec1_bytes(&key)?;
                Ok(EcdsaPublicParams::P521 { key: public })
            }
            ECCCurve::Secp256k1 => {
                let p = Mpi::try_from_reader(&mut i)?;
                ensure!(p.len() <= 65, "invalid public key length");
                let mut key = [0u8; 65];
                key[..p.len()].copy_from_slice(p.as_ref());

                let public = k256::PublicKey::from_sec1_bytes(&key)?;
                Ok(EcdsaPublicParams::Secp256k1 { key: public })
            }
            _ => {
                let opaque = if let Some(pub_len) = len {
                    i.take_bytes(pub_len)?.freeze()
                } else {
                    i.rest()?.freeze()
                };
                Ok(EcdsaPublicParams::Unsupported { curve, opaque })
            }
        }
    }

    pub const fn secret_key_length(&self) -> Option<usize> {
        match self {
            EcdsaPublicParams::P256 { .. } => Some(32),
            EcdsaPublicParams::P384 { .. } => Some(48),
            EcdsaPublicParams::P521 { .. } => Some(66),
            EcdsaPublicParams::Secp256k1 { .. } => Some(32),
            EcdsaPublicParams::Unsupported { .. } => None,
        }
    }
}

impl Serialize for EcdsaPublicParams {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        let oid = match self {
            EcdsaPublicParams::P256 { .. } => ECCCurve::P256.oid(),
            EcdsaPublicParams::P384 { .. } => ECCCurve::P384.oid(),
            EcdsaPublicParams::P521 { .. } => ECCCurve::P521.oid(),
            EcdsaPublicParams::Secp256k1 { .. } => ECCCurve::Secp256k1.oid(),
            EcdsaPublicParams::Unsupported { curve, .. } => curve.oid(),
        };

        writer.write_u8(oid.len().try_into()?)?;
        writer.write_all(&oid)?;

        match self {
            EcdsaPublicParams::P256 { key, .. } => {
                let p = Mpi::from_slice(key.to_encoded_point(false).as_bytes());
                p.to_writer(writer)?;
            }
            EcdsaPublicParams::P384 { key, .. } => {
                let p = Mpi::from_slice(key.to_encoded_point(false).as_bytes());
                p.to_writer(writer)?;
            }
            EcdsaPublicParams::P521 { key, .. } => {
                let p = Mpi::from_slice(key.to_encoded_point(false).as_bytes());
                p.to_writer(writer)?;
            }
            EcdsaPublicParams::Secp256k1 { key, .. } => {
                let p = Mpi::from_slice(key.to_encoded_point(false).as_bytes());
                p.to_writer(writer)?;
            }
            EcdsaPublicParams::Unsupported { opaque, .. } => {
                writer.write_all(opaque)?;
            }
        }

        Ok(())
    }

    fn write_len(&self) -> usize {
        let oid = match self {
            EcdsaPublicParams::P256 { .. } => ECCCurve::P256.oid(),
            EcdsaPublicParams::P384 { .. } => ECCCurve::P384.oid(),
            EcdsaPublicParams::P521 { .. } => ECCCurve::P521.oid(),
            EcdsaPublicParams::Secp256k1 { .. } => ECCCurve::Secp256k1.oid(),
            EcdsaPublicParams::Unsupported { curve, .. } => curve.oid(),
        };

        let mut sum = 1;
        sum += oid.len();

        match self {
            EcdsaPublicParams::P256 { key, .. } => {
                let p = Mpi::from_slice(key.to_encoded_point(false).as_bytes());
                sum += p.write_len();
            }
            EcdsaPublicParams::P384 { key, .. } => {
                let p = Mpi::from_slice(key.to_encoded_point(false).as_bytes());
                sum += p.write_len();
            }
            EcdsaPublicParams::P521 { key, .. } => {
                let p = Mpi::from_slice(key.to_encoded_point(false).as_bytes());
                sum += p.write_len();
            }
            EcdsaPublicParams::Secp256k1 { key, .. } => {
                let p = Mpi::from_slice(key.to_encoded_point(false).as_bytes());
                sum += p.write_len();
            }
            EcdsaPublicParams::Unsupported { opaque, .. } => {
                sum += opaque.len();
            }
        }
        sum
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use rand::SeedableRng;

    use super::*;

    proptest::prop_compose! {
        pub fn p256_pub_gen()(seed: u64) -> p256::PublicKey {
            let mut rng = chacha20::ChaCha8Rng::seed_from_u64(seed);
            p256::SecretKey::random(&mut rng).public_key()
        }
    }

    proptest::prop_compose! {
        pub fn p384_pub_gen()(seed: u64) -> p384::PublicKey {
            let mut rng = chacha20::ChaCha8Rng::seed_from_u64(seed);
            p384::SecretKey::random(&mut rng).public_key()
        }
    }

    proptest::prop_compose! {
        pub fn p521_pub_gen()(seed: u64) -> p521::PublicKey {
            let mut rng = chacha20::ChaCha8Rng::seed_from_u64(seed);
            p521::SecretKey::random(&mut rng).public_key()
        }
    }

    proptest::prop_compose! {
        pub fn k256_pub_gen()(seed: u64) -> k256::PublicKey {
            let mut rng = chacha20::ChaCha8Rng::seed_from_u64(seed);
            k256::SecretKey::random(&mut rng).public_key()
        }
    }

    proptest! {
        #[test]
        fn params_write_len(params: EcdsaPublicParams) {
            let mut buf = Vec::new();
            params.to_writer(&mut buf)?;
            prop_assert_eq!(buf.len(), params.write_len());
        }

        #[test]
        fn params_roundtrip(params: EcdsaPublicParams) {
            let mut buf = Vec::new();
            params.to_writer(&mut buf)?;
            let new_params = EcdsaPublicParams::try_from_reader(&mut &buf[..], None)?;
            prop_assert_eq!(params, new_params);
        }
    }
}

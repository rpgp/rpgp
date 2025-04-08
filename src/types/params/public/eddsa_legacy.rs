use std::io::{self, BufRead};

use byteorder::WriteBytesExt;
use bytes::Bytes;

use crate::{
    crypto::ecc_curve::{ecc_curve_from_oid, ECCCurve},
    errors::{ensure_eq, format_err, Result},
    parsing_reader::BufReadParsing,
    ser::Serialize,
    types::Mpi,
};

#[derive(derive_more::Debug, PartialEq, Eq, Clone)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum EddsaLegacyPublicParams {
    Ed25519 {
        #[cfg_attr(test, proptest(strategy = "tests::ed25519_pub_gen()"))]
        key: ed25519_dalek::VerifyingKey,
    },
    #[cfg_attr(test, proptest(skip))]
    Unsupported {
        curve: ECCCurve,
        #[debug("{}", hex::encode(opaque))]
        opaque: Bytes,
    },
}

impl EddsaLegacyPublicParams {
    /// <https://www.rfc-editor.org/rfc/rfc9580.html#name-algorithm-specific-part-for-ed>
    pub fn try_from_reader<B: BufRead>(mut i: B, len: Option<usize>) -> Result<Self> {
        // a one-octet size of the following field
        let curve_len = i.read_u8()?;
        // octets representing a curve OID
        let curve_raw = i.take_bytes(curve_len.into())?;
        let curve = ecc_curve_from_oid(&curve_raw).ok_or_else(|| format_err!("invalid curve"))?;

        // MPI of an EC point representing a public key
        match curve {
            ECCCurve::Ed25519 => {
                let q = Mpi::try_from_reader(&mut i)?;
                ensure_eq!(q.len(), 33, "invalid Q (len)");
                ensure_eq!(q.as_ref()[0], 0x40, "invalid Q (prefix)");
                let public = &q.as_ref()[1..];

                let key: ed25519_dalek::VerifyingKey = public.try_into()?;
                Ok(Self::Ed25519 { key })
            }
            _ => {
                let opaque = if let Some(pub_len) = len {
                    i.take_bytes(pub_len)?.freeze()
                } else {
                    i.rest()?.freeze()
                };

                Ok(Self::Unsupported { curve, opaque })
            }
        }
    }

    pub fn curve(&self) -> ECCCurve {
        match self {
            Self::Ed25519 { .. } => ECCCurve::Ed25519,
            Self::Unsupported { curve, .. } => curve.clone(),
        }
    }
}

impl Serialize for EddsaLegacyPublicParams {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            Self::Ed25519 { key } => {
                let oid = ECCCurve::Ed25519.oid();
                writer.write_u8(oid.len().try_into()?)?;
                writer.write_all(&oid)?;
                let mut mpi = Vec::with_capacity(33);
                mpi.push(0x40);
                mpi.extend_from_slice(key.as_bytes());
                let mpi = Mpi::from_slice(&mpi);
                mpi.to_writer(writer)?;
            }
            Self::Unsupported { curve, opaque } => {
                let oid = curve.oid();
                writer.write_u8(oid.len().try_into()?)?;
                writer.write_all(&oid)?;

                writer.write_all(opaque)?;
            }
        }
        Ok(())
    }
    fn write_len(&self) -> usize {
        let mut sum = 0;
        match self {
            Self::Ed25519 { key } => {
                let oid = ECCCurve::Ed25519.oid();
                sum += 1;
                sum += oid.len();

                let mut mpi = Vec::with_capacity(33);
                mpi.push(0x40);
                mpi.extend_from_slice(key.as_bytes());
                let mpi = Mpi::from_slice(&mpi);
                sum += mpi.write_len();
            }
            Self::Unsupported { curve, opaque } => {
                let oid = curve.oid();
                sum += 1;
                sum += oid.len();
                sum += opaque.len();
            }
        }
        sum
    }
}

#[cfg(test)]
pub(super) mod tests {
    use proptest::prelude::*;

    use super::*;

    proptest::prop_compose! {
        pub fn ed25519_pub_gen()(bytes: [u8; 32]) -> ed25519_dalek::VerifyingKey {
            let secret = ed25519_dalek::SigningKey::from_bytes(&bytes);
            ed25519_dalek::VerifyingKey::from(&secret)
        }
    }

    proptest! {
        #[test]
        fn params_write_len(params: EddsaLegacyPublicParams) {
            let mut buf = Vec::new();
            params.to_writer(&mut buf)?;
            prop_assert_eq!(buf.len(), params.write_len());
        }

        #[test]
        fn params_roundtrip(params: EddsaLegacyPublicParams) {
            let mut buf = Vec::new();
            params.to_writer(&mut buf)?;
            let new_params = EddsaLegacyPublicParams::try_from_reader(&mut &buf[..], None)?;
            prop_assert_eq!(params, new_params);
        }
    }
}

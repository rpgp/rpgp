use std::io;

use byteorder::WriteBytesExt;

use crate::crypto::ecc_curve::ECCCurve;
use crate::errors::Result;
use crate::ser::Serialize;
use crate::types::{Mpi, MpiRef};

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum EddsaLegacyPublicParams {
    Ed25519 {
        #[cfg_attr(test, proptest(strategy = "tests::ed25519_pub_gen()"))]
        key: ed25519_dalek::VerifyingKey,
    },
    #[cfg_attr(test, proptest(skip))]
    Unsupported { curve: ECCCurve, mpi: Mpi },
}

impl EddsaLegacyPublicParams {
    pub fn try_from_mpi(curve: ECCCurve, mpi: MpiRef<'_>) -> Result<Self> {
        match curve {
            ECCCurve::Ed25519 => {
                ensure_eq!(mpi.len(), 33, "invalid Q (len)");
                ensure_eq!(mpi[0], 0x40, "invalid Q (prefix)");
                let public = &mpi[1..];

                let key: ed25519_dalek::VerifyingKey = public.try_into()?;
                Ok(Self::Ed25519 { key })
            }
            _ => Ok(Self::Unsupported {
                curve,
                mpi: mpi.to_owned(),
            }),
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
                let mpi = MpiRef::from_slice(&mpi);
                mpi.to_writer(writer)?;
            }
            Self::Unsupported { curve, mpi } => {
                let oid = curve.oid();
                writer.write_u8(oid.len().try_into()?)?;
                writer.write_all(&oid)?;

                mpi.to_writer(writer)?;
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
                let mpi = MpiRef::from_slice(&mpi);
                sum += mpi.write_len();
            }
            Self::Unsupported { curve, mpi } => {
                let oid = curve.oid();
                sum += 1;
                sum += oid.len();
                sum += mpi.write_len();
            }
        }
        sum
    }
}

#[cfg(test)]
pub(super) mod tests {
    proptest::prop_compose! {
        pub fn ed25519_pub_gen()(bytes: [u8; 32]) -> ed25519_dalek::VerifyingKey {
            let secret = ed25519_dalek::SigningKey::from_bytes(&bytes);
            ed25519_dalek::VerifyingKey::from(&secret)
        }
    }
}

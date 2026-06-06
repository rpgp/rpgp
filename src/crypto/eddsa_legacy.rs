use bytes::BytesMut;
use zeroize::ZeroizeOnDrop;

use crate::{
    crypto::ecc_curve::ECCCurve,
    errors::{bail, Error},
    ser::Serialize,
    types::EddsaLegacyPublicParams,
};

#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop, derive_more::Debug)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum SecretKey {
    Ed25519(crate::crypto::ed25519::SecretKey),
    #[cfg_attr(test, proptest(skip))]
    Unsupported {
        #[zeroize(skip)]
        curve: ECCCurve,

        // The secret parameter as opaque data (including the Mpi length header)
        #[debug("{}", hex::encode(opaque))]
        opaque: BytesMut,
    },
}

impl Serialize for crate::crypto::eddsa_legacy::SecretKey {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> crate::errors::Result<()> {
        match self {
            Self::Ed25519(key) => key.to_writer(writer),
            Self::Unsupported { opaque, .. } => Ok(writer.write_all(opaque)?),
        }
    }

    fn write_len(&self) -> usize {
        match self {
            Self::Ed25519(key) => key.write_len(),
            Self::Unsupported { opaque, .. } => opaque.len(),
        }
    }
}

impl TryFrom<&crate::crypto::eddsa_legacy::SecretKey> for EddsaLegacyPublicParams {
    type Error = Error;
    fn try_from(value: &SecretKey) -> Result<Self, Self::Error> {
        match value {
            SecretKey::Ed25519(key) => Ok(key.into()),
            SecretKey::Unsupported { curve, .. } => {
                bail!(
                    "Can't transform eddsa_legacy::SecretKey::Unsupported ({:?}) into EddsaLegacyPublicParams",
                    curve
                )
            }
        }
    }
}

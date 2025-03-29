use bytes::Bytes;
use log::debug;

use super::MpiBytes;
use crate::ser::Serialize;

/// An OpenPGP cryptographic signature.
///
/// It is an element of a [crate::packet::Signature] packet.
/// Historically, cryptographic signatures in OpenPGP were encoded as [crate::types::Mpi],
/// however, in RFC 9580, native encoding is used for the modern Ed25519 and Ed448 signatures.
///
/// This type can represent both flavors of cryptographic signature data.
#[derive(derive_more::Debug, PartialEq, Eq, Clone)]
pub enum SignatureBytes {
    /// A cryptographic signature that is represented as a set of [Mpi]s.
    ///
    /// This format has been used for all OpenPGP cryptographic signatures in RFCs 4880 and 6637.
    Mpis(Vec<MpiBytes>),

    /// A cryptographic signature that is represented in native format.
    ///
    /// This format was introduced in RFC 9580 and is currently only used for Ed25519 and Ed448.
    Native(#[debug("{}", hex::encode(_0))] Bytes),
}

impl SignatureBytes {
    pub(crate) fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> crate::errors::Result<()> {
        use crate::ser::Serialize;

        match &self {
            SignatureBytes::Mpis(mpis) => {
                debug!("writing {} signature MPIs", mpis.len());
                // the actual signature
                for val in mpis {
                    val.to_writer(writer)?;
                }
            }
            SignatureBytes::Native(sig) => {
                writer.write_all(sig)?;
            }
        }

        Ok(())
    }

    pub(crate) fn write_len(&self) -> usize {
        match self {
            SignatureBytes::Mpis(mpis) => mpis.write_len(),
            SignatureBytes::Native(sig) => sig.len(),
        }
    }
}

impl<'a> TryFrom<&'a SignatureBytes> for &'a [MpiBytes] {
    type Error = crate::errors::Error;

    fn try_from(value: &'a SignatureBytes) -> std::result::Result<Self, Self::Error> {
        match value {
            SignatureBytes::Mpis(mpis) => Ok(mpis),

            // We reject this operation because it doesn't fit with the intent of the Sig abstraction
            SignatureBytes::Native(_) => bail!("Native Sig can't be transformed into Mpis"),
        }
    }
}

impl<'a> TryFrom<&'a SignatureBytes> for &'a [u8] {
    type Error = crate::errors::Error;

    fn try_from(value: &'a SignatureBytes) -> std::result::Result<Self, Self::Error> {
        match value {
            // We reject this operation because it doesn't fit with the intent of the Sig abstraction
            SignatureBytes::Mpis(_) => bail!("Mpi-based Sig can't be transformed into &[u8]"),

            SignatureBytes::Native(native) => Ok(native),
        }
    }
}

impl From<Vec<MpiBytes>> for SignatureBytes {
    fn from(value: Vec<MpiBytes>) -> Self {
        SignatureBytes::Mpis(value)
    }
}

impl From<Bytes> for SignatureBytes {
    fn from(value: Bytes) -> Self {
        SignatureBytes::Native(value)
    }
}

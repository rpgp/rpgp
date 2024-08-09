mod compression;
mod fingerprint;
mod key_id;
mod mpi;
mod packet;
mod params;
mod public_key;
mod revocation_key;
mod s2k;
mod secret_key;
mod secret_key_repr;
mod user;

use log::debug;

pub use self::compression::*;
pub use self::fingerprint::*;
pub use self::key_id::*;
pub use self::mpi::*;
pub use self::packet::*;
pub use self::params::*;
pub use self::public_key::*;
pub use self::revocation_key::*;
pub use self::s2k::*;
pub use self::secret_key::*;
pub use self::secret_key_repr::*;
pub use self::user::*;

/// An OpenPGP cryptographic signature.
///
/// It is an element of a [pgp::packet::Signature] packet.
/// Historically, cryptographic signatures in OpenPGP were encoded as [pgp::types::Mpi],
/// however, in RFC 9580, native encoding is used for the modern Ed25519 and Ed448 signatures.
///
/// This type can represent both flavors of cryptographic signature data.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Sig {
    Mpis(Vec<Mpi>),
    Native(Vec<u8>),
}

impl Sig {
    pub(crate) fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> crate::errors::Result<()> {
        use crate::ser::Serialize;

        match &self {
            Sig::Mpis(mpis) => {
                // the actual signature
                for val in mpis {
                    debug!("writing: {}", hex::encode(val));
                    val.to_writer(writer)?;
                }
            }
            Sig::Native(sig) => {
                writer.write_all(sig)?;
            }
        }

        Ok(())
    }
}

impl<'a> TryFrom<&'a Sig> for &'a [Mpi] {
    type Error = crate::errors::Error;

    fn try_from(value: &'a Sig) -> std::result::Result<Self, Self::Error> {
        match value {
            Sig::Mpis(mpis) => Ok(mpis),

            // We reject this operation because it doesn't fit with the intent of the Sig abstraction
            Sig::Native(_) => bail!("Native Sig can't be transformed into Mpis"),
        }
    }
}

impl<'a> TryFrom<&'a Sig> for &'a [u8] {
    type Error = crate::errors::Error;

    fn try_from(value: &'a Sig) -> std::result::Result<Self, Self::Error> {
        match value {
            // We reject this operation because it doesn't fit with the intent of the Sig abstraction
            Sig::Mpis(_) => bail!("Mpi-based Sig can't be transformed into &[u8]"),

            Sig::Native(native) => Ok(native),
        }
    }
}

impl From<Vec<Mpi>> for Sig {
    fn from(value: Vec<Mpi>) -> Self {
        Sig::Mpis(value)
    }
}

impl From<Vec<u8>> for Sig {
    fn from(value: Vec<u8>) -> Self {
        Sig::Native(value)
    }
}

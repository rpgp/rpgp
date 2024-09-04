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
use crate::crypto::sym::SymmetricKeyAlgorithm;

/// An OpenPGP cryptographic signature.
///
/// It is an element of a [crate::packet::Signature] packet.
/// Historically, cryptographic signatures in OpenPGP were encoded as [crate::types::Mpi],
/// however, in RFC 9580, native encoding is used for the modern Ed25519 and Ed448 signatures.
///
/// This type can represent both flavors of cryptographic signature data.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SignatureBytes {
    /// A cryptographic signature that is represented as a set of [Mpi]s.
    ///
    /// This format has been used for all OpenPGP cryptographic signatures in RFCs 4880 and 6637.
    Mpis(Vec<Mpi>),

    /// A cryptographic signature that is represented in native format.
    ///
    /// This format was introduced in RFC 9580 and is currently only used for Ed25519 and Ed448.
    Native(Vec<u8>),
}

impl SignatureBytes {
    pub(crate) fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> crate::errors::Result<()> {
        use crate::ser::Serialize;

        match &self {
            SignatureBytes::Mpis(mpis) => {
                // the actual signature
                for val in mpis {
                    debug!("writing: {}", hex::encode(val));
                    val.to_writer(writer)?;
                }
            }
            SignatureBytes::Native(sig) => {
                writer.write_all(sig)?;
            }
        }

        Ok(())
    }
}

impl<'a> TryFrom<&'a SignatureBytes> for &'a [Mpi] {
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

impl From<Vec<Mpi>> for SignatureBytes {
    fn from(value: Vec<Mpi>) -> Self {
        SignatureBytes::Mpis(value)
    }
}

impl From<Vec<u8>> for SignatureBytes {
    fn from(value: Vec<u8>) -> Self {
        SignatureBytes::Native(value)
    }
}

/// Select which type of encrypted session key data should be produced in an encryption step\
#[derive(Debug)]
pub enum EskType {
    /// V3 PKESK or V4 SKESK (these are used in RFC 4880 and 2440)
    V3_4,

    /// V6 PKESK or SKESK (introduced in RFC 9580)
    V6,
}

/// Values comprising a public key encrypted session key
///
/// FIXME: extend for algorithm specific values? (and/or v3 vs. v6)
/// FIXME: naming?
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PkeskBytes {
    Rsa {
        mpi: Mpi,
    },
    Elgamal {
        first: Mpi,
        second: Mpi,
    },
    Ecdh {
        public_point: Mpi,
        encrypted_session_key: Vec<u8>,
    },
    X25519 {
        /// Ephemeral X25519 public key (32 bytes).
        ephemeral: [u8; 32],

        /// Encrypted and wrapped session key.
        session_key: Vec<u8>,

        /// Set for v3 PKESK only (the sym_alg is not encrypted with the session key for X25519)
        sym_alg: Option<SymmetricKeyAlgorithm>,
    },
    X448 {
        /// Ephemeral X448 public key (56 bytes).
        ephemeral: [u8; 56],

        /// Encrypted and wrapped session key.
        session_key: Vec<u8>,

        /// Set for v3 PKESK only (the sym_alg is not encrypted with the session key for X448)
        sym_alg: Option<SymmetricKeyAlgorithm>,
    },
    Other,
}

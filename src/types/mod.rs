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

use rand::{CryptoRng, Rng};

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
use crate::crypto::hash::HashAlgorithm;

/// OpenPGP signature data
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Sig {
    Mpis(Vec<Mpi>),
    Native(Vec<u8>),
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

pub(crate) fn salt_for<R: CryptoRng + Rng>(rng: &mut R, hash_alg: HashAlgorithm) -> Vec<u8> {
    let mut salt = vec![0; hash_alg.salt_len()];
    rng.fill_bytes(&mut salt);

    salt
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

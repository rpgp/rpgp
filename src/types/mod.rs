mod compression;
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
use crate::packet::SignatureVersion;

/// OpenPGP signature data
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Sig {
    Mpis(Vec<Mpi>),
    Native(Vec<u8>),
}

pub(crate) fn salt_for<R: CryptoRng + Rng>(
    rng: &mut R,
    sig_version: SignatureVersion,
    hash_alg: HashAlgorithm,
) -> Option<Vec<u8>> {
    match sig_version {
        SignatureVersion::V6 => {
            let mut salt = vec![0; hash_alg.salt_len()];
            rng.fill_bytes(&mut salt);

            Some(salt)
        }
        _ => None,
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

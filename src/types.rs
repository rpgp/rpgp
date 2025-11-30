mod compression;
mod fingerprint;
mod key_id;
mod key_traits;
mod mpi;
mod packet;
mod params;
mod password;
mod pkesk;
mod revocation_key;
mod s2k;
mod signature;
mod timestamp;
mod user;

pub use self::{
    compression::CompressionAlgorithm,
    fingerprint::Fingerprint,
    key_id::KeyId,
    key_traits::{EncryptionKey, Imprint, KeyDetails, SigningKey, VerifyingKey},
    mpi::Mpi,
    packet::*,
    params::*,
    password::Password,
    pkesk::PkeskBytes,
    revocation_key::{RevocationKey, RevocationKeyClass},
    s2k::{S2kParams, S2kUsage, StringToKey},
    signature::SignatureBytes,
    timestamp::{Timestamp, TimestampError},
    user::{SignedUser, SignedUserAttribute},
};

/// Select which type of encrypted session key data should be produced in an encryption step
#[derive(Debug, Copy, Clone)]
pub enum EskType {
    /// V3 PKESK or V4 SKESK (these are used in RFC 4880 and 2440)
    V3_4,

    /// V6 PKESK or SKESK (introduced in RFC 9580)
    V6,
}

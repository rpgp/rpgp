//! rPGP types

mod compression;
mod duration;
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
    duration::{Duration, DurationError},
    fingerprint::Fingerprint,
    key_id::KeyId,
    key_traits::{DecryptionKey, EncryptionKey, Imprint, KeyDetails, SigningKey, VerifyingKey},
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

/// Specify the type of an encrypted session key.
///
/// This distinguishes between the two generations of encrypted session key:
///
/// - The RFC 2440-era PKESK v3 and SKESK v4, vs
/// - The RFC 9580 PKESK v6 and SKESK v6
#[derive(Debug, Copy, Clone)]
pub enum EskType {
    /// V3 PKESK or V4 SKESK (these are used in RFC 4880 and 2440)
    V3_4,

    /// V6 PKESK or SKESK (introduced in RFC 9580)
    V6,
}

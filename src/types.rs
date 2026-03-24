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

/// Specifies how SEIPDv1 encrypted messages are processed during decryption.
///
/// There is an inherent tradeoff when decrypting SEIPDv1 data:
/// Decryption be performed either in streaming mode, which releases plaintext before the message's
/// integrity has been checked. Or decryption first checks the integrity of the message, which
/// requires reading the complete message into memory first. This can be prohibitive for messages
/// that exceed the available memory.
///
/// The default mode is `CheckFirst`, since it is the more defensive choice.
/// In `CheckFirst` mode, the maximum message size (in bytes) can be specified. If an
/// encrypted message exceeds this limit, decryption returns an error (to avoid running out of
/// memory).
///
/// If decryption of prohibitively large SEIPDv1 messages is required, and the application can
/// safely process plaintext that is released before the integrity has been checked, then the
/// alternative `Streaming` mode can be used.
#[derive(derive_more::Debug, Clone, Copy, PartialEq, Eq)]
pub enum Seipdv1ReadMode {
    CheckFirst { max_message_size: usize },
    Streaming,
}

/// The maximum message length that we're willing to decrypt in non-streaming SEIPDv1 mode
const MAX_DEFAULT_UNSTREAMED_MSG_SIZE: usize = 1024 * 1024 * 1024;

impl Default for Seipdv1ReadMode {
    fn default() -> Self {
        Self::CheckFirst {
            max_message_size: MAX_DEFAULT_UNSTREAMED_MSG_SIZE,
        }
    }
}

/// A proxy parameter for use in `draft-wussler-openpgp-forwarding` message transformations.
/// <https://www.ietf.org/archive/id/draft-wussler-openpgp-forwarding-00.html#name-computing-the-proxy-paramet>
#[cfg(feature = "draft-wussler-openpgp-forwarding")]
#[derive(zeroize::ZeroizeOnDrop)]
pub struct ForwardingProxyParameter([u8; 32]);

#[cfg(feature = "draft-wussler-openpgp-forwarding")]
impl From<[u8; 32]> for ForwardingProxyParameter {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

#[cfg(feature = "draft-wussler-openpgp-forwarding")]
impl ForwardingProxyParameter {
    pub(crate) fn into_array(self) -> [u8; 32] {
        self.0
    }
}

#[cfg(feature = "draft-wussler-openpgp-forwarding")]
impl AsRef<[u8; 32]> for ForwardingProxyParameter {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

use crate::errors::{Error, Result};
use crate::types::KeyVersion;

/// Represents a Fingerprint.
#[derive(Clone, Eq, PartialEq, derive_more::Debug)]
pub enum Fingerprint {
    #[debug("{}", hex::encode(_0))]
    V2([u8; 16]),
    #[debug("{}", hex::encode(_0))]
    V3([u8; 16]),
    #[debug("{}", hex::encode(_0))]
    V4([u8; 20]),
    #[debug("{}", hex::encode(_0))]
    V5([u8; 32]),
    #[debug("{}", hex::encode(_0))]
    V6([u8; 32]),

    #[debug("{}", hex::encode(_0))]
    /// Fingerprint with unknown key version
    Other(Vec<u8>),
}

impl Fingerprint {
    pub fn new(version: KeyVersion, fp: &[u8]) -> Result<Self> {
        let fp = match version {
            KeyVersion::V2 => Fingerprint::V2(
                fp.try_into()
                    .map_err(|_| Error::Message("foo".to_string()))?,
            ),
            KeyVersion::V3 => Fingerprint::V3(
                fp.try_into()
                    .map_err(|_| Error::Message("foo".to_string()))?,
            ),
            KeyVersion::V4 => Fingerprint::V4(
                fp.try_into()
                    .map_err(|_| Error::Message("foo".to_string()))?,
            ),
            KeyVersion::V5 => Fingerprint::V5(
                fp.try_into()
                    .map_err(|_| Error::Message("foo".to_string()))?,
            ),
            KeyVersion::V6 => Fingerprint::V6(
                fp.try_into()
                    .map_err(|_| Error::Message("foo".to_string()))?,
            ),
            KeyVersion::Other(v) => bail!("Unsupported version {}", v),
        };

        Ok(fp)
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        match self {
            Self::V2(_) | Self::V3(_) => 16,
            Self::V4(_) => 20,
            Self::V5(_) | Self::V6(_) => 32,
            Self::Other(fp) => fp.len(),
        }
    }

    pub fn version(&self) -> Option<KeyVersion> {
        match self {
            Self::V2(_) => Some(KeyVersion::V2),
            Self::V3(_) => Some(KeyVersion::V3),
            Self::V4(_) => Some(KeyVersion::V4),
            Self::V5(_) => Some(KeyVersion::V5),
            Self::V6(_) => Some(KeyVersion::V6),
            Self::Other(_) => None,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::V2(fp) | Self::V3(fp) => &fp[..],
            Self::V4(fp) => &fp[..],
            Self::V5(fp) | Self::V6(fp) => &fp[..],
            Self::Other(fp) => fp,
        }
    }
}

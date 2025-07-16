use crate::{
    errors::{bail, format_err, Result},
    types::KeyVersion,
};

/// Represents a Fingerprint.
///
/// OpenPGP fingerprints consist of two pieces of information:
/// The key version, and binary data that represents the fingerprint itself.
#[derive(Clone, Eq, Hash, PartialEq, derive_more::Debug, derive_more::Display)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum Fingerprint {
    #[debug("{}", hex::encode(_0))]
    #[display("{}", hex::encode(_0))]
    V2([u8; 16]),
    #[debug("{}", hex::encode(_0))]
    #[display("{}", hex::encode(_0))]
    V3([u8; 16]),
    #[debug("{}", hex::encode(_0))]
    #[display("{}", hex::encode(_0))]
    V4([u8; 20]),
    #[debug("{}", hex::encode(_0))]
    #[display("{}", hex::encode(_0))]
    V5([u8; 32]),
    #[debug("{}", hex::encode(_0))]
    #[display("{}", hex::encode(_0))]
    V6([u8; 32]),

    #[debug("{}", hex::encode(_0))]
    #[display("{}", hex::encode(_0))]
    #[cfg_attr(test, proptest(skip))]
    /// Fingerprint with unknown key version
    Unknown(Box<[u8]>),
}

impl Fingerprint {
    /// Constructor for an OpenPGP fingerprint.
    ///
    /// The length of the binary data in `fp` must match the expected length for `version`,
    /// otherwise an error is returned.
    pub fn new(version: KeyVersion, fp: &[u8]) -> Result<Self> {
        let e = |_| {
            format_err!(
                "Illegal fingerprint length {} for key version {:?}",
                fp.len(),
                version
            )
        };

        let fp = match version {
            KeyVersion::V2 => Fingerprint::V2(fp.try_into().map_err(e)?),
            KeyVersion::V3 => Fingerprint::V3(fp.try_into().map_err(e)?),
            KeyVersion::V4 => Fingerprint::V4(fp.try_into().map_err(e)?),
            KeyVersion::V5 => Fingerprint::V5(fp.try_into().map_err(e)?),
            KeyVersion::V6 => Fingerprint::V6(fp.try_into().map_err(e)?),

            KeyVersion::Other(v) => bail!("Unsupported version {}", v),
        };

        Ok(fp)
    }

    /// Make a fingerprint with unknown key version.
    ///
    /// A fingerprint without version information is not usually desirable to have.
    /// It can't be processed in a lot of places, in rPGP.
    ///
    /// However, sometimes a fingerprint may be obtained where the key version is unknown.
    /// Then, this is the only possible way to encode it.
    #[allow(dead_code)]
    pub(crate) fn new_unknown(fp: &[u8]) -> Result<Self> {
        Ok(Fingerprint::Unknown(Box::from(fp)))
    }

    /// Returns the length of the fingerprint's binary data, based on the key version.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        match self {
            Self::V2(_) | Self::V3(_) => 16,
            Self::V4(_) => 20,
            Self::V5(_) | Self::V6(_) => 32,
            Self::Unknown(fp) => fp.len(),
        }
    }

    /// The key version of the key that this fingerprint references.
    pub fn version(&self) -> Option<KeyVersion> {
        match self {
            Self::V2(_) => Some(KeyVersion::V2),
            Self::V3(_) => Some(KeyVersion::V3),
            Self::V4(_) => Some(KeyVersion::V4),
            Self::V5(_) => Some(KeyVersion::V5),
            Self::V6(_) => Some(KeyVersion::V6),
            Self::Unknown(_) => None,
        }
    }

    /// The binary data of this fingerprint.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::V2(fp) | Self::V3(fp) => &fp[..],
            Self::V4(fp) => &fp[..],
            Self::V5(fp) | Self::V6(fp) => &fp[..],
            Self::Unknown(fp) => fp,
        }
    }
}

impl AsRef<[u8]> for Fingerprint {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl std::fmt::UpperHex for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode_upper(self))
    }
}

impl std::fmt::LowerHex for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_as_ref() {
        let fingerprint = Fingerprint::V4([0; 20]);
        // hex::encode accepts AsRef<[u8]>s
        assert_eq!(
            "0000000000000000000000000000000000000000",
            hex::encode(fingerprint)
        );
    }

    #[test]
    fn fingerprint_upper_hex() {
        let fingerprint = Fingerprint::V4([10; 20]);
        assert_eq!(
            "0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A",
            format!("{fingerprint:X}")
        );
    }

    #[test]
    fn fingerprint_lower_hex() {
        let fingerprint = Fingerprint::V4([10; 20]);
        assert_eq!(
            "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
            format!("{fingerprint:x}")
        );
    }
}

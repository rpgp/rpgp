/// Represents a Key ID.
///
/// This ID is always 8 bytes long, but calculated differntly, depending on the key version.
///
/// <https://www.rfc-editor.org/rfc/rfc9580.html#section-5.5.4>
#[derive(Clone, Copy, Hash, Eq, PartialEq, derive_more::Debug, derive_more::Display)]
#[display("{}", hex::encode(_0))]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct KeyId(#[debug("{}", hex::encode(_0))] [u8; 8]);

impl AsRef<[u8]> for KeyId {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<[u8; 8]> for KeyId {
    fn from(value: [u8; 8]) -> Self {
        Self::new(value)
    }
}

impl KeyId {
    /// The wild card ID, representing an "anonymous recipient".
    pub const WILDCARD: KeyId = KeyId([0u8; 8]);

    /// Creates a new fingerprint based on the provided bytes.
    pub const fn new(id: [u8; 8]) -> Self {
        Self(id)
    }

    /// True, if `self` is the "wild card" (or "anonymous recipient") Key ID of all zeros.
    ///
    /// See <https://www.rfc-editor.org/rfc/rfc9580.html#pkesk-notes>
    pub fn is_wildcard(&self) -> bool {
        self == &Self::WILDCARD
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display() {
        let keyid = KeyId::new([0x4C, 0x07, 0x3A, 0xE0, 0xC8, 0x44, 0x5C, 0x0C]);
        assert_eq!("4c073ae0c8445c0c", format!("{keyid}"));
    }

    #[test]
    fn test_wildcard() {
        assert!(KeyId::WILDCARD.is_wildcard());
        assert!(KeyId::from([0u8; 8]).is_wildcard());

        assert!(!KeyId::from([1u8; 8]).is_wildcard());
    }
}

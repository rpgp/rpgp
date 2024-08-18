use std::fmt;

use crate::errors::Result;

/// Represents a Key ID.
#[derive(Clone, Eq, PartialEq, derive_more::Debug)]
pub struct KeyId(#[debug("{}", hex::encode(_0))] [u8; 8]);

impl AsRef<[u8]> for KeyId {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl KeyId {
    pub fn from_slice(input: &[u8]) -> Result<KeyId> {
        ensure_eq!(input.len(), 8, "invalid input length");
        let mut r = [0u8; 8];
        r.copy_from_slice(input);

        Ok(KeyId(r))
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn is_wildcard(&self) -> bool {
        self.0 == [0, 0, 0, 0, 0, 0, 0, 0]
    }
}

impl fmt::LowerHex for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.as_ref()))
    }
}

impl fmt::UpperHex for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut encoded = hex::encode(self.as_ref());
        encoded.make_ascii_uppercase();
        write!(f, "{encoded}")
    }
}

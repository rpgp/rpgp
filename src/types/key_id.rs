use std::fmt;

use errors::Result;
use hex;

/// Represents a Key ID.
#[derive(Clone, Eq, PartialEq)]
pub struct KeyId([u8; 8]);

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
}

impl fmt::Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "KeyId({})", hex::encode(self.as_ref()))
    }
}

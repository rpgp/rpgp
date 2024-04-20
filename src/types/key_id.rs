use std::fmt;

use nom::{AsBytes, InputLength};

use crate::errors::Result;

/// Represents a Key ID.
#[derive(Clone, Eq, PartialEq)]
pub struct KeyId([u8; 8]);

impl AsRef<[u8]> for KeyId {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl KeyId {
    pub fn from_slice<I>(input: I) -> Result<KeyId>
    where
        I: AsBytes + InputLength,
    {
        ensure_eq!(input.input_len(), 8, "invalid input length");
        let mut r = [0u8; 8];
        r.copy_from_slice(input.as_bytes());

        Ok(KeyId(r))
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl fmt::Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyId({})", hex::encode(self.as_ref()))
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

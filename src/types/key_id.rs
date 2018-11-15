use errors::Result;

/// Represents a Key ID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyId([u8; 8]);

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

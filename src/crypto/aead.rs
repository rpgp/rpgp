use num_enum::{IntoPrimitive, TryFromPrimitive};

/// Available AEAD algorithms.
#[derive(Debug, PartialEq, Eq, Copy, Clone, TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum AeadAlgorithm {
    /// None
    None = 0,
    Eax = 1,
    Ocb = 2,
    Gcm = 3,

    Private100 = 100,
    Private101 = 101,
    Private102 = 102,
    Private103 = 103,
    Private104 = 104,
    Private105 = 105,
    Private106 = 106,
    Private107 = 107,
    Private108 = 108,
    Private109 = 109,
    Private110 = 110,

    #[num_enum(catch_all)]
    Other(u8),
}

impl Default for AeadAlgorithm {
    fn default() -> Self {
        AeadAlgorithm::None
    }
}

impl AeadAlgorithm {
    /// Nonce size used for this AEAD algorithm.
    pub fn nonce_size(&self) -> usize {
        // TODO: verify this is correct
        16
    }
}

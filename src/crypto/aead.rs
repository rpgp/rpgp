use num_enum::TryFromPrimitive;

/// Available AEAD algorithms.
#[derive(Debug, PartialEq, Eq, Copy, Clone, TryFromPrimitive)]
#[repr(u8)]
#[derive(Default)]
pub enum AeadAlgorithm {
    /// None
    #[default]
    None = 0,
    Eax = 1,
    Ocb = 2,
}

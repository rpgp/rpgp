/// Available AEAD algorithms.
#[derive(Debug, PartialEq, Eq, Copy, Clone, FromPrimitive)]
#[repr(u8)]
#[derive(Default)]
pub enum AeadAlgorithm {
    /// None
    #[default]
    None = 0,
    Eax = 1,
    Ocb = 2,
}



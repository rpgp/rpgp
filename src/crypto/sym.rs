enum_from_primitive!{
#[derive(Debug, PartialEq, Eq, Clone)]
/// Available symmetric key algorithms.
pub enum SymmetricKeyAlgorithm {
    /// Plaintext or unencrypted data
    Plaintext = 0,
    IDEA = 1,
    /// TripleDES (DES-EDE, 168 bit key derived from 192)
    TripleDES = 2,
    /// CAST5 (128 bit key, as per [RFC2144])
    CAST5 = 3,
    /// Blowfish (128 bit key, 16 rounds)
    Blowfish = 4,
    AES128 = 7,
    AES192 = 8,
    AES256 = 9,
    /// Twofish with 256-bit key [TWOFISH]
    Twofish = 10,
}
}

impl SymmetricKeyAlgorithm {
    /// The size of a single block in bytes.
    /// Based on https://github.com/gpg/libgcrypt/blob/master/cipher
    pub fn block_size(&self) -> usize {
        match self {
            SymmetricKeyAlgorithm::Plaintext => 0,
            SymmetricKeyAlgorithm::IDEA => 8,
            SymmetricKeyAlgorithm::TripleDES => 8,
            SymmetricKeyAlgorithm::CAST5 => 8,
            SymmetricKeyAlgorithm::Blowfish => 16,
            SymmetricKeyAlgorithm::AES128 => 16,
            SymmetricKeyAlgorithm::AES192 => 16,
            SymmetricKeyAlgorithm::AES256 => 16,
            SymmetricKeyAlgorithm::Twofish => 16,
        }
    }

    /// The size of a single block in bytes.
    /// Based on https://github.com/gpg/libgcrypt/blob/master/cipher
    pub fn key_size(&self) -> usize {
        match self {
            SymmetricKeyAlgorithm::Plaintext => 0,
            SymmetricKeyAlgorithm::IDEA => 16,
            SymmetricKeyAlgorithm::TripleDES => 24,
            SymmetricKeyAlgorithm::CAST5 => 16,
            SymmetricKeyAlgorithm::Blowfish => 16,
            SymmetricKeyAlgorithm::AES128 => 16,
            SymmetricKeyAlgorithm::AES192 => 24,
            SymmetricKeyAlgorithm::AES256 => 32,
            SymmetricKeyAlgorithm::Twofish => 32,
        }
    }
}

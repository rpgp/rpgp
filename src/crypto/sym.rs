use aes_soft::{Aes128, Aes192, Aes256, BlockCipher};
use block_modes::block_padding::ZeroPadding;
use block_modes::{BlockMode, BlockModeIv, Cfb};
use generic_array::GenericArray;

use errors::Result;

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

    /// Decrypt the data using CFB mode, without padding. Overwrites the input.
    pub fn decrypt(&self, key: &[u8], ciphertext: &mut [u8]) -> Result<()> {
        let iv_vec = vec![0u8; self.block_size()];
        let iv = GenericArray::from_slice(&iv_vec);

        match self {
            SymmetricKeyAlgorithm::Plaintext => Ok(()),
            SymmetricKeyAlgorithm::IDEA => unimplemented!("IDEA encrypt"),
            SymmetricKeyAlgorithm::TripleDES => unimplemented!("IDEA encrypt"),
            SymmetricKeyAlgorithm::CAST5 => unimplemented!("CAST5 encrypt"),
            SymmetricKeyAlgorithm::Blowfish => unimplemented!("Blowfish encrypt"),
            SymmetricKeyAlgorithm::AES128 => {
                let mut mode = Cfb::<Aes128, ZeroPadding>::new_varkey(key, iv)?;
                mode.decrypt_nopad(ciphertext)?;
                Ok(())
            }
            SymmetricKeyAlgorithm::AES192 => {
                let mut mode = Cfb::<Aes192, ZeroPadding>::new_varkey(key, iv)?;
                mode.decrypt_nopad(ciphertext)?;
                Ok(())
            }
            SymmetricKeyAlgorithm::AES256 => {
                let mut mode = Cfb::<Aes256, ZeroPadding>::new_varkey(key, iv)?;
                mode.decrypt_nopad(ciphertext)?;
                Ok(())
            }
            SymmetricKeyAlgorithm::Twofish => unimplemented!("Twofish encrypt"),
        }
    }

    /// Encrypt the data using CFB mode, without padding. Overwrites the input.
    pub fn encrypt(&self, key: &[u8], plaintext: &mut [u8]) -> Result<()> {
        let iv_vec = vec![0u8; self.block_size()];
        let iv = GenericArray::from_slice(&iv_vec);

        match self {
            SymmetricKeyAlgorithm::Plaintext => Ok(()),
            SymmetricKeyAlgorithm::IDEA => unimplemented!("IDEA encrypt"),
            SymmetricKeyAlgorithm::TripleDES => unimplemented!("IDEA encrypt"),
            SymmetricKeyAlgorithm::CAST5 => unimplemented!("CAST5 encrypt"),
            SymmetricKeyAlgorithm::Blowfish => unimplemented!("Blowfish encrypt"),
            SymmetricKeyAlgorithm::AES128 => {
                let mut mode = Cfb::<Aes128, ZeroPadding>::new_varkey(key, iv)?;
                mode.encrypt_nopad(plaintext)?;
                Ok(())
            }
            SymmetricKeyAlgorithm::AES192 => {
                let mut mode = Cfb::<Aes192, ZeroPadding>::new_varkey(key, iv)?;
                mode.encrypt_nopad(plaintext)?;
                Ok(())
            }
            SymmetricKeyAlgorithm::AES256 => {
                let mut mode = Cfb::<Aes256, ZeroPadding>::new_varkey(key, iv)?;
                mode.encrypt_nopad(plaintext)?;
                Ok(())
            }
            SymmetricKeyAlgorithm::Twofish => unimplemented!("Twofish encrypt"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! roundtrip {
        ($name:ident, $alg:path) => {
            #[test]
            fn $name() {
                let data = vec![2u8; 256];
                let key = vec![1u8; $alg.key_size()];

                let mut ciphertext = data.clone();
                $alg.encrypt(&key, &mut ciphertext).unwrap();
                assert_ne!(data, ciphertext);

                let mut plaintext = ciphertext.clone();
                $alg.decrypt(&key, &mut plaintext).unwrap();
                assert_eq!(data, plaintext);
            }
        };
    }

    roundtrip!(roundtrip_aes128, SymmetricKeyAlgorithm::AES128);
    roundtrip!(roundtrip_aes192, SymmetricKeyAlgorithm::AES192);
    roundtrip!(roundtrip_aes256, SymmetricKeyAlgorithm::AES256);
}

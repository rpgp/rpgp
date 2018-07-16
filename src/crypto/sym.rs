use aes_soft::block_cipher_trait::generic_array::GenericArray;
use aes_soft::{Aes128, Aes192, Aes256};
use block_modes::block_padding::ZeroPadding;
use block_modes::{BlockMode, BlockModeIv, Cfb};
use blowfish::Blowfish;
use des::TdesEde3;
use twofish::Twofish;

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
            SymmetricKeyAlgorithm::Blowfish => 8,
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
    /// Uses an IV of all zeroes, as specified in the openpgp cfb mode.
    pub fn decrypt(&self, key: &[u8], ciphertext: &mut [u8]) -> Result<()> {
        let iv_vec = vec![0u8; self.block_size()];
        self.decrypt_with_iv(key, &iv_vec, ciphertext)
    }

    /// Decrypt the data using CFB mode, without padding. Overwrites the input.
    pub fn decrypt_with_iv(&self, key: &[u8], iv_vec: &[u8], ciphertext: &mut [u8]) -> Result<()> {
        let rounds = ciphertext.len() / self.block_size();
        let ciphertext = &mut ciphertext[0..rounds * self.block_size()];
        match self {
            SymmetricKeyAlgorithm::Plaintext => {}
            SymmetricKeyAlgorithm::IDEA => unimplemented!("IDEA encrypt"),
            SymmetricKeyAlgorithm::TripleDES => {
                let iv = GenericArray::from_slice(&iv_vec);
                let mut mode = Cfb::<TdesEde3, ZeroPadding>::new_varkey(key, iv)?;
                mode.decrypt_nopad(ciphertext)?;
            }
            SymmetricKeyAlgorithm::CAST5 => unimplemented!("CAST5 encrypt"),
            SymmetricKeyAlgorithm::Blowfish => {
                let iv = GenericArray::from_slice(&iv_vec);
                let mut mode = Cfb::<Blowfish, ZeroPadding>::new_varkey(key, iv)?;
                mode.decrypt_nopad(ciphertext)?;
            }
            SymmetricKeyAlgorithm::AES128 => {
                let iv = GenericArray::from_slice(&iv_vec);
                let mut mode = Cfb::<Aes128, ZeroPadding>::new_varkey(key, iv)?;
                mode.decrypt_nopad(ciphertext)?;
            }
            SymmetricKeyAlgorithm::AES192 => {
                let iv = GenericArray::from_slice(&iv_vec);
                let mut mode = Cfb::<Aes192, ZeroPadding>::new_varkey(key, iv)?;
                mode.decrypt_nopad(ciphertext)?;
            }
            SymmetricKeyAlgorithm::AES256 => {
                let iv = GenericArray::from_slice(&iv_vec);
                let mut mode = Cfb::<Aes256, ZeroPadding>::new_varkey(key, iv)?;
                mode.decrypt_nopad(ciphertext)?;
            }
            SymmetricKeyAlgorithm::Twofish => {
                let iv = GenericArray::from_slice(&iv_vec);
                let mut mode = Cfb::<Twofish, ZeroPadding>::new_varkey(key, iv)?;
                mode.decrypt_nopad(ciphertext)?;
            }
        }
        Ok(())
    }

    /// Encrypt the data using CFB mode, without padding. Overwrites the input.
    /// Uses an IV of all zeroes, as specified in the openpgp cfb mode.
    pub fn encrypt(&self, key: &[u8], ciphertext: &mut [u8]) -> Result<()> {
        let iv_vec = vec![0u8; self.block_size()];
        self.encrypt_with_iv(key, &iv_vec, ciphertext)
    }

    /// Encrypt the data using CFB mode, without padding. Overwrites the input.
    pub fn encrypt_with_iv(&self, key: &[u8], iv_vec: &[u8], plaintext: &mut [u8]) -> Result<()> {
        match self {
            SymmetricKeyAlgorithm::Plaintext => {}
            SymmetricKeyAlgorithm::IDEA => unimplemented!("IDEA encrypt"),
            SymmetricKeyAlgorithm::TripleDES => {
                let iv = GenericArray::from_slice(&iv_vec);
                let mut mode = Cfb::<TdesEde3, ZeroPadding>::new_varkey(key, iv)?;
                mode.encrypt_nopad(plaintext)?;
            }
            SymmetricKeyAlgorithm::CAST5 => unimplemented!("CAST5 encrypt"),
            SymmetricKeyAlgorithm::Blowfish => {
                let iv = GenericArray::from_slice(&iv_vec);
                let mut mode = Cfb::<Blowfish, ZeroPadding>::new_varkey(key, iv)?;
                mode.encrypt_nopad(plaintext)?;
            }
            SymmetricKeyAlgorithm::AES128 => {
                let iv = GenericArray::from_slice(&iv_vec);
                let mut mode = Cfb::<Aes128, ZeroPadding>::new_varkey(key, iv)?;
                mode.encrypt_nopad(plaintext)?;
            }
            SymmetricKeyAlgorithm::AES192 => {
                let iv = GenericArray::from_slice(&iv_vec);
                let mut mode = Cfb::<Aes192, ZeroPadding>::new_varkey(key, iv)?;
                mode.encrypt_nopad(plaintext)?;
            }
            SymmetricKeyAlgorithm::AES256 => {
                let iv = GenericArray::from_slice(&iv_vec);
                let mut mode = Cfb::<Aes256, ZeroPadding>::new_varkey(key, iv)?;
                mode.encrypt_nopad(plaintext)?;
            }
            SymmetricKeyAlgorithm::Twofish => {
                let iv = GenericArray::from_slice(&iv_vec);
                let mut mode = Cfb::<Twofish, ZeroPadding>::new_varkey(key, iv)?;
                mode.encrypt_nopad(plaintext)?;
            }
        }
        Ok(())
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
    roundtrip!(roundtrip_tripledes, SymmetricKeyAlgorithm::TripleDES);
    roundtrip!(roundtrip_blowfish, SymmetricKeyAlgorithm::Blowfish);
    roundtrip!(roundtrip_twofish, SymmetricKeyAlgorithm::Twofish);
}

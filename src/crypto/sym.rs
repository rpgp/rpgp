use aes::{Aes128, Aes192, Aes256};
use blowfish::Blowfish;
use cfb_mode::Cfb;
use des::TdesEde3;
use twofish::Twofish;

use errors::Result;

macro_rules! decrypt {
    ($mode:ident, $key:expr, $iv:expr, $prefix:expr, $data:expr, $bs:expr, $resync:expr) => {{
        let mut mode = Cfb::<$mode>::new_var($key, $iv)?;
        mode.decrypt($prefix);

        // TODO: proper error
        // quick check, before decrypting the rest
        assert_eq!($prefix[$bs - 2], $prefix[$bs], "quick check part 1");
        assert_eq!($prefix[$bs - 1], $prefix[$bs + 1], "quick check part 2");

        if $resync {
            unimplemented!();
        } else {
            mode.decrypt($data);
        }
    }};
}

macro_rules! decrypt_regular {
    ($mode:ident, $key:expr, $iv:expr, $ciphertext:expr, $bs:expr) => {{
        let mut mode = Cfb::<$mode>::new_var($key, $iv)?;
        mode.decrypt($ciphertext);
    }};
}
macro_rules! encrypt_regular {
    ($mode:ident, $key:expr, $iv:expr, $plaintext:expr, $bs:expr) => {{
        let mut mode = Cfb::<$mode>::new_var($key, $iv)?;
        mode.encrypt($plaintext);
    }};
}
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
    /// Uses an IV of all zeroes, as specified in the openpgp cfb mode. Does
    /// resynchronization.
    pub fn decrypt<'a>(&self, key: &[u8], ciphertext: &'a mut [u8]) -> Result<&'a [u8]> {
        println!("unprotected decrypt");
        let iv_vec = vec![0u8; self.block_size()];
        self.decrypt_with_iv(key, &iv_vec, ciphertext, true)
    }

    /// Decrypt the data using CFB mode, without padding. Overwrites the input.
    /// Uses an IV of all zeroes, as specified in the openpgp cfb mode.
    /// Does not do resynchronization.
    pub fn decrypt_protected<'a>(&self, key: &[u8], ciphertext: &'a mut [u8]) -> Result<&'a [u8]> {
        println!("{}", hex::encode(&ciphertext));
        println!("protected decrypt");
        let iv_vec = vec![0u8; self.block_size()];
        let cv_len = ciphertext.len();
        let res = self.decrypt_with_iv(key, &iv_vec, ciphertext, false)?;
        println!("{}", hex::encode(&res));
        // MDC is 1 byte packet tag, 1 byte length prefix and 20 bytes SHA1 hash.
        let mdc_len = 22;
        let (data, mdc) = res.split_at(res.len() - mdc_len);
        println!(
            "decrypted {}b from {}b ({}|{})",
            res.len(),
            cv_len,
            data.len(),
            mdc.len()
        );
        // TODO: Proper error handling
        assert_eq!(mdc[0], 0xD3, "invalid MDC tag");
        assert_eq!(mdc[1], 0x14, "invalid MDC length");
        // TODO: hash and compare to mdc[2..];
        println!("mdc: {}", hex::encode(mdc));

        Ok(data)
    }

    /// Decrypt the data using CFB mode, without padding. Overwrites the input.
    ///
    /// OpenPGP CFB mode uses an initialization vector (IV) of all zeros, and
    /// prefixes the plaintext with BS+2 octets of random data, such that
    /// octets BS+1 and BS+2 match octets BS-1 and BS.  It does a CFB
    /// resynchronization after encrypting those BS+2 octets.
    ///
    /// Thus, for an algorithm that has a block size of 8 octets (64 bits),
    /// the IV is 10 octets long and octets 7 and 8 of the IV are the same as
    /// octets 9 and 10.  For an algorithm with a block size of 16 octets
    /// (128 bits), the IV is 18 octets long, and octets 17 and 18 replicate
    /// octets 15 and 16.  Those extra two octets are an easy check for a
    /// correct key.
    pub fn decrypt_with_iv<'a>(
        &self,
        key: &[u8],
        iv_vec: &[u8],
        ciphertext: &'a mut [u8],
        resync: bool,
    ) -> Result<&'a [u8]> {
        let bs = self.block_size();

        let (encrypted_prefix, encrypted_data) = ciphertext.split_at_mut(bs + 2);

        {
            match self {
                SymmetricKeyAlgorithm::Plaintext => {}
                SymmetricKeyAlgorithm::IDEA => unimplemented!("IDEA encrypt"),
                SymmetricKeyAlgorithm::TripleDES => {
                    decrypt!(
                        TdesEde3,
                        key,
                        &iv_vec,
                        encrypted_prefix,
                        encrypted_data,
                        bs,
                        resync
                    );
                }
                SymmetricKeyAlgorithm::CAST5 => unimplemented!("CAST5 encrypt"),
                SymmetricKeyAlgorithm::Blowfish => decrypt!(
                    Blowfish,
                    key,
                    &iv_vec,
                    encrypted_prefix,
                    encrypted_data,
                    bs,
                    resync
                ),
                SymmetricKeyAlgorithm::AES128 => decrypt!(
                    Aes128,
                    key,
                    &iv_vec,
                    encrypted_prefix,
                    encrypted_data,
                    bs,
                    resync
                ),
                SymmetricKeyAlgorithm::AES192 => decrypt!(
                    Aes192,
                    key,
                    &iv_vec,
                    encrypted_prefix,
                    encrypted_data,
                    bs,
                    resync
                ),
                SymmetricKeyAlgorithm::AES256 => decrypt!(
                    Aes256,
                    key,
                    &iv_vec,
                    encrypted_prefix,
                    encrypted_data,
                    bs,
                    resync
                ),
                SymmetricKeyAlgorithm::Twofish => decrypt!(
                    Twofish,
                    key,
                    &iv_vec,
                    encrypted_prefix,
                    encrypted_data,
                    bs,
                    resync
                ),
            }
        }

        Ok(encrypted_data)
    }

    /// Decrypt the data using CFB mode, without padding. Overwrites the input.
    /// This is regular CFB, not OpenPgP CFB.
    pub fn decrypt_with_iv_regular<'a>(
        &self,
        key: &[u8],
        iv_vec: &[u8],
        ciphertext: &'a mut [u8],
    ) -> Result<()> {
        let bs = self.block_size();
        {
            match self {
                SymmetricKeyAlgorithm::Plaintext => {}
                SymmetricKeyAlgorithm::IDEA => unimplemented!("IDEA encrypt"),
                SymmetricKeyAlgorithm::TripleDES => {
                    decrypt_regular!(TdesEde3, key, &iv_vec, ciphertext, bs);
                }
                SymmetricKeyAlgorithm::CAST5 => unimplemented!("CAST5 encrypt"),
                SymmetricKeyAlgorithm::Blowfish => {
                    decrypt_regular!(Blowfish, key, &iv_vec, ciphertext, bs)
                }
                SymmetricKeyAlgorithm::AES128 => {
                    decrypt_regular!(Aes128, key, &iv_vec, ciphertext, bs)
                }
                SymmetricKeyAlgorithm::AES192 => {
                    decrypt_regular!(Aes192, key, &iv_vec, ciphertext, bs)
                }
                SymmetricKeyAlgorithm::AES256 => {
                    decrypt_regular!(Aes256, key, &iv_vec, ciphertext, bs)
                }
                SymmetricKeyAlgorithm::Twofish => {
                    decrypt_regular!(Twofish, key, &iv_vec, ciphertext, bs)
                }
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
        // TODO: actual cfb mode used in pgp
        match self {
            SymmetricKeyAlgorithm::Plaintext => {}
            SymmetricKeyAlgorithm::IDEA => unimplemented!("IDEA encrypt"),
            SymmetricKeyAlgorithm::TripleDES => {
                encrypt_regular!(TdesEde3, key, &iv_vec, plaintext, bs);
            }
            SymmetricKeyAlgorithm::CAST5 => unimplemented!("CAST5 encrypt"),
            SymmetricKeyAlgorithm::Blowfish => {
                encrypt_regular!(Blowfish, key, &iv_vec, plaintext, bs)
            }
            SymmetricKeyAlgorithm::AES128 => encrypt_regular!(Aes128, key, &iv_vec, plaintext, bs),
            SymmetricKeyAlgorithm::AES192 => encrypt_regular!(Aes192, key, &iv_vec, plaintext, bs),
            SymmetricKeyAlgorithm::AES256 => encrypt_regular!(Aes256, key, &iv_vec, plaintext, bs),
            SymmetricKeyAlgorithm::Twofish => {
                encrypt_regular!(Twofish, key, &iv_vec, plaintext, bs)
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

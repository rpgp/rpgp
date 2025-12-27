use aes::{Aes128, Aes192, Aes256};
use blowfish::Blowfish;
use camellia::{Camellia128, Camellia192, Camellia256};
use cast5::Cast5;
use cfb_mode::{
    cipher::{AsyncStreamCipher, KeyIvInit},
    BufEncryptor, Decryptor, Encryptor,
};
use cipher::{BlockCipher, BlockDecrypt, BlockEncryptMut};
use des::TdesEde3;
use idea::Idea;
use log::debug;
use num_enum::{FromPrimitive, IntoPrimitive};
use rand::{CryptoRng, Rng};
use twofish::Twofish;
use zeroize::Zeroizing;

use crate::{
    composed::RawSessionKey,
    errors::{bail, unimplemented_err, Result},
};

mod decryptor;
mod encryptor;

pub use self::{decryptor::StreamDecryptor, encryptor::StreamEncryptor};

fn encrypt<MODE>(key: &[u8], iv: &[u8], prefix: &mut [u8], data: &mut [u8]) -> Result<()>
where
    MODE: BlockDecrypt + BlockEncryptMut + BlockCipher,
    BufEncryptor<MODE>: KeyIvInit,
{
    let mut mode = BufEncryptor::<MODE>::new_from_slices(key, iv)?;
    mode.encrypt(prefix);

    mode.encrypt(data);

    Ok(())
}

/// Legacy format using OpengPGP CFB Mode
///
/// <https://datatracker.ietf.org/doc/html/rfc4880.html#section-13.9>
fn encrypt_resync<MODE>(key: &[u8], iv: &[u8], prefix: &mut [u8], data: &mut [u8]) -> Result<()>
where
    MODE: BlockDecrypt + BlockEncryptMut + BlockCipher,
    BufEncryptor<MODE>: KeyIvInit,
{
    let mut mode = BufEncryptor::<MODE>::new_from_slices(key, iv)?;
    mode.encrypt(prefix);

    // resync
    mode = BufEncryptor::<MODE>::new_from_slices(key, &prefix[2..])?;
    mode.encrypt(data);

    Ok(())
}

/// Available symmetric key algorithms.
/// Ref: <https://www.rfc-editor.org/rfc/rfc9580.html#name-symmetric-key-algorithms>
#[derive(Debug, PartialEq, Eq, Copy, Clone, FromPrimitive, IntoPrimitive)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
#[repr(u8)]
#[non_exhaustive]
pub enum SymmetricKeyAlgorithm {
    /// Plaintext or unencrypted data
    #[cfg_attr(test, proptest(skip))]
    Plaintext = 0,
    /// IDEA
    IDEA = 1,
    /// Triple-DES
    TripleDES = 2,
    /// CAST5
    CAST5 = 3,
    /// Blowfish
    Blowfish = 4,
    // 5 & 6 are reserved for DES/SK
    /// AES with 128-bit key
    AES128 = 7,
    /// AES with 192-bit key
    AES192 = 8,
    /// AES with 256-bit key
    AES256 = 9,
    /// Twofish with 256-bit key
    Twofish = 10,
    /// [Camellia](https://tools.ietf.org/html/rfc5581#section-3) with 128-bit key
    Camellia128 = 11,
    /// [Camellia](https://tools.ietf.org/html/rfc5581#section-3) with 192-bit key
    Camellia192 = 12,
    /// [Camellia](https://tools.ietf.org/html/rfc5581#section-3) with 256-bit key
    Camellia256 = 13,
    Private10 = 110,

    #[num_enum(catch_all)]
    Other(#[cfg_attr(test, proptest(strategy = "111u8.."))] u8),
}

#[allow(clippy::derivable_impls)]
impl Default for SymmetricKeyAlgorithm {
    fn default() -> Self {
        Self::AES128
    }
}

impl zeroize::DefaultIsZeroes for SymmetricKeyAlgorithm {}

impl SymmetricKeyAlgorithm {
    /// The size of a single block in bytes.
    /// Based on <https://github.com/gpg/libgcrypt/blob/master/cipher>
    pub fn block_size(self) -> usize {
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
            SymmetricKeyAlgorithm::Camellia128 => 16,
            SymmetricKeyAlgorithm::Camellia192 => 16,
            SymmetricKeyAlgorithm::Camellia256 => 16,
            SymmetricKeyAlgorithm::Private10 | SymmetricKeyAlgorithm::Other(_) => 0,
        }
    }

    /// The size of a single block in bytes.
    /// Based on <https://github.com/gpg/libgcrypt/blob/master/cipher>
    pub const fn key_size(self) -> usize {
        match self {
            SymmetricKeyAlgorithm::Plaintext => 0,
            SymmetricKeyAlgorithm::IDEA => 16,
            SymmetricKeyAlgorithm::TripleDES => 24,
            SymmetricKeyAlgorithm::CAST5 => 16,
            // TODO: Validate this is the right key size.
            SymmetricKeyAlgorithm::Blowfish => 16, //56,
            SymmetricKeyAlgorithm::AES128 => 16,
            SymmetricKeyAlgorithm::AES192 => 24,
            SymmetricKeyAlgorithm::AES256 => 32,
            SymmetricKeyAlgorithm::Twofish => 32,
            SymmetricKeyAlgorithm::Camellia128 => 16,
            SymmetricKeyAlgorithm::Camellia192 => 24,
            SymmetricKeyAlgorithm::Camellia256 => 32,

            SymmetricKeyAlgorithm::Private10 | SymmetricKeyAlgorithm::Other(_) => 0,
        }
    }

    /// Decrypt the data using CFB mode, without padding. Overwrites the input.
    /// This is regular CFB, not OpenPgP CFB.
    pub fn decrypt_with_iv_regular(
        self,
        key: &[u8],
        iv_vec: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<()> {
        match self {
            SymmetricKeyAlgorithm::Plaintext => {
                bail!("'Plaintext' is not a legal cipher for encrypted data")
            }
            SymmetricKeyAlgorithm::IDEA => {
                Decryptor::<Idea>::new_from_slices(key, iv_vec)?.decrypt(ciphertext);
            }
            SymmetricKeyAlgorithm::TripleDES => {
                Decryptor::<TdesEde3>::new_from_slices(key, iv_vec)?.decrypt(ciphertext);
            }
            SymmetricKeyAlgorithm::CAST5 => {
                Decryptor::<Cast5>::new_from_slices(key, iv_vec)?.decrypt(ciphertext);
            }
            SymmetricKeyAlgorithm::Blowfish => {
                Decryptor::<Blowfish>::new_from_slices(key, iv_vec)?.decrypt(ciphertext);
            }
            SymmetricKeyAlgorithm::AES128 => {
                Decryptor::<Aes128>::new_from_slices(key, iv_vec)?.decrypt(ciphertext);
            }
            SymmetricKeyAlgorithm::AES192 => {
                Decryptor::<Aes192>::new_from_slices(key, iv_vec)?.decrypt(ciphertext);
            }
            SymmetricKeyAlgorithm::AES256 => {
                Decryptor::<Aes256>::new_from_slices(key, iv_vec)?.decrypt(ciphertext);
            }
            SymmetricKeyAlgorithm::Twofish => {
                Decryptor::<Twofish>::new_from_slices(key, iv_vec)?.decrypt(ciphertext);
            }
            SymmetricKeyAlgorithm::Camellia128 => {
                Decryptor::<Camellia128>::new_from_slices(key, iv_vec)?.decrypt(ciphertext);
            }
            SymmetricKeyAlgorithm::Camellia192 => {
                Decryptor::<Camellia192>::new_from_slices(key, iv_vec)?.decrypt(ciphertext);
            }
            SymmetricKeyAlgorithm::Camellia256 => {
                Decryptor::<Camellia256>::new_from_slices(key, iv_vec)?.decrypt(ciphertext);
            }
            SymmetricKeyAlgorithm::Private10 | SymmetricKeyAlgorithm::Other(_) => {
                unimplemented_err!("SymmetricKeyAlgorithm {} is unsupported", u8::from(self))
            }
        }

        Ok(())
    }

    /// Encrypt the data using CFB mode, without padding. Overwrites the input.
    /// Uses an IV of all zeroes, as specified in the openpgp cfb mode.
    pub fn encrypt<R: CryptoRng + Rng>(
        self,
        mut rng: R,
        key: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        debug!("encrypt unprotected");

        let iv_vec = vec![0u8; self.block_size()];

        let bs = self.block_size();

        let prefix_len = bs + 2;
        let plaintext_len = plaintext.len();

        let mut ciphertext = vec![0u8; prefix_len + plaintext_len];
        // prefix
        rng.fill_bytes(&mut ciphertext[..bs]);

        // add quick check
        ciphertext[bs] = ciphertext[bs - 2];
        ciphertext[bs + 1] = ciphertext[bs - 1];

        // plaintext
        ciphertext[prefix_len..].copy_from_slice(plaintext);

        self.encrypt_with_iv_resync(key, &iv_vec, &mut ciphertext)?;

        Ok(ciphertext)
    }

    pub fn encrypt_protected<R: CryptoRng + Rng>(
        self,
        mut rng: R,
        key: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        // We use regular sha1 for MDC, not sha1_checked. Collisions are not currently a concern with MDC.
        use sha1::{Digest, Sha1};

        debug!("protected encrypt");

        // MDC is 1 byte packet tag, 1 byte length prefix and 20 bytes SHA1 hash.
        let mdc_len = 22;

        let bs = self.block_size();

        let prefix_len = bs + 2;
        let plaintext_len = plaintext.len();

        let mut ciphertext = vec![0u8; prefix_len + plaintext_len + mdc_len];

        // prefix
        rng.fill_bytes(&mut ciphertext[..bs]);

        // add quick check
        ciphertext[bs] = ciphertext[bs - 2];
        ciphertext[bs + 1] = ciphertext[bs - 1];

        // plaintext
        ciphertext[prefix_len..(prefix_len + plaintext_len)].copy_from_slice(plaintext);
        // mdc header
        ciphertext[prefix_len + plaintext_len] = 0xD3;
        ciphertext[prefix_len + plaintext_len + 1] = 0x14;
        // mdc body
        let checksum = &Sha1::digest(&ciphertext[..(prefix_len + plaintext_len + 2)])[..20];
        ciphertext[(prefix_len + plaintext_len + 2)..].copy_from_slice(checksum);

        // IV is all zeroes
        let iv_vec = vec![0u8; self.block_size()];

        self.encrypt_with_iv(key, &iv_vec, &mut ciphertext)?;

        Ok(ciphertext)
    }

    pub fn encrypted_protected_len(&self, plaintext_len: usize) -> usize {
        self.encrypted_protected_overhead() + plaintext_len
    }

    pub fn encrypted_protected_overhead(&self) -> usize {
        // See https://www.rfc-editor.org/rfc/rfc9580.html#name-version-1-symmetrically-enc

        // One "block size" of random
        self.block_size() +
                // 2 bytes "quick check"
                2 +
                // MDC (1 byte tag + 1 byte digest size + SHA1 digest)
                22
    }

    pub fn stream_encryptor<R, I>(
        self,
        rng: R,
        key: &[u8],
        plaintext: I,
    ) -> Result<StreamEncryptor<I>>
    where
        R: Rng + CryptoRng,
        I: std::io::Read,
    {
        StreamEncryptor::new(rng, self, key, plaintext)
    }

    /// Protected decryption stream
    pub fn stream_decryptor_protected<R>(
        self,
        key: &[u8],
        ciphertext: R,
    ) -> Result<StreamDecryptor<R>>
    where
        R: std::io::BufRead,
    {
        StreamDecryptor::new(self, true, key, ciphertext)
    }

    /// Unprotected decryption stream
    pub fn stream_decryptor_unprotected<R>(
        self,
        key: &[u8],
        ciphertext: R,
    ) -> Result<StreamDecryptor<R>>
    where
        R: std::io::BufRead,
    {
        StreamDecryptor::new(self, false, key, ciphertext)
    }

    /// Encrypt the data using CFB mode, without padding. Overwrites the input.
    ///
    /// OpenPGP CFB mode uses an initialization vector (IV) of all zeros, and
    /// prefixes the plaintext with BS+2 octets of random data, such that
    /// octets BS+1 and BS+2 match octets BS-1 and BS. It does a CFB
    /// resynchronization after encrypting those BS+2 octets.
    pub fn encrypt_with_iv(self, key: &[u8], iv_vec: &[u8], ciphertext: &mut [u8]) -> Result<()> {
        let bs = self.block_size();

        let (prefix, data) = ciphertext.split_at_mut(bs + 2);

        {
            match self {
                SymmetricKeyAlgorithm::Plaintext => {
                    bail!("'Plaintext' is not a legal cipher for encrypted data")
                }
                SymmetricKeyAlgorithm::IDEA => {
                    encrypt::<Idea>(key, iv_vec, prefix, data)?;
                }
                SymmetricKeyAlgorithm::TripleDES => {
                    encrypt::<TdesEde3>(key, iv_vec, prefix, data)?;
                }
                SymmetricKeyAlgorithm::CAST5 => {
                    encrypt::<Cast5>(key, iv_vec, prefix, data)?;
                }
                SymmetricKeyAlgorithm::Blowfish => {
                    encrypt::<Blowfish>(key, iv_vec, prefix, data)?;
                }
                SymmetricKeyAlgorithm::AES128 => {
                    encrypt::<Aes128>(key, iv_vec, prefix, data)?;
                }
                SymmetricKeyAlgorithm::AES192 => {
                    encrypt::<Aes192>(key, iv_vec, prefix, data)?;
                }
                SymmetricKeyAlgorithm::AES256 => encrypt::<Aes256>(key, iv_vec, prefix, data)?,
                SymmetricKeyAlgorithm::Twofish => {
                    encrypt::<Twofish>(key, iv_vec, prefix, data)?;
                }
                SymmetricKeyAlgorithm::Camellia128 => {
                    encrypt::<Camellia128>(key, iv_vec, prefix, data)?;
                }
                SymmetricKeyAlgorithm::Camellia192 => {
                    encrypt::<Camellia192>(key, iv_vec, prefix, data)?;
                }
                SymmetricKeyAlgorithm::Camellia256 => {
                    encrypt::<Camellia256>(key, iv_vec, prefix, data)?;
                }
                SymmetricKeyAlgorithm::Private10 | SymmetricKeyAlgorithm::Other(_) => {
                    bail!("SymmetricKeyAlgorithm {} is unsupported", u8::from(self))
                }
            }
        }

        Ok(())
    }

    /// Uses legacy resycing
    pub fn encrypt_with_iv_resync(
        self,
        key: &[u8],
        iv_vec: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<()> {
        let bs = self.block_size();

        let (prefix, data) = ciphertext.split_at_mut(bs + 2);

        {
            match self {
                SymmetricKeyAlgorithm::Plaintext => {
                    bail!("'Plaintext' is not a legal cipher for encrypted data")
                }
                SymmetricKeyAlgorithm::IDEA => {
                    encrypt_resync::<Idea>(key, iv_vec, prefix, data)?;
                }
                SymmetricKeyAlgorithm::TripleDES => {
                    encrypt_resync::<TdesEde3>(key, iv_vec, prefix, data)?;
                }
                SymmetricKeyAlgorithm::CAST5 => {
                    encrypt_resync::<Cast5>(key, iv_vec, prefix, data)?;
                }
                SymmetricKeyAlgorithm::Blowfish => {
                    encrypt_resync::<Blowfish>(key, iv_vec, prefix, data)?;
                }
                SymmetricKeyAlgorithm::AES128 => {
                    encrypt_resync::<Aes128>(key, iv_vec, prefix, data)?;
                }
                SymmetricKeyAlgorithm::AES192 => {
                    encrypt_resync::<Aes192>(key, iv_vec, prefix, data)?;
                }
                SymmetricKeyAlgorithm::AES256 => {
                    encrypt_resync::<Aes256>(key, iv_vec, prefix, data)?
                }
                SymmetricKeyAlgorithm::Twofish => {
                    encrypt_resync::<Twofish>(key, iv_vec, prefix, data)?;
                }
                SymmetricKeyAlgorithm::Camellia128 => {
                    encrypt_resync::<Camellia128>(key, iv_vec, prefix, data)?;
                }
                SymmetricKeyAlgorithm::Camellia192 => {
                    encrypt_resync::<Camellia192>(key, iv_vec, prefix, data)?;
                }
                SymmetricKeyAlgorithm::Camellia256 => {
                    encrypt_resync::<Camellia256>(key, iv_vec, prefix, data)?;
                }
                SymmetricKeyAlgorithm::Private10 | SymmetricKeyAlgorithm::Other(_) => {
                    bail!("SymmetricKeyAlgorithm {} is unsupported", u8::from(self))
                }
            }
        }

        Ok(())
    }

    /// Encrypt the data using CFB mode, without padding. Overwrites the input.
    pub fn encrypt_with_iv_regular(
        self,
        key: &[u8],
        iv_vec: &[u8],
        plaintext: &mut [u8],
    ) -> Result<()> {
        match self {
            SymmetricKeyAlgorithm::Plaintext => {
                bail!("'Plaintext' is not a legal cipher for encrypted data")
            }
            SymmetricKeyAlgorithm::IDEA => {
                Encryptor::<Idea>::new_from_slices(key, iv_vec)?.encrypt(plaintext);
            }
            SymmetricKeyAlgorithm::TripleDES => {
                Encryptor::<TdesEde3>::new_from_slices(key, iv_vec)?.encrypt(plaintext);
            }
            SymmetricKeyAlgorithm::CAST5 => {
                Encryptor::<Cast5>::new_from_slices(key, iv_vec)?.encrypt(plaintext);
            }
            SymmetricKeyAlgorithm::Blowfish => {
                Encryptor::<Blowfish>::new_from_slices(key, iv_vec)?.encrypt(plaintext);
            }
            SymmetricKeyAlgorithm::AES128 => {
                Encryptor::<Aes128>::new_from_slices(key, iv_vec)?.encrypt(plaintext);
            }
            SymmetricKeyAlgorithm::AES192 => {
                Encryptor::<Aes192>::new_from_slices(key, iv_vec)?.encrypt(plaintext);
            }
            SymmetricKeyAlgorithm::AES256 => {
                Encryptor::<Aes256>::new_from_slices(key, iv_vec)?.encrypt(plaintext);
            }
            SymmetricKeyAlgorithm::Twofish => {
                Encryptor::<Twofish>::new_from_slices(key, iv_vec)?.encrypt(plaintext);
            }
            SymmetricKeyAlgorithm::Camellia128 => {
                Encryptor::<Camellia128>::new_from_slices(key, iv_vec)?.encrypt(plaintext);
            }
            SymmetricKeyAlgorithm::Camellia192 => {
                Encryptor::<Camellia192>::new_from_slices(key, iv_vec)?.encrypt(plaintext);
            }
            SymmetricKeyAlgorithm::Camellia256 => {
                Encryptor::<Camellia256>::new_from_slices(key, iv_vec)?.encrypt(plaintext);
            }
            SymmetricKeyAlgorithm::Private10 | SymmetricKeyAlgorithm::Other(_) => {
                unimplemented_err!("SymmetricKeyAlgorithm {} is unsupported", u8::from(self))
            }
        }
        Ok(())
    }

    /// Generate a new session key.
    pub fn new_session_key<R: Rng + CryptoRng>(self, mut rng: R) -> RawSessionKey {
        let mut session_key = Zeroizing::new(vec![0u8; self.key_size()]);
        rng.fill_bytes(&mut session_key);
        session_key.into()
    }
}

#[cfg(test)]
mod tests {
    use std::{io::Read, time::Instant};

    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    use super::*;

    #[ignore]
    #[test]
    fn bench_aes_256_protected() {
        const SIZE: usize = 1024 * 1024 * 64;
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let mut data = vec![0u8; SIZE];
        rng.fill_bytes(&mut data);

        let mut key = vec![0u8; SymmetricKeyAlgorithm::AES256.key_size()];
        rng.fill_bytes(&mut key);

        let now = Instant::now();
        let mut encryptor = SymmetricKeyAlgorithm::AES256
            .stream_encryptor(&mut rng, &key, &data[..])
            .unwrap();

        let mut output = Vec::with_capacity(SIZE);
        encryptor.read_to_end(&mut output).unwrap();

        let elapsed = now.elapsed();
        let elapsed_milli = elapsed.as_millis();
        let mb_per_s = ((SIZE as f64) / 1000f64 / 1000f64 / elapsed_milli as f64) * 1000f64;
        println!("Encryption: {elapsed_milli} ms, MByte/s: {mb_per_s:.2?}");

        let now = Instant::now();

        let mut decryptor = SymmetricKeyAlgorithm::AES256
            .stream_decryptor_protected(&key, &output[..])
            .unwrap();
        let mut res = Vec::with_capacity(SIZE);
        decryptor.read_to_end(&mut res).unwrap();
        let elapsed = now.elapsed();

        assert_eq!(res, data);

        let elapsed_milli = elapsed.as_millis();
        let mb_per_s = (SIZE as f64 / 1000f64 / 1000f64 / elapsed_milli as f64) * 1000f64;
        println!("Decryption: {elapsed_milli} ms, MByte/s: {mb_per_s:.2?}");
    }

    #[ignore]
    #[test]
    fn bench_aes_256_unprotected() {
        const SIZE: usize = 1024 * 1024 * 256;
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let mut data = vec![0u8; SIZE];
        rng.fill_bytes(&mut data);

        let mut key = vec![0u8; SymmetricKeyAlgorithm::AES256.key_size()];
        rng.fill_bytes(&mut key);

        let now = Instant::now();
        let output = SymmetricKeyAlgorithm::AES256
            .encrypt(&mut rng, &key, &data[..])
            .unwrap();

        let elapsed = now.elapsed();
        let elapsed_milli = elapsed.as_millis();
        let mb_per_s = ((SIZE as f64) / 1000f64 / 1000f64 / elapsed_milli as f64) * 1000f64;
        println!("Encryption: {elapsed_milli} ms, MByte/s: {mb_per_s:.2?}");

        let now = Instant::now();

        let mut decryptor = SymmetricKeyAlgorithm::AES256
            .stream_decryptor_unprotected(&key, &output[..])
            .unwrap();
        let mut res = Vec::with_capacity(SIZE);
        decryptor.read_to_end(&mut res).unwrap();
        let elapsed = now.elapsed();

        assert_eq!(res, data);

        let elapsed_milli = elapsed.as_millis();
        let mb_per_s = (SIZE as f64 / 1000f64 / 1000f64 / elapsed_milli as f64) * 1000f64;
        println!("Decryption: {elapsed_milli} ms, MByte/s: {mb_per_s:.2?}");
    }
}

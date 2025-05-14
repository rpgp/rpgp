use aes::{Aes128, Aes192, Aes256};
use blowfish::Blowfish;
use camellia::{Camellia128, Camellia192, Camellia256};
use cast5::Cast5;
use cfb_mode::{
    cipher::{AsyncStreamCipher, KeyIvInit},
    BufDecryptor, BufEncryptor, Decryptor, Encryptor,
};
use cipher::BlockCipherEncrypt;
use des::TdesEde3;
use idea::Idea;
use log::debug;
use num_enum::{FromPrimitive, IntoPrimitive};
use rand::{CryptoRng, RngCore};
use twofish::Twofish;
use zeroize::Zeroizing;

use crate::errors::{bail, ensure, unimplemented_err, Error, Result};

mod decryptor;
mod encryptor;

pub use self::{decryptor::StreamDecryptor, encryptor::StreamEncryptor};

fn decrypt<MODE>(key: &[u8], iv: &[u8], prefix: &mut [u8], data: &mut [u8]) -> Result<()>
where
    MODE: BlockCipherEncrypt,
    BufDecryptor<MODE>: KeyIvInit,
{
    let mut mode = BufDecryptor::<MODE>::new_from_slices(key, iv)?;

    // We do not do use "quick check" here.
    // See the "Security Considerations" section
    // in <https://www.rfc-editor.org/rfc/rfc9580.html#name-risks-of-a-quick-check-orac>
    // and the paper <https://eprint.iacr.org/2005/033>
    // for details.

    mode.decrypt(prefix);

    mode.decrypt(data);
    Ok(())
}

/// Legacy format using custom resync
fn decrypt_resync<MODE>(key: &[u8], iv: &[u8], prefix: &mut [u8], data: &mut [u8]) -> Result<()>
where
    MODE: BlockCipherEncrypt,
    BufDecryptor<MODE>: KeyIvInit,
{
    let mut mode = BufDecryptor::<MODE>::new_from_slices(key, iv)?;

    // We do not do use "quick check" here.
    // See the "Security Considerations" section
    // in <https://www.rfc-editor.org/rfc/rfc9580.html#name-risks-of-a-quick-check-orac>
    // and the paper <https://eprint.iacr.org/2005/033>
    // for details.

    let encrypted_prefix = prefix[2..].to_vec();
    mode.decrypt(prefix);
    mode = BufDecryptor::<MODE>::new_from_slices(key, &encrypted_prefix)?;

    mode.decrypt(data);
    Ok(())
}

fn encrypt<MODE>(key: &[u8], iv: &[u8], prefix: &mut [u8], data: &mut [u8]) -> Result<()>
where
    MODE: BlockCipherEncrypt,
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
    MODE: BlockCipherEncrypt,
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

    #[cfg(test)]
    pub(crate) fn cfb_prefix_size(&self) -> usize {
        self.block_size() + 2
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
    /// Uses an IV of all zeroes, as specified in the openpgp cfb mode. Does
    /// resynchronization.
    pub fn decrypt(self, key: &[u8], prefix: &mut [u8], ciphertext: &mut [u8]) -> Result<()> {
        debug!("unprotected decrypt");
        let iv_vec = vec![0u8; self.block_size()];
        self.decrypt_with_iv_resync(key, &iv_vec, prefix, ciphertext)?;
        Ok(())
    }

    /// Decrypt the data using CFB mode, without padding. Overwrites the input.
    /// Uses an IV of all zeroes, as specified in the openpgp cfb mode.
    /// Does not do resynchronization.
    ///
    /// The result will be in `ciphertext`.
    pub fn decrypt_protected(
        self,
        key: &[u8],
        prefix: &mut [u8],
        ciphertext: &mut Vec<u8>,
    ) -> Result<()> {
        debug!("protected decrypt");

        let iv_vec = vec![0u8; self.block_size()];
        self.decrypt_with_iv(key, &iv_vec, prefix, ciphertext)?;

        // MDC is 1 byte packet tag, 1 byte length prefix and 20 bytes SHA1 hash.
        const MDC_LEN: usize = 22;
        let mdc = ciphertext.split_off(ciphertext.len() - MDC_LEN);

        // We use regular sha1 for MDC, not sha1_checked. Collisions are not currently a concern with MDC.
        let sha1 = calculate_sha1_unchecked([prefix, &ciphertext[..], &mdc[0..2]]);
        if mdc[0] != 0xD3 || // Invalid MDC tag
           mdc[1] != 0x14 || // Invalid MDC length
            mdc[2..] != sha1[..]
        {
            return Err(Error::MdcError);
        }

        Ok(())
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
    pub fn decrypt_with_iv(
        self,
        key: &[u8],
        iv_vec: &[u8],
        encrypted_prefix: &mut [u8],
        encrypted_data: &mut [u8],
    ) -> Result<()> {
        let bs = self.block_size();
        let ciphertext_len = encrypted_prefix.len() + encrypted_data.len();
        ensure!(bs + 2 < ciphertext_len, "invalid ciphertext");

        match self {
            SymmetricKeyAlgorithm::Plaintext => {
                bail!("'Plaintext' is not a legal cipher for encrypted data")
            }
            SymmetricKeyAlgorithm::IDEA => {
                decrypt::<Idea>(key, iv_vec, encrypted_prefix, encrypted_data)?;
            }
            SymmetricKeyAlgorithm::TripleDES => {
                decrypt::<TdesEde3>(key, iv_vec, encrypted_prefix, encrypted_data)?;
            }
            SymmetricKeyAlgorithm::CAST5 => {
                decrypt::<Cast5>(key, iv_vec, encrypted_prefix, encrypted_data)?;
            }
            SymmetricKeyAlgorithm::Blowfish => {
                decrypt::<Blowfish>(key, iv_vec, encrypted_prefix, encrypted_data)?;
            }
            SymmetricKeyAlgorithm::AES128 => {
                decrypt::<Aes128>(key, iv_vec, encrypted_prefix, encrypted_data)?;
            }
            SymmetricKeyAlgorithm::AES192 => {
                decrypt::<Aes192>(key, iv_vec, encrypted_prefix, encrypted_data)?;
            }
            SymmetricKeyAlgorithm::AES256 => {
                decrypt::<Aes256>(key, iv_vec, encrypted_prefix, encrypted_data)?;
            }
            SymmetricKeyAlgorithm::Twofish => {
                decrypt::<Twofish>(key, iv_vec, encrypted_prefix, encrypted_data)?;
            }
            SymmetricKeyAlgorithm::Camellia128 => {
                decrypt::<Camellia128>(key, iv_vec, encrypted_prefix, encrypted_data)?;
            }
            SymmetricKeyAlgorithm::Camellia192 => {
                decrypt::<Camellia192>(key, iv_vec, encrypted_prefix, encrypted_data)?;
            }
            SymmetricKeyAlgorithm::Camellia256 => {
                decrypt::<Camellia256>(key, iv_vec, encrypted_prefix, encrypted_data)?
            }
            SymmetricKeyAlgorithm::Private10 | SymmetricKeyAlgorithm::Other(_) => {
                unimplemented_err!("SymmetricKeyAlgorithm {} is unsupported", u8::from(self))
            }
        }

        Ok(())
    }

    /// Applies the legacy resyncing
    pub fn decrypt_with_iv_resync(
        self,
        key: &[u8],
        iv_vec: &[u8],
        encrypted_prefix: &mut [u8],
        encrypted_data: &mut [u8],
    ) -> Result<()> {
        let bs = self.block_size();
        let ciphertext_len = encrypted_prefix.len() + encrypted_data.len();
        ensure!(bs + 2 < ciphertext_len, "invalid ciphertext");

        match self {
            SymmetricKeyAlgorithm::Plaintext => {
                bail!("'Plaintext' is not a legal cipher for encrypted data")
            }
            SymmetricKeyAlgorithm::IDEA => {
                decrypt_resync::<Idea>(key, iv_vec, encrypted_prefix, encrypted_data)?;
            }
            SymmetricKeyAlgorithm::TripleDES => {
                decrypt_resync::<TdesEde3>(key, iv_vec, encrypted_prefix, encrypted_data)?;
            }
            SymmetricKeyAlgorithm::CAST5 => {
                decrypt_resync::<Cast5>(key, iv_vec, encrypted_prefix, encrypted_data)?;
            }
            SymmetricKeyAlgorithm::Blowfish => {
                decrypt_resync::<Blowfish>(key, iv_vec, encrypted_prefix, encrypted_data)?;
            }
            SymmetricKeyAlgorithm::AES128 => {
                decrypt_resync::<Aes128>(key, iv_vec, encrypted_prefix, encrypted_data)?;
            }
            SymmetricKeyAlgorithm::AES192 => {
                decrypt_resync::<Aes192>(key, iv_vec, encrypted_prefix, encrypted_data)?;
            }
            SymmetricKeyAlgorithm::AES256 => {
                decrypt_resync::<Aes256>(key, iv_vec, encrypted_prefix, encrypted_data)?;
            }
            SymmetricKeyAlgorithm::Twofish => {
                decrypt_resync::<Twofish>(key, iv_vec, encrypted_prefix, encrypted_data)?;
            }
            SymmetricKeyAlgorithm::Camellia128 => {
                decrypt_resync::<Camellia128>(key, iv_vec, encrypted_prefix, encrypted_data)?;
            }
            SymmetricKeyAlgorithm::Camellia192 => {
                decrypt_resync::<Camellia192>(key, iv_vec, encrypted_prefix, encrypted_data)?;
            }
            SymmetricKeyAlgorithm::Camellia256 => {
                decrypt_resync::<Camellia256>(key, iv_vec, encrypted_prefix, encrypted_data)?
            }
            SymmetricKeyAlgorithm::Private10 | SymmetricKeyAlgorithm::Other(_) => {
                unimplemented_err!("SymmetricKeyAlgorithm {} is unsupported", u8::from(self))
            }
        }

        Ok(())
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
    pub fn encrypt<R: CryptoRng + RngCore + ?Sized>(
        self,
        rng: &mut R,
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

    pub fn encrypt_protected<R: CryptoRng + RngCore + ?Sized>(
        self,
        rng: &mut R,
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
        rng: &mut R,
        key: &[u8],
        plaintext: I,
    ) -> Result<StreamEncryptor<I>>
    where
        R: RngCore + CryptoRng + ?Sized,
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
    pub fn new_session_key<R: RngCore + CryptoRng + ?Sized>(
        self,
        rng: &mut R,
    ) -> Zeroizing<Vec<u8>> {
        let mut session_key = Zeroizing::new(vec![0u8; self.key_size()]);
        rng.fill_bytes(&mut session_key);
        session_key
    }
}

#[inline]
fn calculate_sha1_unchecked<I, T>(data: I) -> [u8; 20]
where
    T: AsRef<[u8]>,
    I: IntoIterator<Item = T>,
{
    use sha1::{Digest, Sha1};

    let mut digest = Sha1::new();
    for chunk in data {
        digest.update(chunk.as_ref());
    }
    digest.finalize().into()
}

#[cfg(test)]
mod tests {
    use std::{io::Read, time::Instant};

    use log::info;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    use super::*;

    macro_rules! roundtrip_unprotected {
        ($name:ident, $alg:path) => {
            #[test]
            fn $name() {
                pretty_env_logger::try_init().ok();

                let mut data_rng = ChaCha8Rng::seed_from_u64(0);

                const MAX_SIZE: usize = 2048;

                // Unprotected
                for i in 1..MAX_SIZE {
                    info!("Size {}", i);
                    let mut data = vec![0u8; i];
                    data_rng.fill(&mut data[..]);
                    let mut key = vec![0u8; $alg.key_size()];
                    data_rng.fill(&mut key[..]);

                    info!("unprotected encrypt");
                    let mut rng = ChaCha8Rng::seed_from_u64(8);
                    let ciphertext = $alg.encrypt(&mut rng, &key, &data).unwrap();
                    assert_ne!(data, ciphertext);

                    {
                        info!("unprotected decrypt");
                        let mut ciphertext = ciphertext.clone();
                        let mut plaintext = ciphertext.split_off($alg.cfb_prefix_size());
                        let mut prefix = ciphertext;
                        $alg.decrypt(&key, &mut prefix, &mut plaintext).unwrap();
                        assert_eq!(
                            hex::encode(&data),
                            hex::encode(&plaintext),
                            "unprotected decrypt"
                        );
                    }

                    {
                        info!("unprotected decrypt streaming");
                        dbg!(ciphertext.len(), $alg.cfb_prefix_size());
                        let mut input = std::io::Cursor::new(&ciphertext);
                        let mut decryptor =
                            $alg.stream_decryptor_unprotected(&key, &mut input).unwrap();
                        let mut plaintext = Vec::new();
                        decryptor.read_to_end(&mut plaintext).unwrap();
                        assert_eq!(
                            hex::encode(&data),
                            hex::encode(&plaintext),
                            "stream decrypt failed"
                        );
                    }
                }
            }
        };
    }

    macro_rules! roundtrip_protected {
        ($name:ident, $alg:path) => {
            #[test]
            fn $name() {
                pretty_env_logger::try_init().ok();

                let mut data_rng = ChaCha8Rng::seed_from_u64(0);

                const MAX_SIZE: usize = 2048;

                // Protected
                for i in 1..MAX_SIZE {
                    info!("Size {}", i);
                    let mut data = vec![0u8; i];
                    data_rng.fill(&mut data[..]);
                    let mut key = vec![0u8; $alg.key_size()];
                    data_rng.fill(&mut key[..]);

                    info!("encrypt");
                    let mut rng = ChaCha8Rng::seed_from_u64(8);
                    let ciphertext = $alg.encrypt_protected(&mut rng, &key, &data).unwrap();
                    assert_ne!(data, ciphertext, "failed to encrypt");

                    {
                        info!("encrypt streaming");
                        let mut input = std::io::Cursor::new(&data);
                        let len = $alg.encrypted_protected_len(data.len());
                        assert_eq!(len, ciphertext.len(), "failed to encrypt");
                        let mut output = Vec::new();
                        let mut rng = ChaCha8Rng::seed_from_u64(8);
                        let mut encryptor =
                            $alg.stream_encryptor(&mut rng, &key, &mut input).unwrap();
                        encryptor.read_to_end(&mut output).unwrap();

                        assert_eq!(output.len(), len, "output length mismatch");
                        assert_eq!(ciphertext, output, "output mismatch");
                    }

                    {
                        info!("decrypt");
                        let mut ciphertext = ciphertext.clone();
                        let mut plaintext = ciphertext.split_off($alg.cfb_prefix_size());
                        let mut prefix = ciphertext;
                        $alg.decrypt_protected(&key, &mut prefix, &mut plaintext)
                            .unwrap();
                        assert_eq!(data, plaintext, "decrypt failed");
                    }
                    {
                        info!("decrypt streaming");
                        dbg!(ciphertext.len(), $alg.cfb_prefix_size());
                        let mut input = std::io::Cursor::new(&ciphertext);
                        let mut decryptor =
                            $alg.stream_decryptor_protected(&key, &mut input).unwrap();
                        let mut plaintext = Vec::new();
                        decryptor.read_to_end(&mut plaintext).unwrap();
                        assert_eq!(
                            hex::encode(&data),
                            hex::encode(&plaintext),
                            "stream decrypt failed"
                        );
                    }
                }
            }
        };
    }

    roundtrip_protected!(roundtrip_protected_aes128, SymmetricKeyAlgorithm::AES128);
    roundtrip_protected!(roundtrip_protected_aes192, SymmetricKeyAlgorithm::AES192);
    roundtrip_protected!(roundtrip_protected_aes256, SymmetricKeyAlgorithm::AES256);
    roundtrip_protected!(
        roundtrip_protected_tripledes,
        SymmetricKeyAlgorithm::TripleDES
    );
    roundtrip_protected!(
        roundtrip_protected_blowfish,
        SymmetricKeyAlgorithm::Blowfish
    );
    roundtrip_protected!(roundtrip_protected_twofish, SymmetricKeyAlgorithm::Twofish);
    roundtrip_protected!(roundtrip_protected_cast5, SymmetricKeyAlgorithm::CAST5);
    roundtrip_protected!(roundtrip_protected_idea, SymmetricKeyAlgorithm::IDEA);
    roundtrip_protected!(
        roundtrip_protected_camellia128,
        SymmetricKeyAlgorithm::Camellia128
    );
    roundtrip_protected!(
        roundtrip_protected_camellia192,
        SymmetricKeyAlgorithm::Camellia192
    );
    roundtrip_protected!(
        roundtrip_protected_camellia256,
        SymmetricKeyAlgorithm::Camellia256
    );

    roundtrip_unprotected!(roundtrip_unprotected_aes128, SymmetricKeyAlgorithm::AES128);
    roundtrip_unprotected!(roundtrip_unprotected_aes192, SymmetricKeyAlgorithm::AES192);
    roundtrip_unprotected!(roundtrip_unprotected_aes256, SymmetricKeyAlgorithm::AES256);
    roundtrip_unprotected!(
        roundtrip_unprotected_tripledes,
        SymmetricKeyAlgorithm::TripleDES
    );
    roundtrip_unprotected!(
        roundtrip_unprotected_blowfish,
        SymmetricKeyAlgorithm::Blowfish
    );
    roundtrip_unprotected!(
        roundtrip_unprotected_twofish,
        SymmetricKeyAlgorithm::Twofish
    );
    roundtrip_unprotected!(roundtrip_unprotected_cast5, SymmetricKeyAlgorithm::CAST5);
    roundtrip_unprotected!(roundtrip_unprotected_idea, SymmetricKeyAlgorithm::IDEA);
    roundtrip_unprotected!(
        roundtrip_unprotected_camellia128,
        SymmetricKeyAlgorithm::Camellia128
    );
    roundtrip_unprotected!(
        roundtrip_unprotected_camellia192,
        SymmetricKeyAlgorithm::Camellia192
    );
    roundtrip_unprotected!(
        roundtrip_unprotected_camellia256,
        SymmetricKeyAlgorithm::Camellia256
    );

    #[test]
    pub fn decrypt_without_enough_ciphertext() {
        let key: [u8; 0] = [];
        let mut prefix: [u8; 0] = [];
        let mut cipher_text: [u8; 0] = [];
        assert!(SymmetricKeyAlgorithm::AES128
            .decrypt(&key, &mut prefix, &mut cipher_text)
            .is_err());
    }

    use rand::RngCore;

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

use aes::{Aes128, Aes192, Aes256};
use blowfish::Blowfish;
use bytes::{Buf, Bytes, BytesMut};
use camellia::{Camellia128, Camellia192, Camellia256};
use cast5::Cast5;
use cfb_mode::cipher::{AsyncStreamCipher, KeyIvInit};
use cfb_mode::{BufDecryptor, BufEncryptor, Decryptor, Encryptor};
use cipher::{BlockCipher, BlockDecrypt, BlockEncryptMut, BlockSizeUser};
use des::TdesEde3;
use idea::Idea;
use log::debug;
use num_enum::{FromPrimitive, IntoPrimitive};
use rand::{CryptoRng, Rng};
use sha1::{Digest, Sha1};
use twofish::Twofish;
use zeroize::Zeroizing;

use crate::errors::{Error, Result};
use crate::util::fill_buffer;

fn decrypt<MODE>(
    key: &[u8],
    iv: &[u8],
    prefix: &mut [u8],
    data: &mut [u8],
    resync: bool,
) -> Result<()>
where
    MODE: BlockDecrypt + BlockEncryptMut + BlockCipher,
    BufDecryptor<MODE>: KeyIvInit,
{
    let mut mode = BufDecryptor::<MODE>::new_from_slices(key, iv)?;
    mode.decrypt(prefix);

    // We do not do use "quick check" here.
    // See the "Security Considerations" section
    // in <https://www.rfc-editor.org/rfc/rfc9580.html#name-risks-of-a-quick-check-orac>
    // and the paper <https://eprint.iacr.org/2005/033>
    // for details.

    if resync {
        unsupported_err!("CFB resync is disabled");
    }
    mode.decrypt(data);
    Ok(())
}

fn encrypt<MODE>(
    key: &[u8],
    iv: &[u8],
    prefix: &mut [u8],
    data: &mut [u8],
    resync: bool,
) -> Result<()>
where
    MODE: BlockDecrypt + BlockEncryptMut + BlockCipher,
    BufEncryptor<MODE>: KeyIvInit,
{
    let mut mode = BufEncryptor::<MODE>::new_from_slices(key, iv)?;
    mode.encrypt(prefix);

    if resync {
        unsupported_err!("CFB resync is disabled");
    } else {
        mode.encrypt(data);
    }
    Ok(())
}

/// Available symmetric key algorithms.
/// Ref: <https://www.rfc-editor.org/rfc/rfc9580.html#name-symmetric-key-algorithms>
#[derive(Debug, PartialEq, Eq, Copy, Clone, FromPrimitive, IntoPrimitive)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
#[repr(u8)]
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
        self.decrypt_with_iv(key, &iv_vec, prefix, ciphertext, true)?;
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

        debug!("protected decrypt");

        let iv_vec = vec![0u8; self.block_size()];
        self.decrypt_with_iv(key, &iv_vec, prefix, ciphertext, false)?;

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
    #[allow(clippy::complexity)]
    pub fn decrypt_with_iv<'a>(
        self,
        key: &[u8],
        iv_vec: &[u8],
        encrypted_prefix: &mut [u8],
        encrypted_data: &mut [u8],
        resync: bool,
    ) -> Result<()> {
        let bs = self.block_size();
        let ciphertext_len = encrypted_prefix.len() + encrypted_data.len();
        ensure!(bs + 2 < ciphertext_len, "invalid ciphertext");

        match self {
            SymmetricKeyAlgorithm::Plaintext => {
                bail!("'Plaintext' is not a legal cipher for encrypted data")
            }
            SymmetricKeyAlgorithm::IDEA => {
                decrypt::<Idea>(key, iv_vec, encrypted_prefix, encrypted_data, resync)?;
            }
            SymmetricKeyAlgorithm::TripleDES => {
                decrypt::<TdesEde3>(key, iv_vec, encrypted_prefix, encrypted_data, resync)?;
            }
            SymmetricKeyAlgorithm::CAST5 => {
                decrypt::<Cast5>(key, iv_vec, encrypted_prefix, encrypted_data, resync)?;
            }
            SymmetricKeyAlgorithm::Blowfish => {
                decrypt::<Blowfish>(key, iv_vec, encrypted_prefix, encrypted_data, resync)?;
            }
            SymmetricKeyAlgorithm::AES128 => {
                decrypt::<Aes128>(key, iv_vec, encrypted_prefix, encrypted_data, resync)?;
            }
            SymmetricKeyAlgorithm::AES192 => {
                decrypt::<Aes192>(key, iv_vec, encrypted_prefix, encrypted_data, resync)?;
            }
            SymmetricKeyAlgorithm::AES256 => {
                decrypt::<Aes256>(key, iv_vec, encrypted_prefix, encrypted_data, resync)?;
            }
            SymmetricKeyAlgorithm::Twofish => {
                decrypt::<Twofish>(key, iv_vec, encrypted_prefix, encrypted_data, resync)?;
            }
            SymmetricKeyAlgorithm::Camellia128 => {
                decrypt::<Camellia128>(key, iv_vec, encrypted_prefix, encrypted_data, resync)?;
            }
            SymmetricKeyAlgorithm::Camellia192 => {
                decrypt::<Camellia192>(key, iv_vec, encrypted_prefix, encrypted_data, resync)?;
            }
            SymmetricKeyAlgorithm::Camellia256 => {
                decrypt::<Camellia256>(key, iv_vec, encrypted_prefix, encrypted_data, resync)?
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

        self.encrypt_with_iv(key, &iv_vec, &mut ciphertext, true)?;

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

        self.encrypt_with_iv(key, &iv_vec, &mut ciphertext, false)?;

        Ok(ciphertext)
    }

    pub fn encrypted_protected_len(&self, plaintext_len: usize) -> usize {
        self.encrypted_protected_overhead() + plaintext_len
    }

    pub fn encrypted_protected_overhead(&self) -> usize {
        // MDC is 1 byte packet tag, 1 byte length prefix and 20 bytes SHA1 hash.
        let mdc_len = 22;
        self.block_size() + 2 + mdc_len
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
        match self {
            SymmetricKeyAlgorithm::Plaintext => {
                bail!("'Plaintext' is not a legal cipher for encrypted data")
            }
            SymmetricKeyAlgorithm::IDEA => Ok(StreamEncryptor::Idea(StreamEncryptorInner::new(
                rng, plaintext, self, key,
            )?)),
            SymmetricKeyAlgorithm::TripleDES => Ok(StreamEncryptor::TripleDes(
                StreamEncryptorInner::new(rng, plaintext, self, key)?,
            )),
            SymmetricKeyAlgorithm::CAST5 => Ok(StreamEncryptor::Cast5(StreamEncryptorInner::new(
                rng, plaintext, self, key,
            )?)),
            SymmetricKeyAlgorithm::Blowfish => Ok(StreamEncryptor::Blowfish(
                StreamEncryptorInner::new(rng, plaintext, self, key)?,
            )),
            SymmetricKeyAlgorithm::AES128 => Ok(StreamEncryptor::Aes128(
                StreamEncryptorInner::new(rng, plaintext, self, key)?,
            )),
            SymmetricKeyAlgorithm::AES192 => Ok(StreamEncryptor::Aes192(
                StreamEncryptorInner::new(rng, plaintext, self, key)?,
            )),
            SymmetricKeyAlgorithm::AES256 => Ok(StreamEncryptor::Aes256(
                StreamEncryptorInner::new(rng, plaintext, self, key)?,
            )),
            SymmetricKeyAlgorithm::Twofish => Ok(StreamEncryptor::Twofish(
                StreamEncryptorInner::new(rng, plaintext, self, key)?,
            )),
            SymmetricKeyAlgorithm::Camellia128 => Ok(StreamEncryptor::Camellia128(
                StreamEncryptorInner::new(rng, plaintext, self, key)?,
            )),
            SymmetricKeyAlgorithm::Camellia192 => Ok(StreamEncryptor::Camellia192(
                StreamEncryptorInner::new(rng, plaintext, self, key)?,
            )),
            SymmetricKeyAlgorithm::Camellia256 => Ok(StreamEncryptor::Camellia256(
                StreamEncryptorInner::new(rng, plaintext, self, key)?,
            )),
            SymmetricKeyAlgorithm::Private10 | SymmetricKeyAlgorithm::Other(_) => {
                bail!("SymmetricKeyAlgorithm {} is unsupported", u8::from(self))
            }
        }
    }

    pub fn encrypt_protected_stream<R, I, O>(
        self,
        rng: R,
        key: &[u8],
        plaintext: I,
        mut ciphertext: O,
    ) -> Result<()>
    where
        R: Rng + CryptoRng,
        I: std::io::Read,
        O: std::io::Write,
    {
        let mut encryptor = self.stream_encryptor(rng, key, plaintext)?;
        std::io::copy(&mut encryptor, &mut ciphertext)?;
        Ok(())
    }

    /// Encrypt the data using CFB mode, without padding. Overwrites the input.
    ///
    /// OpenPGP CFB mode uses an initialization vector (IV) of all zeros, and
    /// prefixes the plaintext with BS+2 octets of random data, such that
    /// octets BS+1 and BS+2 match octets BS-1 and BS. It does a CFB
    /// resynchronization after encrypting those BS+2 octets.
    #[allow(clippy::cognitive_complexity)] // FIXME
    pub fn encrypt_with_iv(
        self,
        key: &[u8],
        iv_vec: &[u8],
        ciphertext: &mut [u8],
        resync: bool,
    ) -> Result<()> {
        let bs = self.block_size();

        let (prefix, data) = ciphertext.split_at_mut(bs + 2);

        {
            match self {
                SymmetricKeyAlgorithm::Plaintext => {
                    bail!("'Plaintext' is not a legal cipher for encrypted data")
                }
                SymmetricKeyAlgorithm::IDEA => {
                    encrypt::<Idea>(key, iv_vec, prefix, data, resync)?;
                }
                SymmetricKeyAlgorithm::TripleDES => {
                    encrypt::<TdesEde3>(key, iv_vec, prefix, data, resync)?;
                }
                SymmetricKeyAlgorithm::CAST5 => {
                    encrypt::<Cast5>(key, iv_vec, prefix, data, resync)?;
                }
                SymmetricKeyAlgorithm::Blowfish => {
                    encrypt::<Blowfish>(key, iv_vec, prefix, data, resync)?;
                }
                SymmetricKeyAlgorithm::AES128 => {
                    encrypt::<Aes128>(key, iv_vec, prefix, data, resync)?;
                }
                SymmetricKeyAlgorithm::AES192 => {
                    encrypt::<Aes192>(key, iv_vec, prefix, data, resync)?;
                }
                SymmetricKeyAlgorithm::AES256 => {
                    encrypt::<Aes256>(key, iv_vec, prefix, data, resync)?
                }
                SymmetricKeyAlgorithm::Twofish => {
                    encrypt::<Twofish>(key, iv_vec, prefix, data, resync)?;
                }
                SymmetricKeyAlgorithm::Camellia128 => {
                    encrypt::<Camellia128>(key, iv_vec, prefix, data, resync)?;
                }
                SymmetricKeyAlgorithm::Camellia192 => {
                    encrypt::<Camellia192>(key, iv_vec, prefix, data, resync)?;
                }
                SymmetricKeyAlgorithm::Camellia256 => {
                    encrypt::<Camellia256>(key, iv_vec, prefix, data, resync)?;
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
    pub fn new_session_key<R: Rng + CryptoRng>(self, mut rng: R) -> Zeroizing<Vec<u8>> {
        let mut session_key = Zeroizing::new(vec![0u8; self.key_size()]);
        rng.fill_bytes(&mut session_key);
        session_key
    }
}

pub enum StreamEncryptor<R>
where
    R: std::io::Read,
{
    Idea(StreamEncryptorInner<Idea, R>),
    TripleDes(StreamEncryptorInner<TdesEde3, R>),
    Cast5(StreamEncryptorInner<Cast5, R>),
    Blowfish(StreamEncryptorInner<Blowfish, R>),
    Aes128(StreamEncryptorInner<Aes128, R>),
    Aes192(StreamEncryptorInner<Aes192, R>),
    Aes256(StreamEncryptorInner<Aes256, R>),
    Twofish(StreamEncryptorInner<Twofish, R>),
    Camellia128(StreamEncryptorInner<Camellia128, R>),
    Camellia192(StreamEncryptorInner<Camellia192, R>),
    Camellia256(StreamEncryptorInner<Camellia256, R>),
}

impl<R> std::io::Read for StreamEncryptor<R>
where
    R: std::io::Read,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Idea(ref mut i) => i.read(buf),
            Self::TripleDes(ref mut i) => i.read(buf),
            Self::Cast5(ref mut i) => i.read(buf),
            Self::Blowfish(ref mut i) => i.read(buf),
            Self::Aes128(ref mut i) => i.read(buf),
            Self::Aes192(ref mut i) => i.read(buf),
            Self::Aes256(ref mut i) => i.read(buf),
            Self::Twofish(ref mut i) => i.read(buf),
            Self::Camellia128(ref mut i) => i.read(buf),
            Self::Camellia192(ref mut i) => i.read(buf),
            Self::Camellia256(ref mut i) => i.read(buf),
        }
    }
}

#[derive(derive_more::Debug)]
pub enum StreamEncryptorInner<M, R>
where
    M: BlockDecrypt + BlockEncryptMut + BlockCipher,
    BufEncryptor<M>: KeyIvInit,
    R: std::io::Read,
{
    Prefix {
        // We use regular sha1 for MDC, not sha1_checked. Collisions are not currently a concern with MDC.
        hasher: Sha1,
        #[debug("BufEncryptor")]
        encryptor: BufEncryptor<M>,
        prefix: Bytes,
        #[debug("source")]
        source: R,
    },
    Data {
        hasher: Sha1,
        #[debug("BufEncryptor")]
        encryptor: BufEncryptor<M>,
        buffer: BytesMut,
        /// set to `None` once the source is fully read
        #[debug("source: remaining? {}", source.is_some())]
        source: Option<R>,
    },
    Mdc {
        mdc: Bytes,
    },
    Done,
    Unknown,
}

impl<M, R> StreamEncryptorInner<M, R>
where
    M: BlockDecrypt + BlockEncryptMut + BlockCipher,
    BufEncryptor<M>: KeyIvInit,
    R: std::io::Read,
{
    fn new<RAND>(mut rng: RAND, source: R, alg: SymmetricKeyAlgorithm, key: &[u8]) -> Result<Self>
    where
        RAND: Rng + CryptoRng,
    {
        debug!("protected encrypt stream");

        let bs = alg.block_size();
        let mut prefix = vec![0u8; bs + 2];

        // prefix
        rng.fill_bytes(&mut prefix[..bs]);

        // add quick check
        prefix[bs] = prefix[bs - 2];
        prefix[bs + 1] = prefix[bs - 1];

        // checksum over unencrypted data
        let mut hasher = Sha1::default();

        // IV is all zeroes
        let iv_vec = vec![0u8; bs];

        let mut encryptor = BufEncryptor::<M>::new_from_slices(key, &iv_vec)?;

        // pre ingest prefix and encrypt it
        hasher.update(&prefix);
        encryptor.encrypt(&mut prefix);

        Ok(Self::Prefix {
            hasher,
            encryptor,
            prefix: prefix.into(),
            source,
        })
    }

    fn buffer_size() -> usize {
        let block_size = <M as BlockSizeUser>::block_size();
        block_size * 2
    }
}

impl<M, R> std::io::Read for StreamEncryptorInner<M, R>
where
    M: BlockDecrypt + BlockEncryptMut + BlockCipher,
    BufEncryptor<M>: KeyIvInit,
    R: std::io::Read,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match std::mem::replace(self, Self::Unknown) {
            Self::Prefix {
                mut hasher,
                mut encryptor,
                mut prefix,
                mut source,
            } => {
                // Prefix
                let to_write = buf.len().min(prefix.remaining());
                prefix.copy_to_slice(&mut buf[..to_write]);

                if prefix.has_remaining() {
                    *self = Self::Prefix {
                        hasher,
                        encryptor,
                        prefix,
                        source,
                    };
                } else {
                    // prefix written, transition to data
                    let mut buffer = BytesMut::zeroed(Self::buffer_size());

                    // fill buffer
                    let read = fill_buffer(&mut source, &mut buffer, None)?;
                    let source = if read < buffer.len() {
                        // done reading
                        // shorten buffer accordingly
                        buffer.truncate(read);
                        None
                    } else {
                        Some(source)
                    };

                    // encrypt it
                    hasher.update(&buffer);
                    encryptor.encrypt(&mut buffer);

                    *self = Self::Data {
                        hasher,
                        encryptor,
                        buffer,
                        source,
                    };
                }

                Ok(to_write)
            }
            Self::Data {
                mut hasher,
                mut encryptor,
                mut buffer,
                source,
            } => {
                let to_write = buf.len().min(buffer.remaining());
                buffer.copy_to_slice(&mut buf[..to_write]);

                if buffer.has_remaining() {
                    *self = Self::Data {
                        hasher,
                        encryptor,
                        buffer,
                        source,
                    };
                } else {
                    // needs filling
                    let (mdc, source) = if let Some(mut source) = source {
                        // fill buffer
                        buffer.resize(Self::buffer_size(), 0);
                        let read = fill_buffer(&mut source, &mut buffer, None)?;
                        let source = if read < buffer.len() {
                            // done reading
                            // shorten buffer accordingly
                            buffer.truncate(read);
                            None
                        } else {
                            Some(source)
                        };
                        if buffer.is_empty() {
                            // nothing left
                            (true, source)
                        } else {
                            // encrypt it
                            hasher.update(&buffer);
                            encryptor.encrypt(&mut buffer);
                            (false, source)
                        }
                    } else {
                        (true, source)
                    };

                    if mdc {
                        // source is fully read, move on to Mdc
                        // mdc header
                        let mdc_header = [0xD3, 0x14];
                        hasher.update(mdc_header);

                        let mut mdc = BytesMut::zeroed(22);
                        mdc[..2].copy_from_slice(&mdc_header);

                        // mdc body
                        let checksum = &hasher.finalize()[..20];
                        mdc[2..22].copy_from_slice(checksum);

                        encryptor.encrypt(&mut mdc[..]);
                        *self = Self::Mdc { mdc: mdc.freeze() };
                    } else {
                        *self = Self::Data {
                            hasher,
                            encryptor,
                            buffer,
                            source,
                        };
                    };
                }
                Ok(to_write)
            }
            Self::Mdc { mut mdc } => {
                let to_write = buf.len().min(mdc.remaining());
                mdc.copy_to_slice(&mut buf[..to_write]);

                if mdc.has_remaining() {
                    *self = Self::Mdc { mdc };
                } else {
                    *self = Self::Done;
                }

                Ok(to_write)
            }
            Self::Done => Ok(0),
            Self::Unknown => {
                panic!("encryption panicked");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use log::info;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    use super::*;

    macro_rules! roundtrip {
        ($name:ident, $alg:path) => {
            #[test]
            fn $name() {
                pretty_env_logger::try_init().ok();

                let mut rng = ChaCha8Rng::seed_from_u64(0);

                // Protected
                for i in 1..1024 {
                    info!("Size {}", i);
                    let data = (0..i).map(|_| rng.gen()).collect::<Vec<_>>();
                    let key = (0..$alg.key_size()).map(|_| rng.gen()).collect::<Vec<_>>();

                    info!("encrypt");
                    let mut rng = ChaCha8Rng::seed_from_u64(8);
                    let mut ciphertext = $alg.encrypt_protected(&mut rng, &key, &data).unwrap();
                    assert_ne!(data, ciphertext, "failed to encrypt");

                    {
                        info!("encrypt streaming");
                        let mut input = std::io::Cursor::new(&data);
                        let len = $alg.encrypted_protected_len(data.len());
                        assert_eq!(len, ciphertext.len(), "failed to encrypt");
                        let mut output = Vec::new();
                        let mut rng = ChaCha8Rng::seed_from_u64(8);
                        $alg.encrypt_protected_stream(&mut rng, &key, &mut input, &mut output)
                            .unwrap();
                        assert_eq!(output.len(), len, "output length mismatch");
                        assert_eq!(ciphertext, output, "output mismatch");
                    }

                    info!("decrypt");
                    let mut plaintext = ciphertext.split_off($alg.cfb_prefix_size());
                    let mut prefix = ciphertext;
                    $alg.decrypt_protected(&key, &mut prefix, &mut plaintext)
                        .unwrap();
                    assert_eq!(data, plaintext, "decrypt failed");
                }

                // Unprotected
                // resync is not implemented yet
                // {
                //     let data = vec![2u8; 256];
                //     let key = vec![1u8; $alg.key_size()];

                //     let mut ciphertext = $alg.encrypt(&key, &data).unwrap();
                //     assert_ne!(data, ciphertext);

                //     let plaintext = $alg.decrypt(&key, &mut ciphertext).unwrap();
                //     assert_eq!(data, plaintext);
                // }
            }
        };
    }

    roundtrip!(roundtrip_aes128, SymmetricKeyAlgorithm::AES128);
    roundtrip!(roundtrip_aes192, SymmetricKeyAlgorithm::AES192);
    roundtrip!(roundtrip_aes256, SymmetricKeyAlgorithm::AES256);
    roundtrip!(roundtrip_tripledes, SymmetricKeyAlgorithm::TripleDES);
    roundtrip!(roundtrip_blowfish, SymmetricKeyAlgorithm::Blowfish);
    roundtrip!(roundtrip_twofish, SymmetricKeyAlgorithm::Twofish);
    roundtrip!(roundtrip_cast5, SymmetricKeyAlgorithm::CAST5);
    roundtrip!(roundtrip_idea, SymmetricKeyAlgorithm::IDEA);
    roundtrip!(roundtrip_camellia128, SymmetricKeyAlgorithm::Camellia128);
    roundtrip!(roundtrip_camellia192, SymmetricKeyAlgorithm::Camellia192);
    roundtrip!(roundtrip_camellia256, SymmetricKeyAlgorithm::Camellia256);

    #[test]
    pub fn decrypt_without_enough_ciphertext() {
        let key: [u8; 0] = [];
        let mut prefix: [u8; 0] = [];
        let mut cipher_text: [u8; 0] = [];
        assert!(SymmetricKeyAlgorithm::AES128
            .decrypt(&key, &mut prefix, &mut cipher_text)
            .is_err());
    }
}

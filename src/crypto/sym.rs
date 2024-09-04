use aes::{Aes128, Aes192, Aes256};
use blowfish::Blowfish;
use camellia::{Camellia128, Camellia192, Camellia256};
use cast5::Cast5;
use cfb_mode::cipher::{AsyncStreamCipher, KeyIvInit};
use cfb_mode::{BufDecryptor, BufEncryptor, Decryptor, Encryptor};
use des::TdesEde3;
use idea::Idea;
use log::debug;
use num_enum::{FromPrimitive, IntoPrimitive};
use rand::{CryptoRng, Rng};
use twofish::Twofish;

use crate::errors::{Error, Result};

macro_rules! decrypt {
    ($mode:ident, $key:expr, $iv:expr, $prefix:expr, $data:expr, $bs:expr, $resync:expr) => {{
        let mut mode = BufDecryptor::<$mode>::new_from_slices($key, $iv)?;
        mode.decrypt($prefix);

        // We do not do "quick check" here.
        // See "Security Considerations" section
        // in <https://tools.ietf.org/html/rfc4880#page-84>
        // and paper <https://eprint.iacr.org/2005/033>
        // for details.

        if $resync {
            unimplemented!("CFB resync is not here");
        // debug!("resync {}", hex::encode(&$prefix[2..$bs + 2]));
        // let mut mode = Cfb::<$mode>::new_from_slices($key, &$prefix[2..$bs + 2])?;
        // mode.decrypt($data);
        } else {
            mode.decrypt($data);
        }
    }};
}

macro_rules! encrypt {
    ($mode:ident, $key:expr, $iv:expr, $prefix:expr, $data:expr, $bs:expr, $resync:expr) => {{
        let mut mode = BufEncryptor::<$mode>::new_from_slices($key, $iv)?;
        mode.encrypt($prefix);

        if $resync {
            unimplemented!("CFB resync is not here");
        // debug!("resync {}", hex::encode(&$prefix[2..$bs + 2]));
        // let mut mode = Cfb::<$mode>::new_var($key, &$prefix[2..$bs + 2])?;
        // mode.encrypt($data);
        } else {
            mode.encrypt($data);
        }
    }};
}

macro_rules! decrypt_regular {
    ($mode:ident, $key:expr, $iv:expr, $ciphertext:expr) => {{
        let mode = Decryptor::<$mode>::new_from_slices($key, $iv)?;
        mode.decrypt($ciphertext);
    }};
}
macro_rules! encrypt_regular {
    ($mode:ident, $key:expr, $iv:expr, $plaintext:expr) => {{
        let mode = Encryptor::<$mode>::new_from_slices($key, $iv)?;
        mode.encrypt($plaintext);
    }};
}

/// Available [symmetric key algorithms](https://tools.ietf.org/html/rfc4880#section-9.2).
#[derive(Debug, PartialEq, Eq, Copy, Clone, FromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum SymmetricKeyAlgorithm {
    /// Plaintext or unencrypted data
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
    Other(u8),
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

    /// The size of a single block in bytes.
    /// Based on <https://github.com/gpg/libgcrypt/blob/master/cipher>
    pub fn key_size(self) -> usize {
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
    pub fn decrypt<'a>(self, key: &[u8], ciphertext: &'a mut [u8]) -> Result<&'a [u8]> {
        debug!("unprotected decrypt");
        let iv_vec = vec![0u8; self.block_size()];
        Ok(self.decrypt_with_iv(key, &iv_vec, ciphertext, true)?.1)
    }

    /// Decrypt the data using CFB mode, without padding. Overwrites the input.
    /// Uses an IV of all zeroes, as specified in the openpgp cfb mode.
    /// Does not do resynchronization.
    pub fn decrypt_protected<'a>(self, key: &[u8], ciphertext: &'a mut [u8]) -> Result<&'a [u8]> {
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
        let (prefix, res) = self.decrypt_with_iv(key, &iv_vec, ciphertext, false)?;

        // MDC is 1 byte packet tag, 1 byte length prefix and 20 bytes SHA1 hash.
        const MDC_LEN: usize = 22;
        let (data, mdc) = res.split_at(res.len() - MDC_LEN);

        // We use regular sha1 for MDC, not sha1_checked. Collisions are not currently a concern with MDC.
        let sha1 = calculate_sha1_unchecked([prefix, data, &mdc[0..2]]);
        if mdc[0] != 0xD3 || // Invalid MDC tag
           mdc[1] != 0x14 || // Invalid MDC length
           mdc[2..] != sha1[..]
        {
            Err(Error::MdcError)
        } else {
            Ok(data)
        }
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
        ciphertext: &'a mut [u8],
        resync: bool,
    ) -> Result<(&'a [u8], &'a [u8])> {
        let bs = self.block_size();

        ensure!(bs + 2 < ciphertext.len(), "invalid ciphertext");
        let (encrypted_prefix, encrypted_data) = ciphertext.split_at_mut(bs + 2);

        {
            match self {
                SymmetricKeyAlgorithm::Plaintext => {}
                SymmetricKeyAlgorithm::IDEA => decrypt!(
                    Idea,
                    key,
                    iv_vec,
                    encrypted_prefix,
                    encrypted_data,
                    bs,
                    resync
                ),

                SymmetricKeyAlgorithm::TripleDES => {
                    decrypt!(
                        TdesEde3,
                        key,
                        iv_vec,
                        encrypted_prefix,
                        encrypted_data,
                        bs,
                        resync
                    );
                }
                SymmetricKeyAlgorithm::CAST5 => decrypt!(
                    Cast5,
                    key,
                    iv_vec,
                    encrypted_prefix,
                    encrypted_data,
                    bs,
                    resync
                ),
                SymmetricKeyAlgorithm::Blowfish => decrypt!(
                    Blowfish,
                    key,
                    iv_vec,
                    encrypted_prefix,
                    encrypted_data,
                    bs,
                    resync
                ),
                SymmetricKeyAlgorithm::AES128 => decrypt!(
                    Aes128,
                    key,
                    iv_vec,
                    encrypted_prefix,
                    encrypted_data,
                    bs,
                    resync
                ),
                SymmetricKeyAlgorithm::AES192 => decrypt!(
                    Aes192,
                    key,
                    iv_vec,
                    encrypted_prefix,
                    encrypted_data,
                    bs,
                    resync
                ),
                SymmetricKeyAlgorithm::AES256 => decrypt!(
                    Aes256,
                    key,
                    iv_vec,
                    encrypted_prefix,
                    encrypted_data,
                    bs,
                    resync
                ),
                SymmetricKeyAlgorithm::Twofish => decrypt!(
                    Twofish,
                    key,
                    iv_vec,
                    encrypted_prefix,
                    encrypted_data,
                    bs,
                    resync
                ),
                SymmetricKeyAlgorithm::Camellia128 => decrypt!(
                    Camellia128,
                    key,
                    iv_vec,
                    encrypted_prefix,
                    encrypted_data,
                    bs,
                    resync
                ),
                SymmetricKeyAlgorithm::Camellia192 => decrypt!(
                    Camellia192,
                    key,
                    iv_vec,
                    encrypted_prefix,
                    encrypted_data,
                    bs,
                    resync
                ),
                SymmetricKeyAlgorithm::Camellia256 => decrypt!(
                    Camellia256,
                    key,
                    iv_vec,
                    encrypted_prefix,
                    encrypted_data,
                    bs,
                    resync
                ),
                SymmetricKeyAlgorithm::Private10 | SymmetricKeyAlgorithm::Other(_) => {
                    unimplemented_err!("SymmetricKeyAlgorithm {} is unsupported", u8::from(self))
                }
            }
        }

        Ok((encrypted_prefix, encrypted_data))
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
            SymmetricKeyAlgorithm::Plaintext => {}
            SymmetricKeyAlgorithm::IDEA => {
                decrypt_regular!(Idea, key, iv_vec, ciphertext)
            }
            SymmetricKeyAlgorithm::TripleDES => {
                decrypt_regular!(TdesEde3, key, iv_vec, ciphertext);
            }
            SymmetricKeyAlgorithm::CAST5 => decrypt_regular!(Cast5, key, iv_vec, ciphertext),
            SymmetricKeyAlgorithm::Blowfish => {
                decrypt_regular!(Blowfish, key, iv_vec, ciphertext)
            }
            SymmetricKeyAlgorithm::AES128 => {
                decrypt_regular!(Aes128, key, iv_vec, ciphertext)
            }
            SymmetricKeyAlgorithm::AES192 => {
                decrypt_regular!(Aes192, key, iv_vec, ciphertext)
            }
            SymmetricKeyAlgorithm::AES256 => {
                decrypt_regular!(Aes256, key, iv_vec, ciphertext)
            }
            SymmetricKeyAlgorithm::Twofish => {
                decrypt_regular!(Twofish, key, iv_vec, ciphertext)
            }
            SymmetricKeyAlgorithm::Camellia128 => {
                decrypt_regular!(Camellia128, key, iv_vec, ciphertext)
            }
            SymmetricKeyAlgorithm::Camellia192 => {
                decrypt_regular!(Camellia192, key, iv_vec, ciphertext)
            }
            SymmetricKeyAlgorithm::Camellia256 => {
                decrypt_regular!(Camellia256, key, iv_vec, ciphertext)
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
                SymmetricKeyAlgorithm::Plaintext => {}
                SymmetricKeyAlgorithm::IDEA => {
                    encrypt!(Idea, key, iv_vec, prefix, data, bs, resync)
                }
                SymmetricKeyAlgorithm::TripleDES => {
                    encrypt!(TdesEde3, key, iv_vec, prefix, data, bs, resync);
                }
                SymmetricKeyAlgorithm::CAST5 => {
                    encrypt!(Cast5, key, iv_vec, prefix, data, bs, resync)
                }
                SymmetricKeyAlgorithm::Blowfish => {
                    encrypt!(Blowfish, key, iv_vec, prefix, data, bs, resync)
                }
                SymmetricKeyAlgorithm::AES128 => {
                    encrypt!(Aes128, key, iv_vec, prefix, data, bs, resync)
                }
                SymmetricKeyAlgorithm::AES192 => {
                    encrypt!(Aes192, key, iv_vec, prefix, data, bs, resync)
                }
                SymmetricKeyAlgorithm::AES256 => {
                    encrypt!(Aes256, key, iv_vec, prefix, data, bs, resync)
                }
                SymmetricKeyAlgorithm::Twofish => {
                    encrypt!(Twofish, key, iv_vec, prefix, data, bs, resync)
                }
                SymmetricKeyAlgorithm::Camellia128 => {
                    encrypt!(Camellia128, key, iv_vec, prefix, data, bs, resync)
                }
                SymmetricKeyAlgorithm::Camellia192 => {
                    encrypt!(Camellia192, key, iv_vec, prefix, data, bs, resync)
                }
                SymmetricKeyAlgorithm::Camellia256 => {
                    encrypt!(Camellia256, key, iv_vec, prefix, data, bs, resync)
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
        // TODO: actual cfb mode used in pgp
        match self {
            SymmetricKeyAlgorithm::Plaintext => {}
            SymmetricKeyAlgorithm::IDEA => encrypt_regular!(Idea, key, iv_vec, plaintext),
            SymmetricKeyAlgorithm::TripleDES => {
                encrypt_regular!(TdesEde3, key, iv_vec, plaintext);
            }
            SymmetricKeyAlgorithm::CAST5 => encrypt_regular!(Cast5, key, iv_vec, plaintext),
            SymmetricKeyAlgorithm::Blowfish => {
                encrypt_regular!(Blowfish, key, iv_vec, plaintext)
            }
            SymmetricKeyAlgorithm::AES128 => encrypt_regular!(Aes128, key, iv_vec, plaintext),
            SymmetricKeyAlgorithm::AES192 => encrypt_regular!(Aes192, key, iv_vec, plaintext),
            SymmetricKeyAlgorithm::AES256 => encrypt_regular!(Aes256, key, iv_vec, plaintext),
            SymmetricKeyAlgorithm::Twofish => encrypt_regular!(Twofish, key, iv_vec, plaintext),
            SymmetricKeyAlgorithm::Camellia128 => {
                encrypt_regular!(Camellia128, key, iv_vec, plaintext)
            }
            SymmetricKeyAlgorithm::Camellia192 => {
                encrypt_regular!(Camellia192, key, iv_vec, plaintext)
            }
            SymmetricKeyAlgorithm::Camellia256 => {
                encrypt_regular!(Camellia256, key, iv_vec, plaintext)
            }
            SymmetricKeyAlgorithm::Private10 | SymmetricKeyAlgorithm::Other(_) => {
                unimplemented_err!("SymmetricKeyAlgorithm {} is unsupported", u8::from(self))
            }
        }
        Ok(())
    }

    /// Generate a new session key.
    pub fn new_session_key<R: Rng + CryptoRng>(self, mut rng: R) -> Vec<u8> {
        let mut session_key = vec![0u8; self.key_size()];
        rng.fill_bytes(&mut session_key);
        session_key
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    use super::*;

    macro_rules! roundtrip {
        ($name:ident, $alg:path) => {
            #[test]
            fn $name() {
                let mut rng = ChaCha8Rng::seed_from_u64(0);

                // Protected
                for i in 1..1024 {
                    let data = (0..i).map(|_| rng.gen()).collect::<Vec<_>>();
                    let key = (0..$alg.key_size()).map(|_| rng.gen()).collect::<Vec<_>>();

                    let mut ciphertext = $alg.encrypt_protected(&mut rng, &key, &data).unwrap();
                    assert_ne!(data, ciphertext);

                    let plaintext = $alg.decrypt_protected(&key, &mut ciphertext).unwrap();
                    assert_eq!(data, plaintext);
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
        let mut cipher_text: [u8; 0] = [];
        assert!(SymmetricKeyAlgorithm::AES128
            .decrypt(&key, &mut cipher_text)
            .is_err());
    }
}

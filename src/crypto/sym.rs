use aes::{Aes128, Aes192, Aes256};
use blowfish::Blowfish;
use cast5::Cast5;
use cfb_mode::stream_cipher::{NewStreamCipher, StreamCipher};
use cfb_mode::Cfb;
use des::TdesEde3;
use rand::{thread_rng, RngCore};
use sha1::{Digest, Sha1};
use twofish::Twofish;

use crypto::checksum;
use errors::Result;

macro_rules! decrypt {
    ($mode:ident, $key:expr, $iv:expr, $prefix:expr, $data:expr, $bs:expr, $resync:expr) => {{
        info!("key {}", hex::encode($key));
        info!("iv {}", hex::encode($iv));
        info!("prefix {}", hex::encode(&$prefix));

        let mut mode = Cfb::<$mode>::new_var($key, $iv)?;
        mode.decrypt($prefix);

        // quick check, before decrypting the rest
        ensure_eq!(
            $prefix[$bs - 2],
            $prefix[$bs],
            "cfb decrypt, quick check part 1"
        );
        ensure_eq!(
            $prefix[$bs - 1],
            $prefix[$bs + 1],
            "cfb decrypt, quick check part 2"
        );

        info!("decypting: {}", hex::encode(&$data));
        if $resync {
            unimplemented!("CFB resync is not here");
        // info!("resync {}", hex::encode(&$prefix[2..$bs + 2]));
        // let mut mode = Cfb::<$mode>::new_var($key, &$prefix[2..$bs + 2])?;
        // mode.decrypt($data);
        } else {
            mode.decrypt($data);
        }
    }};
}

macro_rules! encrypt {
    ($mode:ident, $key:expr, $iv:expr, $prefix:expr, $data:expr, $bs:expr, $resync:expr) => {{
        info!("key {}", hex::encode($key));
        info!("iv {}", hex::encode($iv));
        info!("prefix {}", hex::encode(&$prefix));

        let mut mode = Cfb::<$mode>::new_var($key, $iv)?;
        mode.encrypt($prefix);

        info!("encrypting: {}", hex::encode(&$data));
        if $resync {
            unimplemented!("CFB resync is not here");
        // info!("resync {}", hex::encode(&$prefix[2..$bs + 2]));
        // let mut mode = Cfb::<$mode>::new_var($key, &$prefix[2..$bs + 2])?;
        // mode.encrypt($data);
        } else {
            mode.encrypt($data);
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

/// Available symmetric key algorithms.
#[derive(Debug, PartialEq, Eq, Copy, Clone, FromPrimitive)]
#[repr(u8)]
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
    // 5 & 6 are reserved
    AES128 = 7,
    AES192 = 8,
    AES256 = 9,
    /// Twofish with 256-bit key [TWOFISH]
    Twofish = 10,
    Camellia128 = 11,
    Camellia192 = 12,
    Camellia256 = 13,
    Private10 = 110,
}

impl SymmetricKeyAlgorithm {
    /// The size of a single block in bytes.
    /// Based on https://github.com/gpg/libgcrypt/blob/master/cipher
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
            SymmetricKeyAlgorithm::Private10 => 0,
        }
    }

    /// The size of a single block in bytes.
    /// Based on https://github.com/gpg/libgcrypt/blob/master/cipher
    pub fn key_size(self) -> usize {
        match self {
            SymmetricKeyAlgorithm::Plaintext => 0,
            SymmetricKeyAlgorithm::IDEA => 16,
            SymmetricKeyAlgorithm::TripleDES => 24,
            SymmetricKeyAlgorithm::CAST5 => 16,
            // TODO: Validate this is the right key size.
            SymmetricKeyAlgorithm::Blowfish => 56,
            SymmetricKeyAlgorithm::AES128 => 16,
            SymmetricKeyAlgorithm::AES192 => 24,
            SymmetricKeyAlgorithm::AES256 => 32,
            SymmetricKeyAlgorithm::Twofish => 32,
            SymmetricKeyAlgorithm::Camellia128 => 16,
            SymmetricKeyAlgorithm::Camellia192 => 24,
            SymmetricKeyAlgorithm::Camellia256 => 32,
            SymmetricKeyAlgorithm::Private10 => 0,
        }
    }

    /// Decrypt the data using CFB mode, without padding. Overwrites the input.
    /// Uses an IV of all zeroes, as specified in the openpgp cfb mode. Does
    /// resynchronization.
    pub fn decrypt<'a>(self, key: &[u8], ciphertext: &'a mut [u8]) -> Result<&'a [u8]> {
        info!("unprotected decrypt");
        let iv_vec = vec![0u8; self.block_size()];
        Ok(self.decrypt_with_iv(key, &iv_vec, ciphertext, true)?.1)
    }

    /// Decrypt the data using CFB mode, without padding. Overwrites the input.
    /// Uses an IV of all zeroes, as specified in the openpgp cfb mode.
    /// Does not do resynchronization.
    pub fn decrypt_protected<'a>(self, key: &[u8], ciphertext: &'a mut [u8]) -> Result<&'a [u8]> {
        info!("{}", hex::encode(&ciphertext));
        info!("protected decrypt");
        let iv_vec = vec![0u8; self.block_size()];
        let cv_len = ciphertext.len();
        let (prefix, res) = self.decrypt_with_iv(key, &iv_vec, ciphertext, false)?;
        info!("{}", hex::encode(&res));
        // MDC is 1 byte packet tag, 1 byte length prefix and 20 bytes SHA1 hash.
        let mdc_len = 22;
        let (data, mdc) = res.split_at(res.len() - mdc_len);
        info!(
            "decrypted {}b from {}b ({}|{})",
            res.len(),
            cv_len,
            data.len(),
            mdc.len()
        );

        info!("mdc: {}", hex::encode(mdc));

        ensure_eq!(mdc[0], 0xD3, "invalid MDC tag");
        ensure_eq!(mdc[1], 0x14, "invalid MDC length");

        checksum::sha1(&mdc[2..], &[prefix, data, &mdc[0..2]].concat())?;

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
    #[cfg_attr(feature = "cargo-clippy", allow(clippy::complexity))]
    pub fn decrypt_with_iv<'a>(
        self,
        key: &[u8],
        iv_vec: &[u8],
        ciphertext: &'a mut [u8],
        resync: bool,
    ) -> Result<(&'a [u8], &'a [u8])> {
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
                SymmetricKeyAlgorithm::Camellia128 => {
                    unimplemented_err!("Camellia 128 not yet available")
                }
                SymmetricKeyAlgorithm::Camellia192 => {
                    unimplemented_err!("Camellia 192 not yet available")
                }
                SymmetricKeyAlgorithm::Camellia256 => {
                    unimplemented_err!("Camellia 256 not yet available")
                }
                SymmetricKeyAlgorithm::Private10 => unimplemented_err!(
                    "Private10 should not be used, and only exist for compatability"
                ),
            }
        }

        info!(
            "{}\n{}",
            hex::encode(&encrypted_prefix),
            hex::encode(&encrypted_data)
        );
        Ok((encrypted_prefix, encrypted_data))
    }

    /// Decrypt the data using CFB mode, without padding. Overwrites the input.
    /// This is regular CFB, not OpenPgP CFB.
    pub fn decrypt_with_iv_regular<'a>(
        self,
        key: &[u8],
        iv_vec: &[u8],
        ciphertext: &'a mut [u8],
    ) -> Result<()> {
        match self {
            SymmetricKeyAlgorithm::Plaintext => {}
            SymmetricKeyAlgorithm::IDEA => unimplemented!("IDEA encrypt"),
            SymmetricKeyAlgorithm::TripleDES => {
                decrypt_regular!(TdesEde3, key, iv_vec, ciphertext, self.block_size());
            }
            SymmetricKeyAlgorithm::CAST5 => decrypt_regular!(Cast5, key, iv_vec, ciphertext, bs),
            SymmetricKeyAlgorithm::Blowfish => {
                decrypt_regular!(Blowfish, key, iv_vec, ciphertext, self.block_size())
            }
            SymmetricKeyAlgorithm::AES128 => {
                decrypt_regular!(Aes128, key, iv_vec, ciphertext, self.block_size())
            }
            SymmetricKeyAlgorithm::AES192 => {
                decrypt_regular!(Aes192, key, iv_vec, ciphertext, self.block_size())
            }
            SymmetricKeyAlgorithm::AES256 => {
                decrypt_regular!(Aes256, key, iv_vec, ciphertext, self.block_size())
            }
            SymmetricKeyAlgorithm::Twofish => {
                decrypt_regular!(Twofish, key, iv_vec, ciphertext, self.block_size())
            }
            SymmetricKeyAlgorithm::Camellia128 => {
                unimplemented_err!("Camellia 128 not yet available")
            }
            SymmetricKeyAlgorithm::Camellia192 => {
                unimplemented_err!("Camellia 192 not yet available")
            }
            SymmetricKeyAlgorithm::Camellia256 => {
                unimplemented_err!("Camellia 256 not yet available")
            }
            SymmetricKeyAlgorithm::Private10 => {
                unimplemented_err!("Private10 should not be used, and only exist for compatability")
            }
        }

        Ok(())
    }

    /// Encrypt the data using CFB mode, without padding. Overwrites the input.
    /// Uses an IV of all zeroes, as specified in the openpgp cfb mode.
    pub fn encrypt(self, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        info!("encrypt unprotected");

        let iv_vec = vec![0u8; self.block_size()];

        let bs = self.block_size();
        let mut rng = thread_rng();

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

    pub fn encrypt_protected<'a>(self, key: &[u8], plaintext: &'a [u8]) -> Result<Vec<u8>> {
        info!("{}", hex::encode(&plaintext));
        info!("protected encrypt");

        // MDC is 1 byte packet tag, 1 byte length prefix and 20 bytes SHA1 hash.
        let mdc_len = 22;

        let bs = self.block_size();
        let mut rng = thread_rng();

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

        info!(
            "mdc: {}",
            hex::encode(&ciphertext[(prefix_len + plaintext_len)..])
        );
        // IV is all zeroes
        let iv_vec = vec![0u8; self.block_size()];

        info!("encrypting: {}", hex::encode(&ciphertext));

        self.encrypt_with_iv(key, &iv_vec, &mut ciphertext, false)?;

        Ok(ciphertext)
    }

    /// Encrypt the data using CFB mode, without padding. Overwrites the input.
    ///
    /// OpenPGP CFB mode uses an initialization vector (IV) of all zeros, and
    /// prefixes the plaintext with BS+2 octets of random data, such that
    /// octets BS+1 and BS+2 match octets BS-1 and BS. It does a CFB
    /// resynchronization after encrypting those BS+2 octets.
    #[allow(clippy::cyclomatic_complexity)] // FIXME
    pub fn encrypt_with_iv<'a>(
        self,
        key: &[u8],
        iv_vec: &[u8],
        ciphertext: &'a mut [u8],
        resync: bool,
    ) -> Result<()> {
        let bs = self.block_size();

        let (prefix, data) = ciphertext.split_at_mut(bs + 2);

        {
            match self {
                SymmetricKeyAlgorithm::Plaintext => {}
                SymmetricKeyAlgorithm::IDEA => unimplemented_err!("IDEA encrypt"),
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
                    unimplemented_err!("Camellia 128 not yet available")
                }
                SymmetricKeyAlgorithm::Camellia192 => {
                    unimplemented_err!("Camellia 192 not yet available")
                }
                SymmetricKeyAlgorithm::Camellia256 => {
                    unimplemented_err!("Camellia 256 not yet available")
                }
                SymmetricKeyAlgorithm::Private10 => {
                    bail!("Private10 should not be used, and only exist for compatability")
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
            SymmetricKeyAlgorithm::IDEA => unimplemented!("IDEA encrypt"),
            SymmetricKeyAlgorithm::TripleDES => {
                encrypt_regular!(TdesEde3, key, iv_vec, plaintext, bs);
            }
            SymmetricKeyAlgorithm::CAST5 => encrypt_regular!(Cast5, key, iv_vec, plaintext, bs),
            SymmetricKeyAlgorithm::Blowfish => {
                encrypt_regular!(Blowfish, key, iv_vec, plaintext, bs)
            }
            SymmetricKeyAlgorithm::AES128 => encrypt_regular!(Aes128, key, iv_vec, plaintext, bs),
            SymmetricKeyAlgorithm::AES192 => encrypt_regular!(Aes192, key, iv_vec, plaintext, bs),
            SymmetricKeyAlgorithm::AES256 => encrypt_regular!(Aes256, key, iv_vec, plaintext, bs),
            SymmetricKeyAlgorithm::Twofish => encrypt_regular!(Twofish, key, iv_vec, plaintext, bs),
            SymmetricKeyAlgorithm::Camellia128 => {
                unimplemented_err!("Camellia 128 not yet available")
            }
            SymmetricKeyAlgorithm::Camellia192 => {
                unimplemented_err!("Camellia 192 not yet available")
            }
            SymmetricKeyAlgorithm::Camellia256 => {
                unimplemented_err!("Camellia 256 not yet available")
            }
            SymmetricKeyAlgorithm::Private10 => {
                unimplemented_err!("Private10 should not be used, and only exist for compatability")
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;

    macro_rules! roundtrip {
        ($name:ident, $alg:path) => {
            #[test]
            fn $name() {
                let rng = &mut XorShiftRng::from_seed([
                    0x3, 0x8, 0x3, 0xe, 0x3, 0x8, 0x3, 0xe, 0x3, 0x8, 0x3, 0xe, 0x3, 0x8, 0x3, 0xe,
                ]);

                // Protected
                for i in 1..1024 {
                    let data = (0..i).map(|_| rng.gen()).collect::<Vec<_>>();
                    let key = (0..$alg.key_size()).map(|_| rng.gen()).collect::<Vec<_>>();

                    let mut ciphertext = $alg.encrypt_protected(&key, &data).unwrap();
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
}

use std::io::{self, BufRead};

use byteorder::WriteBytesExt;
use bytes::Bytes;
use rand::{CryptoRng, Rng, RngCore};

use crate::{
    crypto::{aead::AeadAlgorithm, hash::HashAlgorithm, sym::SymmetricKeyAlgorithm},
    errors::{bail, ensure, unimplemented_err, Result},
    parsing_reader::BufReadParsing,
    ser::Serialize,
    types::KeyVersion,
};

const EXPBIAS: u32 = 6;
const DEFAULT_ITER_SALTED_COUNT: u8 = 224;

/// Restriction for Argon2 memory usage (in KiB) to prevent OOM attacks
const ARGON2_MEMORY_LIMIT_KIB: u32 = 2 * 1024 * 1024; // 2 ~mio KiB (== 2 GiB)

/// The available s2k usages.
///
/// Ref 3.7.2.1. Secret-Key Encryption
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum S2kUsage {
    /// 0
    Unprotected,
    /// 1..253
    LegacyCfb(SymmetricKeyAlgorithm),
    /// 253
    Aead,
    /// 254
    Cfb,
    /// 255
    MalleableCfb,
}

#[derive(derive_more::Debug, PartialEq, Eq, Clone)]
pub enum S2kParams {
    Unprotected,
    LegacyCfb {
        sym_alg: SymmetricKeyAlgorithm,
        #[debug("{}", hex::encode(iv))]
        iv: Bytes,
    },
    Aead {
        sym_alg: SymmetricKeyAlgorithm,
        aead_mode: AeadAlgorithm,
        s2k: StringToKey,
        #[debug("{}", hex::encode(nonce))]
        nonce: Bytes,
    },
    Cfb {
        sym_alg: SymmetricKeyAlgorithm,
        s2k: StringToKey,
        #[debug("{}", hex::encode(iv))]
        iv: Bytes,
    },
    MalleableCfb {
        sym_alg: SymmetricKeyAlgorithm,
        s2k: StringToKey,
        #[debug("{}", hex::encode(iv))]
        iv: Bytes,
    },
}

impl From<&S2kParams> for u8 {
    fn from(value: &S2kParams) -> Self {
        match value {
            S2kParams::Unprotected => 0,
            S2kParams::LegacyCfb { sym_alg, .. } => (*sym_alg).into(),
            S2kParams::Aead { .. } => 253,
            S2kParams::Cfb { .. } => 254,
            S2kParams::MalleableCfb { .. } => 255,
        }
    }
}

impl S2kParams {
    /// Create a new default set of parameters
    /// and initialises relevant randomized values.
    ///
    /// For v6 keys:
    /// - Ocb with AES256
    /// - Argon2 derivation (with parameter choice (2) from <https://www.rfc-editor.org/rfc/rfc9106#name-parameter-choice>)
    ///
    /// For v4 keys:
    /// - AES256
    /// - CFB
    /// - Iterated and Salted with 224 rounds
    pub fn new_default<R: RngCore + CryptoRng + ?Sized>(
        rng: &mut R,
        key_version: KeyVersion,
    ) -> Self {
        match key_version {
            KeyVersion::V6 => {
                let sym_alg = SymmetricKeyAlgorithm::AES256;
                let aead_mode = AeadAlgorithm::Ocb;

                let mut nonce = vec![0u8; aead_mode.nonce_size()];
                rng.fill(&mut nonce[..]);

                let mut salt = [0u8; 16];
                rng.fill(&mut salt[..]);

                S2kParams::Aead {
                    sym_alg,
                    aead_mode,

                    // parameter choice (2) from https://www.rfc-editor.org/rfc/rfc9106#name-parameter-choice
                    s2k: StringToKey::Argon2 {
                        salt,
                        t: 3,
                        p: 4,
                        m_enc: 16, // 64 MiB
                    },
                    nonce: nonce.into(),
                }
            }
            _ => {
                let sym_alg = SymmetricKeyAlgorithm::AES256;

                let mut iv = vec![0u8; sym_alg.block_size()];
                rng.fill(&mut iv[..]);

                Self::Cfb {
                    sym_alg,
                    s2k: StringToKey::new_default(rng),
                    iv: iv.into(),
                }
            }
        }
    }
}

impl From<u8> for S2kUsage {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Unprotected,
            v @ 1..=252 => Self::LegacyCfb(SymmetricKeyAlgorithm::from(v)),
            253 => Self::Aead,
            254 => Self::Cfb,
            255 => Self::MalleableCfb,
        }
    }
}

#[derive(derive_more::Debug, PartialEq, Eq, Clone)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum StringToKey {
    /// Type ID 0
    Simple { hash_alg: HashAlgorithm },
    /// Type ID 1
    Salted {
        hash_alg: HashAlgorithm,
        #[debug("{}", hex::encode(salt))]
        salt: [u8; 8],
    },
    /// Type ID 2
    #[cfg_attr(test, proptest(skip))] // doesn't roundtrip
    Reserved {
        #[debug("{}", hex::encode(unknown))]
        unknown: Bytes,
    },
    /// Type ID 3
    IteratedAndSalted {
        hash_alg: HashAlgorithm,
        #[debug("{}", hex::encode(salt))]
        salt: [u8; 8],
        count: u8,
    },
    /// Type ID 4
    Argon2 {
        #[debug("{}", hex::encode(salt))]
        salt: [u8; 16],
        /// one-octet number of passes t
        t: u8,
        /// one-octet degree of parallelism p
        p: u8,
        /// one-octet encoded_m, specifying the exponent of the memory size
        m_enc: u8,
    },
    /// Private/Experimental S2K: 100-110
    #[cfg_attr(test, proptest(skip))] // doesn't roundtrip
    Private {
        typ: u8,
        #[debug("{}", hex::encode(unknown))]
        unknown: Bytes,
    },
    /// Unknown S2K types
    #[cfg_attr(test, proptest(skip))] // doesn't roundtrip
    Other {
        typ: u8,
        #[debug("{}", hex::encode(unknown))]
        unknown: Bytes,
    },
}

impl StringToKey {
    pub fn new_default<R: CryptoRng + RngCore + ?Sized>(rng: &mut R) -> Self {
        StringToKey::new_iterated(rng, HashAlgorithm::default(), DEFAULT_ITER_SALTED_COUNT)
    }

    pub fn new_iterated<R: CryptoRng + RngCore + ?Sized>(
        rng: &mut R,
        hash_alg: HashAlgorithm,
        count: u8,
    ) -> Self {
        let mut salt = [0u8; 8];
        rng.fill(&mut salt[..]);

        StringToKey::IteratedAndSalted {
            hash_alg,
            salt,
            count,
        }
    }

    pub fn new_argon2<R: CryptoRng + RngCore + ?Sized>(
        rng: &mut R,
        t: u8,
        p: u8,
        m_enc: u8,
    ) -> Self {
        let mut salt = [0u8; 16];
        rng.fill(&mut salt[..]);

        StringToKey::Argon2 { salt, t, p, m_enc }
    }

    pub fn id(&self) -> u8 {
        match self {
            Self::Simple { .. } => 0,
            Self::Salted { .. } => 1,
            Self::Reserved { .. } => 2,
            Self::IteratedAndSalted { .. } => 3,
            Self::Argon2 { .. } => 4,

            Self::Private { typ, .. } => *typ,
            Self::Other { typ, .. } => *typ,
        }
    }

    /// true, if this StringToKey uses a salt
    pub fn uses_salt(&self) -> bool {
        matches![
            self,
            StringToKey::Salted { .. }
                | StringToKey::IteratedAndSalted { .. }
                | StringToKey::Argon2 { .. }
        ]
    }

    /// RFC 9580 limits the use of S2K KDF results that are based on MD5, SHA-1, or RIPEMD-160.
    /// This function returns true for StringToKey configurations that use one of these hash algorithms.
    pub(crate) fn known_weak_hash_algo(&self) -> bool {
        match self {
            Self::Simple { hash_alg }
            | Self::Salted { hash_alg, .. }
            | Self::IteratedAndSalted { hash_alg, .. } => {
                hash_alg == &HashAlgorithm::Md5
                    || hash_alg == &HashAlgorithm::Sha1
                    || hash_alg == &HashAlgorithm::Ripemd160
            }
            _ => false,
        }
    }

    /// String-To-Key methods are used to convert a given password string into a key.
    /// Ref: <https://www.rfc-editor.org/rfc/rfc9580.html#name-string-to-key-s2k-specifier>
    ///
    /// Note that RFC 9580 specifies that:
    ///
    /// - Implementations MUST NOT generate packets using MD5, SHA-1, or RIPEMD-160 as a hash
    ///   function in an S2K KDF.
    /// - Implementations MUST NOT decrypt a secret using MD5, SHA-1, or RIPEMD-160 as a hash
    ///   function in an S2K KDF in a version 6 (or later) packet.
    pub fn derive_key(&self, passphrase: &[u8], key_size: usize) -> Result<Vec<u8>> {
        let key = match self {
            Self::Simple { hash_alg, .. }
            | Self::Salted { hash_alg, .. }
            | Self::IteratedAndSalted { hash_alg, .. } => {
                let Some(digest_size) = hash_alg.digest_size() else {
                    bail!("invalid hash algorithm: {}", hash_alg);
                };
                let rounds = (key_size as f32 / digest_size as f32).ceil() as usize;

                let mut key = vec![0u8; key_size];
                let zeros = vec![0u8; rounds];

                for round in 0..rounds {
                    let mut hasher = hash_alg.new_hasher()?;

                    // add 0s prefix
                    hasher.update(&zeros[..round]);

                    match self {
                        StringToKey::Simple { .. } => {
                            hasher.update(passphrase);
                        }
                        StringToKey::Salted { salt, .. } => {
                            hasher.update(salt);
                            hasher.update(passphrase);
                        }
                        StringToKey::IteratedAndSalted { salt, count, .. } => {
                            /// Converts a coded iteration count into a decoded count.
                            /// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#section-3.7.1.3-3
                            fn decode_count(coded_count: u8) -> usize {
                                ((16u32 + u32::from(coded_count & 15))
                                    << (u32::from(coded_count >> 4) + EXPBIAS))
                                    as usize
                            }

                            let data_size = salt.len() + passphrase.len();
                            // how many bytes are supposed to be hashed
                            let mut count = decode_count(*count);

                            if count < data_size {
                                // if the count is less, hash one full set
                                count = data_size;
                            }

                            while count > data_size {
                                hasher.update(salt);
                                hasher.update(passphrase);
                                count -= data_size;
                            }

                            if count < salt.len() {
                                hasher.update(&salt[..count]);
                            } else {
                                hasher.update(salt);
                                count -= salt.len();
                                hasher.update(&passphrase[..count]);
                            }
                        }
                        _ => unimplemented_err!("S2K {:?} is not available", self),
                    }

                    let start = round * digest_size;
                    let end = if round == rounds - 1 {
                        key_size
                    } else {
                        (round + 1) * digest_size
                    };

                    let hash = hasher.finalize();
                    key[start..end].copy_from_slice(&hash[..end - start]);
                }

                key
            }
            Self::Argon2 { salt, t, p, m_enc } => {
                // Argon2 is invoked with the passphrase as P, the salt as S, the values of t, p
                // and m as described above, the required key size as the tag length T, 0x13 as the
                // version v, and Argon2id as the type

                // Limit the amount of CPU resources an Argon2 derivation may consume,
                // to limit potential DoS attacks via e.g. one (or multiple) adversarial SKESKv6,
                // especially if an application tries to decrypt without user interaction.
                //
                // Benchmark results (on a desktop machine in 2024), for reference:
                // t = 16, p = 16, m = 8 GiB finished in 74.93s
                // t = 16, p = 16, m = 2 GiB finished in 18.43s
                // t = 16, p = 17, m = 2 GiB finished in 18.37s
                // t = 32, p = 32, m = 2 GiB finished in 35.54s
                // t = 128, p = 17, m = 2 GiB finished in 144.57
                ensure!(
                    *t <= 32 && *p <= 32,
                    "unsupported settings t={}, p={} in argon s2k",
                    t,
                    p,
                );

                // The encoded memory size MUST be a value from 3+ceil(log_2(p)) to 31, such that
                // the decoded memory size m is a value from 8*p to 2**31
                let min_m = (*p as f32).log2().ceil() as u8;
                ensure!(
                    *m_enc >= min_m && *m_enc <= 31,
                    "unsupported value {} for m in argon s2k",
                    m_enc
                );

                // Decoded memory size
                // (Note that memory-hardness size is indicated in kibibytes (KiB), not octets.)
                let m = 2u32.pow(*m_enc as u32);

                ensure!(
                    m <= ARGON2_MEMORY_LIMIT_KIB,
                    "unsupported memory usage setting ({} KiB) for m in argon s2k",
                    m
                );

                use argon2::{Algorithm, Argon2, Params, Version};

                let a2 = Argon2::new(
                    Algorithm::Argon2id,
                    Version::V0x13,
                    Params::new(m, *t as u32, *p as u32, Some(key_size))?,
                );

                let mut output_key_material = vec![0; key_size];

                a2.hash_password_into(passphrase, salt, &mut output_key_material)?;

                output_key_material
            }

            _ => unimplemented_err!("S2K {:?} is not available", self),
        };

        Ok(key)
    }

    #[allow(clippy::len_without_is_empty)]
    pub(crate) fn len(&self) -> Result<u8> {
        let len = match self {
            Self::Simple { .. } => 2,
            Self::Salted { .. } => 10,
            Self::IteratedAndSalted { .. } => 11,
            Self::Argon2 { .. } => 20,
            _ => bail!("not implemented for StringToKey: {:?}", self),
        };

        Ok(len)
    }

    /// Parses the identifier from the given buffer.
    pub fn try_from_reader<B: BufRead>(mut i: B) -> Result<Self> {
        let typ = i.read_u8()?;

        match typ {
            0 => {
                let hash_alg = i.read_u8().map(HashAlgorithm::from)?;

                Ok(StringToKey::Simple { hash_alg })
            }
            1 => {
                let hash_alg = i.read_u8().map(HashAlgorithm::from)?;
                let salt = i.read_array::<8>()?;

                Ok(StringToKey::Salted { hash_alg, salt })
            }
            2 => {
                let unknown = i.rest()?.freeze();
                Ok(StringToKey::Reserved { unknown })
            }
            3 => {
                let hash_alg = i.read_u8().map(HashAlgorithm::from)?;
                let salt = i.read_array::<8>()?;
                let count = i.read_u8()?;

                Ok(StringToKey::IteratedAndSalted {
                    hash_alg,
                    salt,
                    count,
                })
            }
            4 => {
                let salt = i.read_array::<16>()?;
                let t = i.read_u8()?;
                let p = i.read_u8()?;
                let m_enc = i.read_u8()?;

                Ok(StringToKey::Argon2 { salt, t, p, m_enc })
            }
            100..=110 => {
                let unknown = i.rest()?.freeze();
                Ok(StringToKey::Private { typ, unknown })
            }
            _ => {
                let unknown = i.rest()?.freeze();
                Ok(StringToKey::Other { typ, unknown })
            }
        }
    }
}

impl Serialize for StringToKey {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            Self::Simple { hash_alg } => {
                writer.write_u8(self.id())?;
                writer.write_u8((*hash_alg).into())?;
            }
            Self::Salted { hash_alg, salt } => {
                writer.write_u8(self.id())?;
                writer.write_u8((*hash_alg).into())?;
                writer.write_all(salt)?;
            }
            Self::IteratedAndSalted {
                hash_alg,
                salt,
                count,
            } => {
                writer.write_u8(self.id())?;
                writer.write_u8((*hash_alg).into())?;
                writer.write_all(salt)?;
                writer.write_u8(*count)?;
            }
            Self::Argon2 { salt, t, p, m_enc } => {
                writer.write_u8(self.id())?;
                writer.write_all(salt)?;
                writer.write_all(&[*t, *p, *m_enc])?;
            }

            Self::Reserved { unknown, .. }
            | Self::Private { unknown, .. }
            | Self::Other { unknown, .. } => {
                writer.write_u8(self.id())?;
                writer.write_all(unknown)?;
            }
        }

        Ok(())
    }

    fn write_len(&self) -> usize {
        let mut sum = 0;
        match self {
            Self::Simple { .. } => {
                sum += 1 + 1;
            }
            Self::Salted { salt, .. } => {
                sum += 1 + 1;
                sum += salt.len();
            }
            Self::IteratedAndSalted { salt, .. } => {
                sum += 1 + 1;
                sum += salt.len();
                sum += 1;
            }
            Self::Argon2 { salt, .. } => {
                sum += 1;
                sum += salt.len();
                sum += 3;
            }

            Self::Reserved { unknown, .. }
            | Self::Private { unknown, .. }
            | Self::Other { unknown, .. } => {
                sum += 1;
                sum += unknown.len();
            }
        }

        sum
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use rand::{
        distr::{Alphanumeric, SampleString},
        SeedableRng,
    };
    use rand_chacha::ChaCha8Rng;

    use super::*;

    #[test]
    #[ignore]
    fn iterated_and_salted() {
        let sizes = [10, 100, 1000];
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        let algs = [
            HashAlgorithm::Sha1,
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha3_256,
        ];
        let counts = [
            1u8,
            224u8,   // default in rpgp
            u8::MAX, // maximum possible
        ];
        let sym_algs = [SymmetricKeyAlgorithm::AES128, SymmetricKeyAlgorithm::AES256];

        for size in sizes {
            for sym_alg in sym_algs {
                for alg in algs {
                    for count in counts {
                        println!("{size}/{alg:?}/{count}/{sym_alg:?}");
                        let s2k = StringToKey::new_iterated(&mut rng, alg, count);
                        let passphrase = Alphanumeric.sample_string(&mut rng, size);

                        let res = s2k
                            .derive_key(passphrase.as_bytes(), sym_alg.key_size())
                            .expect("failed to derive key");
                        assert_eq!(res.len(), sym_alg.key_size());
                    }
                }
            }
        }
    }

    #[test]
    #[ignore] // slow in debug mode
    fn argon2() {
        // test vectors from RFC 9580

        // 16 byte key size
        let s2k = StringToKey::Argon2 {
            salt: [
                0x9c, 0x52, 0xf8, 0x3c, 0x27, 0xf9, 0x5e, 0x50, 0xd5, 0x35, 0x44, 0x0e, 0xcd, 0xff,
                0x31, 0x36,
            ],
            t: 1,
            p: 4,
            m_enc: 21,
        };
        let key = s2k.derive_key(b"password", 16).expect("argon derive");
        assert_eq!(
            key,
            [
                0x84, 0xa3, 0x64, 0x3c, 0x39, 0xd5, 0xf5, 0x50, 0x52, 0x6d, 0x19, 0x39, 0xe8, 0x57,
                0xfa, 0x66
            ]
        );

        // 24 byte key size
        let s2k = StringToKey::Argon2 {
            salt: [
                0xe1, 0x4c, 0xac, 0x47, 0x15, 0x34, 0x59, 0x18, 0xa9, 0x62, 0xdc, 0xa3, 0x47, 0xe1,
                0x43, 0xf8,
            ],
            t: 1,
            p: 4,
            m_enc: 21,
        };
        let key = s2k.derive_key(b"password", 24).expect("argon derive");
        assert_eq!(
            key,
            [
                0xf5, 0x42, 0x47, 0x6d, 0x2b, 0x9f, 0xf4, 0x35, 0x15, 0x85, 0x18, 0x11, 0x21, 0x2d,
                0xe9, 0x49, 0x7f, 0x1b, 0xfe, 0x1a, 0x3d, 0x08, 0xd7, 0x07
            ]
        );

        // 32 byte key size
        let s2k = StringToKey::Argon2 {
            salt: [
                0xb8, 0x78, 0x95, 0x20, 0x20, 0x6f, 0xf7, 0x99, 0xc6, 0x88, 0x2c, 0x42, 0x45, 0xa6,
                0x62, 0x7c,
            ],
            t: 1,
            p: 4,
            m_enc: 21,
        };
        let key = s2k.derive_key(b"password", 32).expect("argon derive");
        assert_eq!(
            key,
            [
                0x4e, 0xd7, 0xeb, 0x27, 0x43, 0x4f, 0x6d, 0xf6, 0x23, 0xce, 0xe3, 0xac, 0x08, 0xb7,
                0x63, 0xc4, 0xaf, 0x79, 0xdf, 0xde, 0x5f, 0xdc, 0x92, 0xdd, 0x1d, 0x88, 0x1c, 0x6c,
                0x99, 0x93, 0x8b, 0x4f
            ]
        );
    }

    #[test]
    #[ignore] // slow in debug mode
    fn argon2_skesk_msg() {
        // Tests decrypting the messages from
        // https://www.rfc-editor.org/rfc/rfc9580.html#name-sample-messages-encrypted-u
        //
        // "These messages are the literal data "Hello, world!" encrypted using v1 SEIPD, with Argon2
        // and the passphrase "password", using different session key sizes."

        const MSGS: &[&str] = &[
            "./tests/unit-tests/argon2/aes128.msg",
            "./tests/unit-tests/argon2/aes192.msg",
            "./tests/unit-tests/argon2/aes256.msg",
        ];

        use crate::composed::Message;

        for filename in MSGS {
            println!("reading {}", filename);

            let (msg, header) = Message::from_armor_file(filename).expect("failed to load msg");

            dbg!(&header);
            let mut decrypted = msg
                .decrypt_with_password(&"password".into())
                .expect("decrypt argon2 skesk");

            let data = decrypted.as_data_vec().unwrap();
            assert_eq!(data, b"Hello, world!");

            // roundtrip
            // TODO: how?
            // let armored = MessageBuilder::from_bytes(&data[..])
            //     .seipd_v1(&mut rng, )
            //     .to_armored_string(ArmorOptions {
            //         headers: Some(&header),
            //         include_checksum: false, // No checksum on v6
            //     })
            //     .expect("encode");

            // let orig_armored = std::fs::read_to_string(filename).expect("file read");

            // let orig_armored = orig_armored.replace("\r\n", "\n").replace('\r', "\n");
            // let armored = armored
            //     .to_string()
            //     .replace("\r\n", "\n")
            //     .replace('\r', "\n");

            // assert_eq!(armored, orig_armored);
        }
    }

    // "These messages are the literal data "Hello, world!" encrypted using AES-128 with various AEADs
    #[test]
    fn test_aead_skesk_msg_gcm() {
        aead_skesk_msg("./tests/unit-tests/aead/gcm.msg");
    }
    #[test]
    fn test_aead_skesk_msg_eax() {
        aead_skesk_msg("./tests/unit-tests/aead/eax.msg");
    }
    #[test]
    fn test_aead_skesk_msg_ocb() {
        aead_skesk_msg("./tests/unit-tests/aead/ocb.msg");
    }

    /// Tests decrypting messages
    fn aead_skesk_msg(filename: &str) {
        let _ = pretty_env_logger::try_init();

        use crate::composed::Message;

        println!("reading {}", filename);
        let (msg, _header) = Message::from_armor_file(filename).expect("parse");

        let mut decrypted = msg
            .decrypt_with_password(&"password".into())
            .expect("decrypt");

        dbg!(&decrypted);
        let data = decrypted.as_data_vec().unwrap();
        assert_eq!(data, b"Hello, world!");

        // TODO: how?
        // // roundtrip
        // let armored = msg
        //     .to_armored_string(ArmorOptions {
        //         headers: Some(&header),
        //         include_checksum: false, // No checksum on v6
        //     })
        //     .expect("encode");

        // let orig_armored = std::fs::read_to_string(filename).expect("file read");

        // let orig_armored = orig_armored.replace("\r\n", "\n").replace('\r', "\n");
        // let armored = armored
        //     .to_string()
        //     .replace("\r\n", "\n")
        //     .replace('\r', "\n");

        // assert_eq!(armored, orig_armored);
    }

    proptest! {
        #[test]
        fn write_len(s2k: StringToKey) {
            let mut buf = Vec::new();
            s2k.to_writer(&mut buf).unwrap();
            assert_eq!(buf.len(), s2k.write_len());
        }


        #[test]
        fn packet_roundtrip(s2k: StringToKey) {
            let mut buf = Vec::new();
            s2k.to_writer(&mut buf).unwrap();
            let new_s2k = StringToKey::try_from_reader(&mut &buf[..]).unwrap();
            assert_eq!(s2k, new_s2k);
        }
    }
}

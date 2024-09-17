use std::io;

use byteorder::WriteBytesExt;
use nom::bytes::streaming::take;
use nom::combinator::{map, rest};
use nom::number::streaming::be_u8;
use rand::{CryptoRng, Rng};

use crate::crypto::aead::AeadAlgorithm;
use crate::crypto::hash::HashAlgorithm;
use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::errors::{Error, IResult, Result};
use crate::ser::Serialize;
use crate::types::KeyVersion;

const EXPBIAS: u32 = 6;
const DEFAULT_ITER_SALTED_COUNT: u8 = 224;

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
        iv: Vec<u8>,
    },
    Aead {
        sym_alg: SymmetricKeyAlgorithm,
        aead_mode: AeadAlgorithm,
        s2k: StringToKey,
        #[debug("{}", hex::encode(nonce))]
        nonce: Vec<u8>,
    },
    Cfb {
        sym_alg: SymmetricKeyAlgorithm,
        s2k: StringToKey,
        #[debug("{}", hex::encode(iv))]
        iv: Vec<u8>,
    },
    MaleableCfb {
        sym_alg: SymmetricKeyAlgorithm,
        s2k: StringToKey,
        #[debug("{}", hex::encode(iv))]
        iv: Vec<u8>,
    },
}

impl From<&S2kParams> for u8 {
    fn from(value: &S2kParams) -> Self {
        match value {
            S2kParams::Unprotected => 0,
            S2kParams::LegacyCfb { sym_alg, .. } => (*sym_alg).into(),
            S2kParams::Aead { .. } => 253,
            S2kParams::Cfb { .. } => 254,
            S2kParams::MaleableCfb { .. } => 255,
        }
    }
}

impl S2kParams {
    /// Create a new default set of parameters
    /// and initialises relevant randomized values.
    ///
    /// For v6 keys:
    /// - Ocb with AES256
    /// - Argon2 derivation (with parameter choice (2) from https://www.rfc-editor.org/rfc/rfc9106#name-parameter-choice)
    ///
    /// For v4 keys:
    /// - AES256
    /// - CFB
    /// - Iterated and Salted with 224 rounds
    pub fn new_default<R: Rng + CryptoRng>(mut rng: R, key_version: KeyVersion) -> Self {
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
                    nonce,
                }
            }
            _ => {
                let sym_alg = SymmetricKeyAlgorithm::AES256;

                let mut iv = vec![0u8; sym_alg.block_size()];
                rng.fill(&mut iv[..]);

                Self::Cfb {
                    sym_alg,
                    s2k: StringToKey::new_default(rng),
                    iv,
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
pub enum StringToKey {
    // Type ID 0
    Simple {
        hash_alg: HashAlgorithm,
    },

    // Type ID 1
    Salted {
        hash_alg: HashAlgorithm,
        #[debug("{}", hex::encode(salt))]
        salt: [u8; 8],
    },

    // Type ID 2
    Reserved {
        #[debug("{}", hex::encode(unknown))]
        unknown: Vec<u8>,
    },

    // Type ID 3
    IteratedAndSalted {
        hash_alg: HashAlgorithm,
        #[debug("{}", hex::encode(salt))]
        salt: [u8; 8],
        count: u8,
    },

    // Type ID 4
    Argon2 {
        #[debug("{}", hex::encode(salt))]
        salt: [u8; 16],
        t: u8,     // one-octet number of passes t
        p: u8,     // one-octet degree of parallelism p
        m_enc: u8, // one-octet encoded_m, specifying the exponent of the memory size
    },

    // Private/Experimental S2K: 100-110
    Private {
        typ: u8,
        #[debug("{}", hex::encode(unknown))]
        unknown: Vec<u8>,
    },

    Other {
        typ: u8,
        #[debug("{}", hex::encode(unknown))]
        unknown: Vec<u8>,
    },
}

impl StringToKey {
    pub fn new_default<R: CryptoRng + Rng>(rng: R) -> Self {
        StringToKey::new_iterated(rng, HashAlgorithm::default(), DEFAULT_ITER_SALTED_COUNT)
    }

    pub fn new_iterated<R: CryptoRng + Rng>(
        mut rng: R,
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

    pub fn new_argon2<R: CryptoRng + Rng>(mut rng: R, t: u8, p: u8, m_enc: u8) -> Self {
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

    /// String-To-Key methods are used to convert a given password string into a key.
    /// Ref: <https://tools.ietf.org/html/rfc4880#section-3.7>
    pub fn derive_key(&self, passphrase: &str, key_size: usize) -> Result<Vec<u8>> {
        let key = match self {
            Self::Simple { hash_alg, .. }
            | Self::Salted { hash_alg, .. }
            | Self::IteratedAndSalted { hash_alg, .. } => {
                let digest_size = hash_alg.digest_size();
                let rounds = (key_size as f32 / digest_size as f32).ceil() as usize;

                let mut key = vec![0u8; key_size];
                let zeros = vec![0u8; rounds];

                for round in 0..rounds {
                    let mut hasher = hash_alg.new_hasher()?;

                    // add 0s prefix
                    hasher.update(&zeros[..round]);

                    match self {
                        StringToKey::Simple { .. } => {
                            hasher.update(passphrase.as_bytes());
                        }
                        StringToKey::Salted { salt, .. } => {
                            hasher.update(salt);
                            hasher.update(passphrase.as_bytes());
                        }
                        StringToKey::IteratedAndSalted { salt, count, .. } => {
                            /// Converts a coded iteration count into a decoded count.
                            /// Ref: https://tools.ietf.org/html/rfc4880#section-3.7.1.3
                            fn decode_count(coded_count: u8) -> usize {
                                ((16u32 + u32::from(coded_count & 15))
                                    << (u32::from(coded_count >> 4) + EXPBIAS))
                                    as usize
                            }

                            let pw = passphrase.as_bytes();
                            let data_size = salt.len() + pw.len();
                            // how many bytes are supposed to be hashed
                            let mut count = decode_count(*count);

                            if count < data_size {
                                // if the count is less, hash one full set
                                count = data_size;
                            }

                            while count > data_size {
                                hasher.update(salt);
                                hasher.update(pw);
                                count -= data_size;
                            }

                            if count < salt.len() {
                                hasher.update(&salt[..count]);
                            } else {
                                hasher.update(salt);
                                count -= salt.len();
                                hasher.update(&pw[..count]);
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

                    hasher.finish_reset_into(&mut key[start..end]);
                }

                key
            }
            Self::Argon2 { salt, t, p, m_enc } => {
                // Argon2 is invoked with the passphrase as P, the salt as S, the values of t, p
                // and m as described above, the required key size as the tag length T, 0x13 as the
                // version v, and Argon2id as the type

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

                use argon2::{Algorithm, Argon2, Params, Version};

                let a2 = Argon2::new(
                    Algorithm::Argon2id,
                    Version::V0x13,
                    Params::new(m, *t as u32, *p as u32, Some(key_size))
                        .map_err(|e| Error::Message(format!("{:?}", e)))?,
                );

                let mut output_key_material = vec![0; key_size];

                a2.hash_password_into(passphrase.as_bytes(), salt, &mut output_key_material)
                    .map_err(|e| Error::Message(format!("{:?}", e)))?;

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
}

pub fn s2k_parser(i: &[u8]) -> IResult<&[u8], StringToKey> {
    let (i, typ) = be_u8(i)?;

    match typ {
        0 => {
            let (i, hash_alg) = map(be_u8, HashAlgorithm::from)(i)?;

            Ok((i, StringToKey::Simple { hash_alg }))
        }
        1 => {
            let (i, hash_alg) = map(be_u8, HashAlgorithm::from)(i)?;
            let (i, salt) = map(take(8usize), |v: &[u8]| {
                v.try_into().expect("should never fail")
            })(i)?;

            Ok((i, StringToKey::Salted { hash_alg, salt }))
        }
        2 => {
            let (i, unknown) = map(rest, Into::into)(i)?;

            Ok((i, StringToKey::Reserved { unknown }))
        }
        3 => {
            let (i, hash_alg) = map(be_u8, HashAlgorithm::from)(i)?;
            let (i, salt) = map(take(8usize), |v: &[u8]| {
                v.try_into().expect("should never fail")
            })(i)?;
            let (i, count) = be_u8(i)?;

            Ok((
                i,
                StringToKey::IteratedAndSalted {
                    hash_alg,
                    salt,
                    count,
                },
            ))
        }
        4 => {
            let (i, salt) = map(take(16usize), |v: &[u8]| {
                v.try_into().expect("should never fail")
            })(i)?;
            let (i, t) = be_u8(i)?;
            let (i, p) = be_u8(i)?;
            let (i, m_enc) = be_u8(i)?;

            Ok((i, StringToKey::Argon2 { salt, t, p, m_enc }))
        }

        100..=110 => {
            let (i, unknown) = map(rest, Into::into)(i)?;
            Ok((i, StringToKey::Private { typ, unknown }))
        }

        _ => {
            let (i, unknown) = map(rest, Into::into)(i)?;
            Ok((i, StringToKey::Other { typ, unknown }))
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
}

#[cfg(test)]
mod tests {
    use rand::distributions::{Alphanumeric, DistString};
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    use super::*;
    use crate::ArmorOptions;

    #[test]
    #[ignore]
    fn iterated_and_salted() {
        let sizes = [10, 100, 1000];
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        let algs = [
            HashAlgorithm::SHA1,
            HashAlgorithm::SHA2_256,
            HashAlgorithm::SHA3_256,
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
                            .derive_key(&passphrase, sym_alg.key_size())
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
        let key = s2k.derive_key("password", 16).expect("argon derive");
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
        let key = s2k.derive_key("password", 24).expect("argon derive");
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
        let key = s2k.derive_key("password", 32).expect("argon derive");
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

        use crate::{composed::Deserializable, Message};

        for filename in MSGS {
            println!("reading {}", filename);

            let (msg, header) =
                Message::from_armor_single(std::fs::File::open(filename).expect("failed to open"))
                    .expect("failed to load msg");

            dbg!(&header);
            let decrypted = msg
                .decrypt_with_password(|| "password".to_string())
                .expect("decrypt argon2 skesk");

            let Message::Literal(data) = decrypted else {
                panic!("expected literal data")
            };

            assert_eq!(data.data(), b"Hello, world!");

            // roundtrip
            let armored = msg
                .to_armored_string(ArmorOptions {
                    headers: Some(&header),
                    include_checksum: false, // No checksum on v6
                })
                .expect("encode");

            let orig_armored = std::fs::read_to_string(filename).expect("file read");

            let orig_armored = orig_armored.replace("\r\n", "\n").replace('\r', "\n");
            let armored = armored
                .to_string()
                .replace("\r\n", "\n")
                .replace('\r', "\n");

            assert_eq!(armored, orig_armored);
        }
    }

    #[test]
    fn aead_skesk_msg() {
        let _ = pretty_env_logger::try_init();

        // Tests decrypting messages
        //
        // "These messages are the literal data "Hello, world!" encrypted using AES-128 with various AEADs

        const MSGS: &[&str] = &[
            "./tests/unit-tests/aead/gcm.msg",
            "./tests/unit-tests/aead/eax.msg",
            "./tests/unit-tests/aead/ocb.msg",
        ];

        use crate::{composed::Deserializable, Message};

        for filename in MSGS {
            println!("reading {}", filename);
            let raw_file = std::fs::File::open(filename).expect("file open");
            let (msg, header) = Message::from_armor_single(raw_file).expect("parse");

            let decrypted = msg
                .decrypt_with_password(|| "password".to_string())
                .expect("decrypt");

            let Message::Literal(data) = decrypted else {
                panic!("expected literal data")
            };

            assert_eq!(data.data(), b"Hello, world!");

            // roundtrip
            let armored = msg
                .to_armored_string(ArmorOptions {
                    headers: Some(&header),
                    include_checksum: false, // No checksum on v6
                })
                .expect("encode");

            let orig_armored = std::fs::read_to_string(filename).expect("file read");

            let orig_armored = orig_armored.replace("\r\n", "\n").replace('\r', "\n");
            let armored = armored
                .to_string()
                .replace("\r\n", "\n")
                .replace('\r', "\n");

            assert_eq!(armored, orig_armored);
        }
    }
}

use std::io;

use nom::bytes::streaming::take;
use nom::combinator::{map, rest};
use nom::number::streaming::be_u8;
use rand::{CryptoRng, Rng};

use crate::crypto::hash::HashAlgorithm;
use crate::errors::{Error, IResult, Result};
use crate::ser::Serialize;

const EXPBIAS: u32 = 6;
const DEFAULT_ITER_SALTED_COUNT: u8 = 224;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum StringToKey {
    // Type ID 0
    Simple {
        hash_alg: HashAlgorithm,
    },

    // Type ID 1
    Salted {
        hash_alg: HashAlgorithm,
        salt: [u8; 8],
    },

    // Type ID 2
    Reserved {
        unknown: Vec<u8>,
    },

    // Type ID 3
    IteratedAndSalted {
        hash_alg: HashAlgorithm,
        salt: [u8; 8],
        count: u8,
    },

    // Type ID 4
    Argon2 {
        salt: [u8; 16],
        t: u8,     // one-octet number of passes t
        p: u8,     // one-octet degree of parallelism p
        m_enc: u8, // one-octet encoded_m, specifying the exponent of the memory size
    },

    // Private/Experimental S2K: 100-110
    Private {
        typ: u8,
        unknown: Vec<u8>,
    },

    Other {
        typ: u8,
        unknown: Vec<u8>,
    },
}

impl StringToKey {
    pub fn new_default<R: CryptoRng + Rng>(rng: &mut R) -> Self {
        StringToKey::new_iterated(rng, HashAlgorithm::default(), DEFAULT_ITER_SALTED_COUNT)
    }

    pub fn new_iterated<R: CryptoRng + Rng>(
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
    /// Ref: https://tools.ietf.org/html/rfc4880#section-3.7
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
                        key_size - start
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
                writer.write_all(&[self.id(), u8::from(*hash_alg)])?;
            }
            Self::Salted { hash_alg, salt } => {
                writer.write_all(&[self.id(), u8::from(*hash_alg)])?;
                writer.write_all(salt)?;
            }
            Self::IteratedAndSalted {
                hash_alg,
                salt,
                count,
            } => {
                writer.write_all(&[self.id(), u8::from(*hash_alg)])?;
                writer.write_all(salt)?;
                writer.write_all(&[*count])?;
            }
            Self::Argon2 { salt, t, p, m_enc } => {
                writer.write_all(&[self.id()])?;
                writer.write_all(salt)?;
                writer.write_all(&[*t, *p, *m_enc])?;
            }

            Self::Reserved { unknown, .. }
            | Self::Private { unknown, .. }
            | Self::Other { unknown, .. } => {
                writer.write_all(&[self.id()])?;
                writer.write_all(unknown)?;
            }
        }

        Ok(())
    }
}

#[test]
#[ignore] // slow in debug mode
fn argon2() {
    // test vectors from draft-ietf-openpgp-crypto-refresh

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
    // https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-sample-messages-encrypted-u
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
        let (msg, _header) =
            Message::from_armor_single(std::fs::File::open(filename).expect("failed to open"))
                .expect("failed to load msg");

        let decrypted = msg
            .decrypt_with_password(|| "password".to_string())
            .expect("decrypt argon2 skesk");

        let Message::Literal(data) = decrypted else {
            panic!("expected literal data")
        };

        assert_eq!(data.data(), b"Hello, world!");
    }
}

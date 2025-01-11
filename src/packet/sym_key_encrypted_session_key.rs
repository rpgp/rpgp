use std::io;

use byteorder::WriteBytesExt;
use bytes::{Buf, Bytes};
use log::debug;
use rand::{CryptoRng, Rng};
use sha2::Sha256;

use crate::crypto::aead::AeadAlgorithm;
use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::errors::{Error, Result};
use crate::packet::PacketTrait;
use crate::parsing::BufParsing;
use crate::ser::Serialize;
use crate::types::{SkeskVersion, StringToKey, Tag, Version};
use crate::PlainSessionKey;

#[cfg(test)]
use proptest::prelude::*;

/// Symmetric-Key Encrypted Session Key Packet
/// <https://www.rfc-editor.org/rfc/rfc9580.html#name-symmetric-key-encrypted-ses>
#[derive(derive_more::Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum SymKeyEncryptedSessionKey {
    V4 {
        packet_version: Version,
        sym_algorithm: SymmetricKeyAlgorithm,
        s2k: StringToKey,
        #[debug("{}", hex::encode(encrypted_key))]
        #[cfg_attr(test, proptest(strategy = "any::<Vec<u8>>().prop_map(Into::into)"))]
        encrypted_key: Bytes,
    },
    V5 {
        packet_version: Version,
        sym_algorithm: SymmetricKeyAlgorithm,
        s2k: StringToKey,
        aead: AeadProps,
        #[debug("{}", hex::encode(encrypted_key))]
        #[cfg_attr(test, proptest(strategy = "any::<Vec<u8>>().prop_map(Into::into)"))]
        encrypted_key: Bytes,
    },
    V6 {
        packet_version: Version,
        sym_algorithm: SymmetricKeyAlgorithm,
        s2k: StringToKey,
        aead: AeadProps,
        #[debug("{}", hex::encode(encrypted_key))]
        #[cfg_attr(test, proptest(strategy = "any::<Vec<u8>>().prop_map(Into::into)"))]
        encrypted_key: Bytes,
    },
}

#[derive(derive_more::Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum AeadProps {
    Eax {
        #[debug("{}", hex::encode(iv))]
        iv: [u8; 16],
        #[debug("{}", hex::encode(auth_tag))]
        auth_tag: [u8; 16],
    },
    Ocb {
        #[debug("{}", hex::encode(iv))]
        iv: [u8; 15],
        #[debug("{}", hex::encode(auth_tag))]
        auth_tag: [u8; 16],
    },
    Gcm {
        #[debug("{}", hex::encode(iv))]
        iv: [u8; 12],
        #[debug("{}", hex::encode(auth_tag))]
        auth_tag: [u8; 16],
    },
}

impl From<&AeadProps> for AeadAlgorithm {
    fn from(value: &AeadProps) -> Self {
        match value {
            AeadProps::Eax { .. } => AeadAlgorithm::Eax,
            AeadProps::Gcm { .. } => AeadAlgorithm::Gcm,
            AeadProps::Ocb { .. } => AeadAlgorithm::Ocb,
        }
    }
}

impl AeadProps {
    fn iv(&self) -> &[u8] {
        match self {
            AeadProps::Eax { iv, .. } => iv,
            AeadProps::Ocb { iv, .. } => iv,
            AeadProps::Gcm { iv, .. } => iv,
        }
    }

    fn auth_tag(&self) -> &[u8] {
        match self {
            AeadProps::Eax { auth_tag, .. } => auth_tag,
            AeadProps::Ocb { auth_tag, .. } => auth_tag,
            AeadProps::Gcm { auth_tag, .. } => auth_tag,
        }
    }
}

impl SymKeyEncryptedSessionKey {
    /// Parses a `SymKeyEncryptedSessionKey` packet from the given buffer.
    pub fn from_buf<B: Buf>(packet_version: Version, mut i: B) -> Result<Self> {
        let version = i.read_u8()?;
        match version {
            4 => parse_v4(packet_version, i),
            5 => parse_v5(packet_version, i),
            6 => parse_v6(packet_version, i),
            _ => unsupported_err!("SKESK version {}", version),
        }
    }

    pub fn sym_algorithm(&self) -> SymmetricKeyAlgorithm {
        match self {
            Self::V4 {
                ref sym_algorithm, ..
            } => *sym_algorithm,
            Self::V5 {
                ref sym_algorithm, ..
            } => *sym_algorithm,
            Self::V6 {
                ref sym_algorithm, ..
            } => *sym_algorithm,
        }
    }

    pub fn s2k(&self) -> &StringToKey {
        match self {
            Self::V4 { ref s2k, .. } => s2k,
            Self::V5 { ref s2k, .. } => s2k,
            Self::V6 { ref s2k, .. } => s2k,
        }
    }

    pub fn version(&self) -> SkeskVersion {
        // TODO: use enum
        match self {
            Self::V4 { .. } => SkeskVersion::V4,
            Self::V5 { .. } => SkeskVersion::Other(5),
            Self::V6 { .. } => SkeskVersion::V6,
        }
    }

    pub fn decrypt(&self, key: &[u8]) -> Result<PlainSessionKey> {
        debug!("decrypt session key {:?}", self.version());

        let mut decrypted_key = self.encrypted_key().to_vec();

        match self {
            Self::V4 { sym_algorithm, .. } => {
                let iv = vec![0u8; sym_algorithm.block_size()];
                self.sym_algorithm()
                    .decrypt_with_iv_regular(key, &iv, &mut decrypted_key)?;

                let sym_alg = SymmetricKeyAlgorithm::from(decrypted_key[0]);
                Ok(PlainSessionKey::V3_4 {
                    key: decrypted_key[1..].to_vec(),
                    sym_alg,
                })
            }
            Self::V5 {
                sym_algorithm,
                aead,
                ..
            } => {
                // Initial key material is the s2k derived key.
                let ikm = key;
                // No salt is used
                let salt = None;
                let alg = AeadAlgorithm::from(aead);

                let info = [
                    Tag::SymKeyEncryptedSessionKey.encode(), // packet type
                    0x05,                                    // version
                    (*sym_algorithm).into(),
                    alg.into(),
                ];

                let hk = hkdf::Hkdf::<Sha256>::new(salt, ikm);
                let mut okm = [0u8; 42];
                hk.expand(&info, &mut okm).expect("42");

                // AEAD decrypt
                alg.decrypt_in_place(
                    sym_algorithm,
                    &okm,
                    aead.iv(),
                    &info,
                    aead.auth_tag(),
                    &mut decrypted_key,
                )?;

                Ok(PlainSessionKey::V5 { key: decrypted_key })
            }
            Self::V6 {
                sym_algorithm,
                aead,
                ..
            } => {
                // Initial key material is the s2k derived key.
                let ikm = key;
                // No salt is used
                let salt = None;
                let alg = AeadAlgorithm::from(aead);

                let info = [
                    Tag::SymKeyEncryptedSessionKey.encode(), // packet type
                    0x06,                                    // version
                    (*sym_algorithm).into(),
                    alg.into(),
                ];

                let hk = hkdf::Hkdf::<Sha256>::new(salt, ikm);
                let mut okm = [0u8; 42];
                hk.expand(&info, &mut okm).expect("42");

                // AEAD decrypt
                alg.decrypt_in_place(
                    sym_algorithm,
                    &okm,
                    aead.iv(),
                    &info,
                    aead.auth_tag(),
                    &mut decrypted_key,
                )?;

                Ok(PlainSessionKey::V6 { key: decrypted_key })
            }
        }
    }

    pub fn encrypted_key(&self) -> &[u8] {
        match self {
            Self::V4 {
                ref encrypted_key, ..
            } => encrypted_key,
            Self::V5 {
                ref encrypted_key, ..
            } => encrypted_key,
            Self::V6 {
                ref encrypted_key, ..
            } => encrypted_key,
        }
    }

    /// Encrypt a session key to a password as a Version 4 Symmetric Key Encrypted Session Key Packet
    ///
    /// See <https://www.rfc-editor.org/rfc/rfc9580.html#name-version-4-symmetric-key-enc>
    pub fn encrypt_v4<F>(
        msg_pw: F,
        session_key: &[u8],
        s2k: StringToKey,
        alg: SymmetricKeyAlgorithm,
    ) -> Result<Self>
    where
        F: FnOnce() -> String + Clone,
    {
        ensure!(
            s2k.uses_salt(),
            "Can not use an s2k algorithm without a salt: {:?}",
            s2k
        );

        // Implementations MUST NOT generate packets using MD5, SHA-1, or RIPEMD-160 as a hash function in an S2K KDF.
        // (See https://www.rfc-editor.org/rfc/rfc9580.html#section-9.5-3)
        ensure!(
            !s2k.known_weak_hash_algo(),
            "Weak hash algorithm in S2K not allowed for v6 {:?}",
            s2k
        );

        let key = s2k.derive_key(&msg_pw(), alg.key_size())?;

        let mut private_key = Vec::with_capacity(session_key.len());
        private_key.push(u8::from(alg));
        private_key.extend(session_key);

        let iv = vec![0u8; alg.block_size()];
        let mut encrypted_key = private_key.to_vec();
        alg.encrypt_with_iv_regular(&key, &iv, &mut encrypted_key)?;

        Ok(SymKeyEncryptedSessionKey::V4 {
            packet_version: Default::default(),
            s2k,
            sym_algorithm: alg,
            encrypted_key: encrypted_key.into(),
        })
    }

    /// Encrypt a session key to a password as a Version 6 Symmetric Key Encrypted Session Key Packet
    ///
    /// See <https://www.rfc-editor.org/rfc/rfc9580.html#name-version-6-symmetric-key-enc>
    pub fn encrypt_v6<F, R: CryptoRng + Rng>(
        mut rng: R,
        msg_pw: F,
        session_key: &[u8],
        s2k: StringToKey,
        sym_algorithm: SymmetricKeyAlgorithm,
        aead: AeadAlgorithm,
    ) -> Result<Self>
    where
        F: FnOnce() -> String + Clone,
    {
        ensure!(
            s2k.uses_salt(),
            "Can not use an s2k algorithm without a salt: {:?}",
            s2k
        );

        // Implementations MUST NOT generate packets using MD5, SHA-1, or RIPEMD-160 as a hash function in an S2K KDF.
        // (See https://www.rfc-editor.org/rfc/rfc9580.html#section-9.5-3)
        ensure!(
            !s2k.known_weak_hash_algo(),
            "Weak hash algorithm in S2K not allowed for v6 {:?}",
            s2k
        );

        // Initial key material is the s2k derived key.
        let ikm = s2k.derive_key(&msg_pw(), sym_algorithm.key_size())?;
        // No salt is used
        let salt = None;

        let info = [
            Tag::SymKeyEncryptedSessionKey.encode(), // packet type
            0x06,                                    // version
            sym_algorithm.into(),
            aead.into(),
        ];

        let hk = hkdf::Hkdf::<Sha256>::new(salt, &ikm);
        let mut okm = [0u8; 42];
        hk.expand(&info, &mut okm).expect("42");

        let mut iv = vec![0; aead.iv_size()];
        rng.fill_bytes(&mut iv);

        // AEAD encrypt
        let mut encrypted_key = session_key.to_vec();
        let auth_tag =
            aead.encrypt_in_place(&sym_algorithm, &okm, &iv, &info, &mut encrypted_key)?;

        let aead = match aead {
            AeadAlgorithm::Eax => AeadProps::Eax {
                iv: iv.try_into().expect("checked"),
                auth_tag: auth_tag.try_into().expect("checked"),
            },
            AeadAlgorithm::Ocb => AeadProps::Ocb {
                iv: iv.try_into().expect("checked"),
                auth_tag: auth_tag.try_into().expect("checked"),
            },
            AeadAlgorithm::Gcm => AeadProps::Gcm {
                iv: iv.try_into().expect("checked"),
                auth_tag: auth_tag.try_into().expect("checked"),
            },
            _ => {
                unimplemented_err!("AEAD {:?}", aead);
            }
        };

        Ok(SymKeyEncryptedSessionKey::V6 {
            packet_version: Default::default(),
            sym_algorithm,
            s2k,
            aead,
            encrypted_key: encrypted_key.into(),
        })
    }
}

fn parse_v4<B: Buf>(packet_version: Version, mut i: B) -> Result<SymKeyEncryptedSessionKey> {
    let sym_alg = i.read_u8().map(SymmetricKeyAlgorithm::from)?;
    let s2k = StringToKey::from_buf(&mut i)?;

    Ok(SymKeyEncryptedSessionKey::V4 {
        packet_version,
        sym_algorithm: sym_alg,
        s2k,
        encrypted_key: i.rest(),
    })
}

fn parse_v5<B: Buf>(packet_version: Version, mut i: B) -> Result<SymKeyEncryptedSessionKey> {
    let _count = i.read_u8()?;
    let sym_alg = i.read_u8().map(SymmetricKeyAlgorithm::from)?;
    let aead = i.read_u8().map(AeadAlgorithm::from)?;
    let s2k_len = i.read_u8()?;
    let s2k_data = i.read_take(s2k_len.into())?;
    let s2k = StringToKey::from_buf(s2k_data)?;
    let iv = i.read_take(aead.iv_size())?;
    let l = i.remaining();
    let aead_tag_size = aead.tag_size().unwrap_or_default();

    if l < aead_tag_size {
        return Err(Error::InvalidInput);
    }
    let esk_size = l - aead_tag_size;
    let esk = i.read_take(esk_size)?;
    let auth_tag = i.read_take(aead_tag_size)?;

    let aead = match aead {
        AeadAlgorithm::Eax => AeadProps::Eax {
            iv: iv.as_ref().try_into().expect("checked"),
            auth_tag: auth_tag.as_ref().try_into().expect("checked"),
        },
        AeadAlgorithm::Ocb => AeadProps::Ocb {
            iv: iv.as_ref().try_into().expect("checked"),
            auth_tag: auth_tag.as_ref().try_into().expect("checked"),
        },
        AeadAlgorithm::Gcm => AeadProps::Gcm {
            iv: iv.as_ref().try_into().expect("checked"),
            auth_tag: auth_tag.as_ref().try_into().expect("checked"),
        },
        _ => unsupported_err!("aead algorithm for v5: {:?}", aead),
    };

    Ok(SymKeyEncryptedSessionKey::V5 {
        packet_version,
        sym_algorithm: sym_alg,
        aead,
        s2k,
        encrypted_key: esk,
    })
}

fn parse_v6<B: Buf>(packet_version: Version, mut i: B) -> Result<SymKeyEncryptedSessionKey> {
    let _count = i.read_u8()?;
    let sym_alg = i.read_u8().map(SymmetricKeyAlgorithm::from)?;
    let aead = i.read_u8().map(AeadAlgorithm::from)?;
    let s2k_len = i.read_u8()?;
    let s2k_data = i.read_take(s2k_len.into())?;
    let s2k = StringToKey::from_buf(s2k_data)?;
    let iv = i.read_take(aead.iv_size())?;
    let l = i.remaining();
    let aead_tag_size = aead.tag_size().unwrap_or_default();
    if l < aead_tag_size {
        return Err(Error::InvalidInput);
    }
    let esk = i.read_take(l - aead_tag_size)?;
    let auth_tag = i.read_take(aead_tag_size)?;

    let aead = match aead {
        AeadAlgorithm::Eax => AeadProps::Eax {
            iv: iv.as_ref().try_into().expect("checked"),
            auth_tag: auth_tag.as_ref().try_into().expect("checked"),
        },
        AeadAlgorithm::Ocb => AeadProps::Ocb {
            iv: iv.as_ref().try_into().expect("checked"),
            auth_tag: auth_tag.as_ref().try_into().expect("checked"),
        },
        AeadAlgorithm::Gcm => AeadProps::Gcm {
            iv: iv.as_ref().try_into().expect("checked"),
            auth_tag: auth_tag.as_ref().try_into().expect("checked"),
        },
        _ => unsupported_err!("aead algorithm for v6: {:?}", aead),
    };

    Ok(SymKeyEncryptedSessionKey::V6 {
        packet_version,
        sym_algorithm: sym_alg,
        aead,
        s2k,
        encrypted_key: esk,
    })
}

impl Serialize for SymKeyEncryptedSessionKey {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        match &self {
            SymKeyEncryptedSessionKey::V4 {
                packet_version: _,
                sym_algorithm,
                s2k,
                encrypted_key,
            } => {
                writer.write_u8(0x04)?;
                writer.write_u8((*sym_algorithm).into())?;
                s2k.to_writer(writer)?;
                writer.write_all(encrypted_key)?;
            }
            SymKeyEncryptedSessionKey::V5 {
                packet_version: _,
                sym_algorithm,
                s2k,
                aead,
                encrypted_key,
            } => {
                writer.write_u8(0x05)?;
                let s2k_len = s2k.write_len();
                let first_len = 1 + 1 + 1 + s2k_len + aead.iv().len();

                // length
                writer.write_u8(first_len.try_into()?)?;

                writer.write_u8((*sym_algorithm).into())?;
                writer.write_u8(AeadAlgorithm::from(aead).into())?;
                writer.write_u8(s2k_len.try_into()?)?;
                s2k.to_writer(writer)?;
                writer.write_all(aead.iv())?;

                writer.write_all(encrypted_key)?;
                writer.write_all(aead.auth_tag())?;
            }
            SymKeyEncryptedSessionKey::V6 {
                packet_version: _,
                sym_algorithm,
                s2k,
                aead,
                encrypted_key,
            } => {
                writer.write_u8(0x06)?;

                let s2k_len = s2k.write_len();
                let first_len = 1 + 1 + 1 + s2k_len + aead.iv().len();

                // length
                writer.write_u8(first_len.try_into()?)?;

                writer.write_u8((*sym_algorithm).into())?;
                writer.write_u8(AeadAlgorithm::from(aead).into())?;
                writer.write_u8(s2k_len.try_into()?)?;
                s2k.to_writer(writer)?;
                writer.write_all(aead.iv())?;

                writer.write_all(encrypted_key)?;
                writer.write_all(aead.auth_tag())?;
            }
        }
        Ok(())
    }

    fn write_len(&self) -> usize {
        let mut sum = 0;
        match self {
            SymKeyEncryptedSessionKey::V4 {
                s2k, encrypted_key, ..
            } => {
                sum += 1 + 1;
                sum += s2k.write_len();
                sum += encrypted_key.len();
            }
            SymKeyEncryptedSessionKey::V5 {
                s2k,
                encrypted_key,
                aead,
                ..
            } => {
                sum += 1;
                sum += 1 + 1;

                sum += s2k.write_len();
                sum += 1;
                sum += aead.iv().len();

                sum += 1;
                sum += encrypted_key.len();
                sum += aead.auth_tag().len();
            }
            SymKeyEncryptedSessionKey::V6 {
                s2k,
                aead,
                encrypted_key,
                ..
            } => {
                sum += 1;
                sum += 1 + 1;

                sum += s2k.write_len();
                sum += 1;
                sum += aead.iv().len();

                sum += 1;
                sum += encrypted_key.len();
                sum += aead.auth_tag().len();
            }
        }
        sum
    }
}

impl PacketTrait for SymKeyEncryptedSessionKey {
    fn packet_version(&self) -> Version {
        match self {
            SymKeyEncryptedSessionKey::V4 { packet_version, .. } => *packet_version,
            SymKeyEncryptedSessionKey::V5 { packet_version, .. } => *packet_version,
            SymKeyEncryptedSessionKey::V6 { packet_version, .. } => *packet_version,
        }
    }

    fn tag(&self) -> Tag {
        Tag::SymKeyEncryptedSessionKey
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    proptest! {
        #[test]
        fn write_len(packet: SymKeyEncryptedSessionKey) {
            let mut buf = Vec::new();
            packet.to_writer(&mut buf).unwrap();
            assert_eq!(buf.len(), packet.write_len());
        }


        #[test]
        fn packet_roundtrip(packet: SymKeyEncryptedSessionKey) {
            let mut buf = Vec::new();
            packet.to_writer(&mut buf).unwrap();
            let new_packet = SymKeyEncryptedSessionKey::from_buf(packet.packet_version(), &mut &buf[..]).unwrap();
            assert_eq!(packet, new_packet);
        }
    }
}

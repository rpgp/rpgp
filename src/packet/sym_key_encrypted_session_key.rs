use std::io;

use nom::bytes::streaming::take;
use nom::combinator::map_res;
use nom::number::streaming::be_u8;
use sha2::Sha256;

use crate::crypto::aead::AeadAlgorithm;
use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::errors::{Error, IResult, Result};
use crate::packet::PacketTrait;
use crate::ser::Serialize;
use crate::types::{s2k_parser, StringToKey, Tag, Version};
use crate::util::rest_len;

/// Symmetric-Key Encrypted Session Key Packet
/// https://tools.ietf.org/html/rfc4880.html#section-5.3
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SymKeyEncryptedSessionKey {
    V4 {
        packet_version: Version,
        sym_algorithm: SymmetricKeyAlgorithm,
        s2k: StringToKey,
        encrypted_key: Option<Vec<u8>>,
    },
    V5 {
        packet_version: Version,
        sym_algorithm: SymmetricKeyAlgorithm,
        s2k: StringToKey,
        aead: AeadAlgorithm,
        iv: Vec<u8>,
        auth_tag: Vec<u8>,
        encrypted_key: Vec<u8>,
    },
    V6 {
        packet_version: Version,
        sym_algorithm: SymmetricKeyAlgorithm,
        s2k: StringToKey,
        aead: AeadAlgorithm,
        iv: Vec<u8>,
        auth_tag: Vec<u8>,
        encrypted_key: Vec<u8>,
    },
}

impl SymKeyEncryptedSessionKey {
    /// Parses a `SymKeyEncryptedSessionKey` packet from the given slice.
    pub fn from_slice(version: Version, input: &[u8]) -> Result<Self> {
        let (_, pk) = parse(version)(input)?;

        Ok(pk)
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

    pub fn decrypt(&self, key: &[u8]) -> Result<Vec<u8>> {
        let mut decrypted_key = self.encrypted_key().map(|v| v.to_vec()).unwrap_or_default();

        match self {
            Self::V4 { sym_algorithm, .. } => {
                let iv = vec![0u8; sym_algorithm.block_size()];
                self.sym_algorithm()
                    .decrypt_with_iv_regular(key, &iv, &mut decrypted_key)?
            }
            Self::V5 {
                iv,
                sym_algorithm,
                aead,
                auth_tag,
                ..
            } => {
                // Initial key material is the s2k derived key.
                let ikm = key;
                // No salt is used
                let salt = None;

                let info = [
                    Tag::SymKeyEncryptedSessionKey.encode(), // packet type
                    0x05,                                    // version
                    (*sym_algorithm).into(),
                    (*aead).into(),
                ];

                let hk = hkdf::Hkdf::<Sha256>::new(salt, ikm);
                let mut okm = [0u8; 42];
                hk.expand(&info, &mut okm).expect("42");
                debug!("info: {} - hkdf: {}", hex::encode(&info), hex::encode(&okm));
                debug!("nonce: {}", hex::encode(iv));

                // AEAD decrypt
                aead.decrypt_in_place(
                    sym_algorithm,
                    &okm,
                    iv,
                    &info,
                    auth_tag,
                    &mut decrypted_key,
                )?;
            }
            Self::V6 { iv, .. } => {
                todo!()
            }
        }

        debug!("decrypted_key: {}", hex::encode(&decrypted_key));
        Ok(decrypted_key)
    }

    pub fn encrypted_key(&self) -> Option<&[u8]> {
        match self {
            Self::V4 {
                ref encrypted_key, ..
            } => encrypted_key.as_ref().map(|s| &s[..]),
            Self::V5 {
                ref encrypted_key, ..
            } => Some(&encrypted_key),
            Self::V6 {
                ref encrypted_key, ..
            } => Some(&encrypted_key),
        }
    }

    pub fn encrypt<F>(
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
            encrypted_key: Some(encrypted_key),
        })
    }
}

fn parse(packet_version: Version) -> impl Fn(&[u8]) -> IResult<&[u8], SymKeyEncryptedSessionKey> {
    move |i: &[u8]| {
        let (i, version) = be_u8(i)?;
        match version {
            4 => parse_v4(packet_version)(i),
            5 => parse_v5(packet_version)(i),
            6 => parse_v6(packet_version)(i),
            _ => Err(nom::Err::Error(Error::Unsupported(format!(
                "Unsupported SKESK version {}",
                version
            )))),
        }
    }
}

fn parse_v4(
    packet_version: Version,
) -> impl Fn(&[u8]) -> IResult<&[u8], SymKeyEncryptedSessionKey> {
    move |i: &[u8]| {
        let (i, sym_alg) = map_res(be_u8, SymmetricKeyAlgorithm::try_from)(i)?;
        let (i, s2k) = s2k_parser(i)?;

        Ok((
            &[][..],
            SymKeyEncryptedSessionKey::V4 {
                packet_version,
                sym_algorithm: sym_alg,
                s2k,
                encrypted_key: i.is_empty().then(|| i.to_vec()),
            },
        ))
    }
}

fn parse_v5(
    packet_version: Version,
) -> impl Fn(&[u8]) -> IResult<&[u8], SymKeyEncryptedSessionKey> {
    move |i: &[u8]| {
        let (i, _count) = be_u8(i)?;
        let (i, sym_alg) = map_res(be_u8, SymmetricKeyAlgorithm::try_from)(i)?;
        let (i, aead) = map_res(be_u8, AeadAlgorithm::try_from)(i)?;
        let (i, _s2k_len) = be_u8(i)?;
        let (i, s2k) = s2k_parser(i)?;
        let (i, iv) = take(aead.iv_size())(i)?;
        let (i, l) = rest_len(i)?;
        let (i, esk) = take(l - aead.tag_size())(i)?;
        let (i, auth_tag) = take(aead.tag_size())(i)?;

        Ok((
            i,
            SymKeyEncryptedSessionKey::V5 {
                packet_version,
                sym_algorithm: sym_alg,
                aead,
                iv: iv.to_vec(),
                auth_tag: auth_tag.to_vec(),
                s2k,
                encrypted_key: esk.to_vec(),
            },
        ))
    }
}

fn parse_v6(
    packet_version: Version,
) -> impl Fn(&[u8]) -> IResult<&[u8], SymKeyEncryptedSessionKey> {
    move |i: &[u8]| {
        let (i, _count) = be_u8(i)?;
        let (i, sym_alg) = map_res(be_u8, SymmetricKeyAlgorithm::try_from)(i)?;
        let (i, aead) = map_res(be_u8, AeadAlgorithm::try_from)(i)?;
        let (i, _s2k_len) = be_u8(i)?;
        let (i, s2k) = s2k_parser(i)?;
        let (i, iv) = take(aead.iv_size())(i)?;
        let (i, l) = rest_len(i)?;
        let (i, esk) = take(l - aead.tag_size())(i)?;
        let (i, auth_tag) = take(aead.tag_size())(i)?;

        Ok((
            i,
            SymKeyEncryptedSessionKey::V6 {
                packet_version,
                sym_algorithm: sym_alg,
                aead,
                iv: iv.to_vec(),
                auth_tag: auth_tag.to_vec(),
                s2k,
                encrypted_key: esk.to_vec(),
            },
        ))
    }
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
                writer.write_all(&[0x04, u8::from(*sym_algorithm)])?;
                s2k.to_writer(writer)?;
                if let Some(ref key) = encrypted_key {
                    writer.write_all(key)?;
                }
            }
            SymKeyEncryptedSessionKey::V5 {
                packet_version: _,
                sym_algorithm,
                s2k,
                aead,
                iv,
                auth_tag,
                encrypted_key,
            } => {
                writer.write_all(&[0x05])?;
                let mut first_buf = vec![u8::from(*sym_algorithm), u8::from(*aead)];

                let mut buf = Vec::new();
                s2k.to_writer(&mut buf)?;
                first_buf.push(buf.len() as u8);
                first_buf.extend(buf);
                first_buf.extend_from_slice(&iv);

                writer.write_all(&[first_buf.len() as u8])?;
                writer.write_all(&first_buf)?;

                writer.write_all(encrypted_key)?;
                writer.write_all(auth_tag)?;
            }
            SymKeyEncryptedSessionKey::V6 {
                packet_version: _,
                sym_algorithm,
                s2k,
                aead,
                iv,
                auth_tag,
                encrypted_key,
            } => {
                writer.write_all(&[0x06])?;
                let mut first_buf = vec![u8::from(*sym_algorithm), u8::from(*aead)];

                let mut buf = Vec::new();
                s2k.to_writer(&mut buf)?;
                first_buf.push(buf.len() as u8);
                first_buf.extend(buf);
                first_buf.extend_from_slice(&iv);

                writer.write_all(&[first_buf.len() as u8])?;
                writer.write_all(&first_buf)?;

                writer.write_all(encrypted_key)?;
                writer.write_all(auth_tag)?;
            }
        }
        Ok(())
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

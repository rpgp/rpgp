use std::io::{self, Read};

use byteorder::WriteBytesExt;
use bytes::{Buf, Bytes, BytesMut};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use rand::{CryptoRng, Rng};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::crypto::aead::AeadAlgorithm;
use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::errors::{Error, Result};
use crate::packet::{PacketHeader, PacketTrait};
use crate::parsing::BufParsing;
use crate::ser::Serialize;
use crate::types::Tag;
use crate::util::fill_buffer;

/// Symmetrically Encrypted Integrity Protected Data Packet
/// <https://www.rfc-editor.org/rfc/rfc9580.html#name-symmetrically-encrypted-and>
#[derive(Clone, PartialEq, Eq, derive_more::Debug)]
pub struct SymEncryptedProtectedData {
    packet_header: PacketHeader,
    config: Config,
    #[debug("{}", hex::encode(data))]
    data: Bytes,
}

#[derive(Clone, PartialEq, Eq, derive_more::Debug)]
pub enum Config {
    V1,
    V2 {
        sym_alg: SymmetricKeyAlgorithm,
        aead: AeadAlgorithm,
        chunk_size: ChunkSize,
        #[debug("{}", hex::encode(salt))]
        salt: [u8; 32],
    },
}

/// Allowed chunk sizes.
/// The range is from 64B to 4 MiB.
///
/// Ref <https://www.rfc-editor.org/rfc/rfc9580.html#name-version-2-symmetrically-enc>
#[derive(
    Default, IntoPrimitive, Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone, TryFromPrimitive,
)]
#[repr(u8)]
pub enum ChunkSize {
    C64B = 0,
    C128B = 1,
    C256B = 2,
    C512B = 3,
    C1KiB = 4,
    C2KiB = 5,
    #[default]
    C4KiB = 6,
    C8KiB = 7,
    C16KiB = 8,
    C32KiB = 9,
    C64KiB = 10,
    C128KiB = 11,
    C256KiB = 12,
    C512KiB = 13,
    C1MiB = 14,
    C2MiB = 15,
    C4MiB = 16,
}

impl ChunkSize {
    /// Returns the number of bytes for this chunk size.
    pub const fn as_byte_size(self) -> u32 {
        1u32 << ((self as u32) + 6)
    }
}

impl SymEncryptedProtectedData {
    /// Parses a `SymEncryptedProtectedData` packet from the given buf.
    pub fn from_buf<B: Buf>(packet_header: PacketHeader, mut data: B) -> Result<Self> {
        ensure_eq!(
            packet_header.tag(),
            Tag::SymEncryptedProtectedData,
            "invalid tag"
        );

        let version = data.read_u8()?;
        let config = match version {
            0x01 => Config::V1,
            0x02 => {
                let sym_alg = data.read_u8().map(SymmetricKeyAlgorithm::from)?;
                let aead = data.read_u8().map(AeadAlgorithm::from)?;
                let chunk_size = data
                    .read_u8()?
                    .try_into()
                    .map_err(|_| Error::InvalidInput)?;
                let salt = data.read_array::<32>()?;

                Config::V2 {
                    sym_alg,
                    aead,
                    chunk_size,
                    salt,
                }
            }
            _ => {
                return Err(format_err!(
                    "unknown SymEncryptedProtectedData version {}",
                    version
                ))
            }
        };
        let data = data.rest();

        Ok(SymEncryptedProtectedData {
            packet_header,
            config,
            data,
        })
    }

    /// Encrypts the data using the given symmetric key.
    pub fn encrypt_seipdv1<R: CryptoRng + Rng>(
        rng: R,
        alg: SymmetricKeyAlgorithm,
        key: &[u8],
        plaintext: &[u8],
    ) -> Result<Self> {
        let data: Bytes = alg.encrypt_protected(rng, key, plaintext)?.into();
        let config = Config::V1;
        let len = config.write_len() + data.len();
        let packet_header = PacketHeader::new_fixed(Tag::SymEncryptedProtectedData, len);

        Ok(SymEncryptedProtectedData {
            packet_header,
            config,
            data,
        })
    }

    /// Encrypts the data using the given symmetric key.
    pub fn encrypt_seipdv2<R: CryptoRng + Rng>(
        mut rng: R,
        sym_alg: SymmetricKeyAlgorithm,
        aead: AeadAlgorithm,
        chunk_size: ChunkSize,
        session_key: &[u8],
        mut plaintext: &[u8],
    ) -> Result<Self> {
        // Generate new salt for this seipd packet.
        let mut salt = [0u8; 32];
        rng.fill(&mut salt[..]);

        let mut encryptor = StreamEncryptor::new(
            sym_alg,
            aead,
            chunk_size,
            session_key,
            &salt,
            &mut plaintext,
        )?;

        let mut out = Vec::new();
        encryptor.read_to_end(&mut out)?;

        let config = Config::V2 {
            sym_alg,
            aead,
            chunk_size,
            salt,
        };
        let data: Bytes = out.into();
        let len = config.write_len() + data.len();
        let packet_header = PacketHeader::new_fixed(Tag::SymEncryptedProtectedData, len);

        Ok(SymEncryptedProtectedData {
            packet_header,
            config,
            data,
        })
    }

    /// Encrypts the data using the given symmetric key.
    pub fn encrypt_seipdv2_stream<R: io::Read>(
        sym_alg: SymmetricKeyAlgorithm,
        aead: AeadAlgorithm,
        chunk_size: ChunkSize,
        session_key: &[u8],
        salt: [u8; 32],
        source: R,
    ) -> Result<StreamEncryptor<R>> {
        let encryptor =
            StreamEncryptor::new(sym_alg, aead, chunk_size, session_key, &salt, source)?;

        Ok(encryptor)
    }

    pub fn data(&self) -> &Bytes {
        &self.data
    }

    pub fn version(&self) -> usize {
        match self.config {
            Config::V1 => 1,
            Config::V2 { .. } => 2,
        }
    }

    /// Returns the configuration for this packet.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Decrypts the inner data, returning the result.
    pub fn decrypt(
        &self,
        session_key: &[u8],
        sym_alg: Option<SymmetricKeyAlgorithm>,
    ) -> Result<Vec<u8>> {
        match &self.config {
            Config::V1 => {
                let sym_alg = sym_alg.expect("v1");
                let mut prefix = self.data[..sym_alg.cfb_prefix_size()].to_vec();
                let mut ciphertext = self.data[sym_alg.cfb_prefix_size()..].to_vec();
                sym_alg.decrypt_protected(session_key, &mut prefix, &mut ciphertext)?;
                Ok(ciphertext)
            }
            Config::V2 {
                sym_alg,
                aead,
                chunk_size,
                salt,
            } => {
                ensure_eq!(
                    session_key.len(),
                    sym_alg.key_size(),
                    "Unexpected session key length for {:?}",
                    sym_alg
                );

                // Initial key material is the session key.
                let ikm = session_key;

                let chunk_size_expanded: usize = chunk_size.as_byte_size().try_into()?;

                let (info, message_key, mut nonce) =
                    aead_setup(*sym_alg, *aead, *chunk_size, &salt[..], ikm)?;

                let mut data: BytesMut = self.data.clone().into();

                // There are n chunks, n auth tags + 1 final auth tag
                let Some(aead_tag_size) = aead.tag_size() else {
                    unsupported_err!("AEAD mode: {:?}", aead);
                };
                if data.len() < aead_tag_size {
                    return Err(Error::InvalidInput);
                }
                let offset = data.len() - aead_tag_size;
                let mut final_auth_tag = data.split_off(offset);

                // Calculate output size (for more efficient vector allocation):
                // - number of chunks: main_chunks length divided by (chunk size + tag size), rounded up to the next integer
                let Some(aead_tag_size) = aead.tag_size() else {
                    unsupported_err!("AEAD mode: {:?}", aead);
                };
                let chunk_and_tag_len = chunk_size_expanded + aead_tag_size;
                let main_len = data.len();
                let num_chunks = main_len.div_ceil(chunk_and_tag_len);
                // - total output size: main_chunks length - size of one authentication tag per chunk
                let out_len = main_len - num_chunks * aead_tag_size;

                let mut out = Vec::with_capacity(out_len);

                let mut chunk_index: u64 = 0;
                let full_chunk_size = chunk_size_expanded + aead_tag_size;
                while !data.is_empty() {
                    let size = full_chunk_size.min(data.len());
                    let mut chunk = data.split_to(size);

                    aead.decrypt_in_place(sym_alg, &message_key, &nonce, &info, &mut chunk)?;
                    out.extend_from_slice(&chunk);

                    // Update nonce to include the next chunk index
                    chunk_index += 1;
                    let l = nonce.len() - 8;
                    nonce[l..].copy_from_slice(&chunk_index.to_be_bytes());
                }

                // verify final auth tag

                // Associated data is extended with number of plaintext octets.
                let size = out.len() as u64;
                let mut final_info = info.to_vec();
                final_info.extend_from_slice(&size.to_be_bytes());

                // Update final nonce
                aead.decrypt_in_place(
                    sym_alg,
                    &message_key,
                    &nonce,
                    &final_info,
                    &mut final_auth_tag,
                )?;

                debug_assert_eq!(out.len(), out_len, "we pre-allocated the wrong output size");

                Ok(out)
            }
        }
    }
}

impl Serialize for Config {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            Config::V1 => {
                writer.write_u8(0x01)?;
            }
            Config::V2 {
                sym_alg,
                aead,
                chunk_size,
                salt,
            } => {
                writer.write_u8(0x02)?;
                writer.write_u8((*sym_alg).into())?;
                writer.write_u8((*aead).into())?;
                writer.write_u8((*chunk_size).into())?;
                writer.write_all(salt)?;
            }
        }
        Ok(())
    }

    fn write_len(&self) -> usize {
        match self {
            Config::V1 => 1,
            Config::V2 { salt, .. } => {
                let mut sum = 1 + 1 + 1 + 1;
                sum += salt.len();
                sum
            }
        }
    }
}
impl Serialize for SymEncryptedProtectedData {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        self.config.to_writer(writer)?;
        writer.write_all(&self.data)?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        let mut sum = self.config.write_len();
        sum += self.data.len();
        sum
    }
}

impl PacketTrait for SymEncryptedProtectedData {
    fn packet_header(&self) -> &PacketHeader {
        &self.packet_header
    }
}

/// Get (info, message_key, nonce) for the given parameters
#[allow(clippy::type_complexity)]
pub(crate) fn aead_setup(
    sym_alg: SymmetricKeyAlgorithm,
    aead: AeadAlgorithm,
    chunk_size: ChunkSize,
    salt: &[u8],
    ikm: &[u8],
) -> Result<([u8; 5], Zeroizing<Vec<u8>>, Vec<u8>)> {
    let info = [
        Tag::SymEncryptedProtectedData.encode(), // packet type
        0x02,                                    // version
        sym_alg.into(),
        aead.into(),
        chunk_size.into(),
    ];

    let hk = hkdf::Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = Zeroizing::new([0u8; 42]);
    hk.expand(&info, okm.as_mut_slice()).expect("42");

    let mut message_key = Zeroizing::new(vec![0; sym_alg.key_size()]);
    message_key.copy_from_slice(&okm.as_slice()[..sym_alg.key_size()]);

    let raw_iv_len = aead.nonce_size() - 8;
    let iv = &okm[sym_alg.key_size()..sym_alg.key_size() + raw_iv_len];
    let mut nonce = vec![0u8; aead.nonce_size()];
    nonce[..raw_iv_len].copy_from_slice(iv);

    Ok((info, message_key, nonce))
}

pub struct StreamEncryptor<R> {
    source: R,
    /// Indicates if we are done reading from the `source`.
    is_source_done: bool,
    /// Total number of bytes read from the source.
    bytes_read: usize,
    chunk_index: u64,
    buffer: BytesMut,
    info: [u8; 5],
    message_key: Zeroizing<Vec<u8>>,
    nonce: Vec<u8>,
    chunk_size_expanded: u32,
    aead: AeadAlgorithm,
    sym_alg: SymmetricKeyAlgorithm,
}

impl<R: io::Read> StreamEncryptor<R> {
    /// Encrypts the data using the given symmetric key.
    pub(crate) fn new(
        sym_alg: SymmetricKeyAlgorithm,
        aead: AeadAlgorithm,
        chunk_size: ChunkSize,
        session_key: &[u8],
        salt: &[u8; 32],
        source: R,
    ) -> Result<Self> {
        ensure_eq!(
            session_key.len(),
            sym_alg.key_size(),
            "Unexpected session key length for {:?}",
            sym_alg
        );

        let (info, message_key, nonce) =
            aead_setup(sym_alg, aead, chunk_size, &salt[..], session_key)?;
        let chunk_size_expanded = chunk_size.as_byte_size();

        let buffer = BytesMut::with_capacity(chunk_size_expanded as usize);

        Ok(StreamEncryptor {
            source,
            is_source_done: false,
            bytes_read: 0,
            chunk_index: 0,
            info,
            message_key,
            nonce,
            chunk_size_expanded,
            aead,
            sym_alg,
            buffer,
        })
    }

    /// Constructs the final auth tag
    fn create_final_auth_tag(&mut self) -> io::Result<()> {
        // Associated data is extended with number of plaintext octets.
        let mut final_info = self.info.to_vec();
        final_info.extend_from_slice(&self.bytes_read.to_be_bytes());

        // encrypts empty string
        self.buffer.clear();
        self.aead
            .encrypt_in_place(
                &self.sym_alg,
                &self.message_key,
                &self.nonce,
                &final_info,
                &mut self.buffer,
            )
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        Ok(())
    }

    fn fill_buffer(&mut self) -> io::Result<()> {
        self.buffer.resize(self.chunk_size_expanded as _, 0);
        let read = fill_buffer(
            &mut self.source,
            &mut self.buffer,
            Some(self.chunk_size_expanded as _),
        )?;
        self.bytes_read += read;
        if read == 0 {
            self.is_source_done = true;
            // time to write the final chunk
            self.create_final_auth_tag()?;

            return Ok(());
        }
        self.buffer.truncate(read);

        self.aead
            .encrypt_in_place(
                &self.sym_alg,
                &self.message_key,
                &self.nonce,
                &self.info,
                &mut self.buffer,
            )
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        // Update nonce to include the next chunk index
        self.chunk_index += 1;
        let l = self.nonce.len() - 8;
        self.nonce[l..].copy_from_slice(&self.chunk_index.to_be_bytes());

        Ok(())
    }
}

impl<R: io::Read> io::Read for StreamEncryptor<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.buffer.has_remaining() {
            if !self.is_source_done {
                // Still more to read and encrypt from the source.
                self.fill_buffer()?;
            } else {
                // The final chunk was written, we have nothing left to give.
                return Ok(0);
            }
        }

        let to_write = buf.len().min(self.buffer.remaining());
        self.buffer.copy_to_slice(&mut buf[..to_write]);

        Ok(to_write)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    use super::*;

    #[test]
    fn test_chunk_size() {
        assert_eq!(ChunkSize::default().as_byte_size(), 4 * 1024);
        assert_eq!(ChunkSize::C64B.as_byte_size(), 64);
    }

    #[test]
    fn test_aead_message_sizes() {
        // Test that AEAD encryption/decryption works for message sizes that span 0-2 chunks.

        let mut rng = ChaCha8Rng::from_seed([0u8; 32]);

        const SYM_ALG: SymmetricKeyAlgorithm = SymmetricKeyAlgorithm::AES128;

        let mut session_key = [0; 16];
        rng.fill_bytes(&mut session_key);

        // Iterate over message sizes from 0 bytes through all 1-chunk and 2-chunk lengths
        // (ending with two chunks of a full 64 bytes)
        for size in 0..=128 {
            let mut message = vec![0; size];
            rng.fill_bytes(&mut message);

            for aead in [AeadAlgorithm::Ocb, AeadAlgorithm::Eax, AeadAlgorithm::Gcm] {
                let enc = SymEncryptedProtectedData::encrypt_seipdv2(
                    &mut rng,
                    SYM_ALG,
                    aead,
                    ChunkSize::C64B,
                    &session_key,
                    &message,
                )
                .expect("encrypt");

                let dec = enc.decrypt(&session_key, Some(SYM_ALG)).expect("decrypt");
                assert_eq!(message, dec);

                // write test
                let mut buffer = Vec::new();
                enc.to_writer(&mut buffer).unwrap();
                assert_eq!(buffer.len(), enc.write_len());

                let back = SymEncryptedProtectedData::from_buf(enc.packet_header, &mut &buffer[..])
                    .unwrap();
                assert_eq!(enc, back);
            }
        }
    }
}

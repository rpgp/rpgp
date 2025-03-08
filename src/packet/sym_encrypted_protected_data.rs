use std::io::{self, BufRead, Read};

use byteorder::WriteBytesExt;
use bytes::{Bytes, BytesMut};
use rand::{CryptoRng, Rng};

use crate::crypto::aead::{aead_setup, AeadAlgorithm, ChunkSize, StreamEncryptor};
use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::errors::{InvalidInputSnafu, Result};
use crate::packet::{PacketHeader, PacketTrait};
use crate::parsing_reader::BufReadParsing;
use crate::ser::Serialize;
use crate::types::Tag;

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

impl Config {
    pub fn try_from_reader<R: BufRead>(mut data: R) -> Result<Self> {
        let version = data.read_u8()?;
        match version {
            0x01 => Ok(Self::V1),
            0x02 => {
                let sym_alg = data.read_u8().map(SymmetricKeyAlgorithm::from)?;
                let aead = data.read_u8().map(AeadAlgorithm::from)?;
                let chunk_size = data
                    .read_u8()?
                    .try_into()
                    .map_err(|_| InvalidInputSnafu.build())?;
                let salt = data.read_array::<32>()?;

                Ok(Self::V2 {
                    sym_alg,
                    aead,
                    chunk_size,
                    salt,
                })
            }
            _ => Err(format_err!(
                "unknown SymEncryptedProtectedData version {}",
                version
            )),
        }
    }
}

impl SymEncryptedProtectedData {
    /// Parses a `SymEncryptedProtectedData` packet from the given buf.
    pub fn try_from_reader<B: BufRead>(packet_header: PacketHeader, mut data: B) -> Result<Self> {
        ensure_eq!(
            packet_header.tag(),
            Tag::SymEncryptedProtectedData,
            "invalid tag"
        );

        let config = Config::try_from_reader(&mut data)?;
        let data = data.rest()?;

        Ok(SymEncryptedProtectedData {
            packet_header,
            config,
            data: data.freeze(),
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
        let packet_header =
            PacketHeader::new_fixed(Tag::SymEncryptedProtectedData, len.try_into()?);

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

        let mut encryptor = crate::crypto::aead::StreamEncryptor::new(
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
        let packet_header =
            PacketHeader::new_fixed(Tag::SymEncryptedProtectedData, len.try_into()?);

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
                    return Err(InvalidInputSnafu.build());
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

#[derive(Debug)]
pub enum StreamDecryptor<R: BufRead> {
    V1(crate::crypto::sym::StreamDecryptor<R>),
    V2(crate::crypto::aead::StreamDecryptor<R>),
}

impl<R: BufRead> BufRead for StreamDecryptor<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        match self {
            Self::V1(r) => r.fill_buf(),
            Self::V2(r) => r.fill_buf(),
        }
    }

    fn consume(&mut self, amt: usize) {
        match self {
            Self::V1(r) => r.consume(amt),
            Self::V2(r) => r.consume(amt),
        }
    }
}

impl<R: BufRead> Read for StreamDecryptor<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::V1(r) => r.read(buf),
            Self::V2(r) => r.read(buf),
        }
    }
}

impl<R: BufRead> StreamDecryptor<R> {
    pub fn v1(sym_alg: SymmetricKeyAlgorithm, key: &[u8], source: R) -> Result<Self> {
        let decryptor = sym_alg.stream_decryptor(key, source)?;
        Ok(Self::V1(decryptor))
    }

    pub fn v2(
        sym_alg: SymmetricKeyAlgorithm,
        aead: AeadAlgorithm,
        chunk_size: ChunkSize,
        salt: &[u8; 32],
        key: &[u8],
        source: R,
    ) -> Result<Self> {
        let decryptor = crate::crypto::aead::StreamDecryptor::new(
            sym_alg, aead, chunk_size, salt, key, source,
        )?;
        Ok(Self::V2(decryptor))
    }

    pub fn into_inner(self) -> R {
        match self {
            Self::V1(r) => r.into_inner(),
            Self::V2(r) => r.into_inner(),
        }
    }

    pub fn get_ref(&self) -> &R {
        match self {
            Self::V1(r) => r.get_ref(),
            Self::V2(r) => r.get_ref(),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    use super::*;

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

                let back =
                    SymEncryptedProtectedData::try_from_reader(enc.packet_header, &mut &buffer[..])
                        .unwrap();
                assert_eq!(enc, back);
            }
        }
    }
}

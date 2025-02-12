use std::io;

use byteorder::WriteBytesExt;
use bytes::{Buf, Bytes};
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
        chunk_size: u8,
        #[debug("{}", hex::encode(salt))]
        salt: [u8; 32],
    },
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
                let chunk_size = data.read_u8()?;
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

    /// Get (info, message_key, nonce) for the given parameters
    #[allow(clippy::type_complexity)]
    fn aead_setup(
        sym_alg: SymmetricKeyAlgorithm,
        aead: AeadAlgorithm,
        chunk_size: u8,
        salt: &[u8],
        ikm: &[u8],
    ) -> Result<([u8; 5], Zeroizing<Vec<u8>>, Vec<u8>)> {
        let info = [
            Tag::SymEncryptedProtectedData.encode(), // packet type
            0x02,                                    // version
            sym_alg.into(),
            aead.into(),
            chunk_size,
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

    /// Encrypts the data using the given symmetric key.
    pub fn encrypt_seipdv2<R: CryptoRng + Rng>(
        mut rng: R,
        sym_alg: SymmetricKeyAlgorithm,
        aead: AeadAlgorithm,
        chunk_size: u8,
        session_key: &[u8],
        plaintext: &[u8],
    ) -> Result<Self> {
        ensure_eq!(
            session_key.len(),
            sym_alg.key_size(),
            "Unexpected session key length for {:?}",
            sym_alg
        );

        // Initial key material is the session key.
        let ikm = session_key;

        // Generate new salt for this seipd packet.
        let mut salt = [0u8; 32];
        rng.fill(&mut salt[..]);

        let chunk_size_expanded = usize::try_from(expand_chunk_size(chunk_size))?;

        let (info, message_key, mut nonce) =
            Self::aead_setup(sym_alg, aead, chunk_size, &salt[..], ikm)?;

        // Calculate output size (for more efficient vector allocation):
        // - plaintext length
        let plain_len = plaintext.len();
        // - number of chunks: plaintext length divided by chunk size, rounded up to the next integer
        let num_chunks = plain_len.div_ceil(chunk_size_expanded);
        // - total output size: plaintext length + size of all authentication tags (one tag per chunk, plus one final tag)
        let out_len = plain_len + (num_chunks + 1) * aead.tag_size().unwrap_or_default();

        let mut out = Vec::with_capacity(out_len);

        let mut chunk_index: u64 = 0;
        for chunk in plaintext.chunks(chunk_size_expanded) {
            let pos = out.len();

            // append this next unencrypted chunk to `out`, and encrypt it in place
            out.extend_from_slice(chunk);

            let encrypt_chunk = &mut out[pos..];

            let auth_tag =
                aead.encrypt_in_place(&sym_alg, &message_key, &nonce, &info, encrypt_chunk)?;

            out.extend_from_slice(&auth_tag);

            // Update nonce to include the next chunk index
            chunk_index += 1;
            let l = nonce.len() - 8;
            nonce[l..].copy_from_slice(&chunk_index.to_be_bytes());
        }

        // Make and append final auth tag

        // Associated data is extended with number of plaintext octets.
        let size = plaintext.len() as u64;
        let mut final_info = info.to_vec();
        final_info.extend_from_slice(&size.to_be_bytes());

        let final_auth_tag = aead.encrypt_in_place(
            &sym_alg,
            &message_key,
            &nonce,
            &final_info,
            &mut [][..], // encrypts empty string
        )?;
        out.extend_from_slice(&final_auth_tag);

        debug_assert_eq!(out.len(), out_len, "we pre-allocated the wrong output size");
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

                let chunk_size_expanded = usize::try_from(expand_chunk_size(*chunk_size))?;

                let (info, message_key, mut nonce) =
                    Self::aead_setup(*sym_alg, *aead, *chunk_size, &salt[..], ikm)?;

                let mut data = self.data.to_vec();

                // There are n chunks, n auth tags + 1 final auth tag
                let Some(aead_tag_size) = aead.tag_size() else {
                    unsupported_err!("AEAD mode: {:?}", aead);
                };
                if data.len() < aead_tag_size {
                    return Err(Error::InvalidInput);
                }
                let offset = data.len() - aead_tag_size;
                let (main_chunks, final_auth_tag) = data.split_at_mut(offset);

                // Calculate output size (for more efficient vector allocation):
                // - number of chunks: main_chunks length divided by (chunk size + tag size), rounded up to the next integer
                let Some(aead_tag_size) = aead.tag_size() else {
                    unsupported_err!("AEAD mode: {:?}", aead);
                };
                let chunk_and_tag_len = chunk_size_expanded + aead_tag_size;
                let main_len = main_chunks.len();
                let num_chunks = main_len.div_ceil(chunk_and_tag_len);
                // - total output size: main_chunks length - size of one authentication tag per chunk
                let out_len = main_len - num_chunks * aead_tag_size;

                let mut out = Vec::with_capacity(out_len);

                let mut chunk_index: u64 = 0;
                for chunk in main_chunks.chunks_mut(chunk_size_expanded + aead_tag_size) {
                    let offset = chunk.len() - aead_tag_size;
                    let (chunk, auth_tag) = chunk.split_at_mut(offset);

                    aead.decrypt_in_place(sym_alg, &message_key, &nonce, &info, auth_tag, chunk)?;

                    out.extend_from_slice(chunk);

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
                    final_auth_tag,
                    &mut [][..], // decrypts empty string
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
                writer.write_u8(*chunk_size)?;
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

fn expand_chunk_size(s: u8) -> u32 {
    1u32 << (s as u32 + 6)
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

        // Chunk size parameter 0 means "chunks of 64 byte each"
        const CHUNK_SIZE: u8 = 0;

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
                    CHUNK_SIZE,
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

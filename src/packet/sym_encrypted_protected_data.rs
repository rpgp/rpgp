use std::io::{self, BufRead, Read};

use byteorder::WriteBytesExt;
use bytes::Bytes;
use rand::{CryptoRng, Rng, RngCore};

use crate::{
    crypto::{
        aead::{AeadAlgorithm, ChunkSize, StreamEncryptor},
        sym::SymmetricKeyAlgorithm,
    },
    errors::{ensure_eq, format_err, InvalidInputSnafu, Result},
    packet::{GnupgAeadDataConfig, PacketHeader, PacketTrait, SymEncryptedProtectedDataConfig},
    parsing_reader::BufReadParsing,
    ser::Serialize,
    types::Tag,
};

/// Either a standard OpenPGP SEIPD config or a Gnupg-specific AEAD config
#[derive(Clone, PartialEq, Eq, derive_more::Debug)]
pub enum ProtectedDataConfig {
    Seipd(SymEncryptedProtectedDataConfig),
    GnupgAead(GnupgAeadDataConfig),
}

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
    pub fn encrypt_seipdv1<R: CryptoRng + RngCore + ?Sized>(
        rng: &mut R,
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
    pub fn encrypt_seipdv2<R: CryptoRng + RngCore + ?Sized>(
        rng: &mut R,
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
                let mut decryptor = StreamDecryptor::v1(sym_alg, session_key, &self.data[..])?;
                let mut out = Vec::new();
                decryptor.read_to_end(&mut out)?;
                Ok(out)
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

                let mut decryptor = StreamDecryptor::v2(
                    *sym_alg,
                    *aead,
                    *chunk_size,
                    salt,
                    session_key,
                    &self.data[..],
                )?;
                let mut out = Vec::new();
                decryptor.read_to_end(&mut out)?;
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
#[allow(clippy::large_enum_variant)]
pub enum StreamDecryptor<R: BufRead> {
    V1(crate::crypto::sym::StreamDecryptor<R>),
    GnupgAead(crate::crypto::aead::StreamDecryptor<R>),
    V2(crate::crypto::aead::StreamDecryptor<R>),
}

impl<R: BufRead> BufRead for StreamDecryptor<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        match self {
            Self::V1(r) => r.fill_buf(),
            Self::GnupgAead(r) => r.fill_buf(),
            Self::V2(r) => r.fill_buf(),
        }
    }

    fn consume(&mut self, amt: usize) {
        match self {
            Self::V1(r) => r.consume(amt),
            Self::GnupgAead(r) => r.consume(amt),
            Self::V2(r) => r.consume(amt),
        }
    }
}

impl<R: BufRead> Read for StreamDecryptor<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::V1(r) => r.read(buf),
            Self::GnupgAead(r) => r.read(buf),
            Self::V2(r) => r.read(buf),
        }
    }
}

impl<R: BufRead> StreamDecryptor<R> {
    pub fn v1(sym_alg: SymmetricKeyAlgorithm, key: &[u8], source: R) -> Result<Self> {
        let decryptor = sym_alg.stream_decryptor_protected(key, source)?;
        Ok(Self::V1(decryptor))
    }

    pub fn gnupg_aead(
        sym_alg: SymmetricKeyAlgorithm,
        aead: AeadAlgorithm,
        chunk_size: ChunkSize,
        key: &[u8],
        iv: &[u8],
        source: R,
    ) -> Result<Self> {
        let decryptor = crate::crypto::aead::StreamDecryptor::new_gnupg(
            sym_alg, aead, chunk_size, key, iv, source,
        )?;
        Ok(Self::GnupgAead(decryptor))
    }

    pub fn v2(
        sym_alg: SymmetricKeyAlgorithm,
        aead: AeadAlgorithm,
        chunk_size: ChunkSize,
        salt: &[u8; 32],
        key: &[u8],
        source: R,
    ) -> Result<Self> {
        let decryptor = crate::crypto::aead::StreamDecryptor::new_rfc9580(
            sym_alg, aead, chunk_size, salt, key, source,
        )?;
        Ok(Self::V2(decryptor))
    }

    pub fn into_inner(self) -> R {
        match self {
            Self::V1(r) => r.into_inner(),
            Self::GnupgAead(r) => r.into_inner(),
            Self::V2(r) => r.into_inner(),
        }
    }

    pub fn get_ref(&self) -> &R {
        match self {
            Self::V1(r) => r.get_ref(),
            Self::GnupgAead(r) => r.get_ref(),
            Self::V2(r) => r.get_ref(),
        }
    }

    pub fn get_mut(&mut self) -> &mut R {
        match self {
            Self::V1(r) => r.get_mut(),
            Self::GnupgAead(r) => r.get_mut(),
            Self::V2(r) => r.get_mut(),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use chacha20::ChaCha8Rng;
    use proptest::{collection::vec, prelude::*};
    use rand::{RngCore, SeedableRng};

    use super::*;
    use crate::{
        packet::sym_encrypted_protected_data::Config,
        types::{PacketHeaderVersion, PacketLength},
    };

    #[test]
    fn test_aead_message_sizes() {
        // Test that AEAD encryption/decryption works for message sizes that span 0-2 chunks.

        let mut rng = ChaCha8Rng::from_seed([0u8; 32]);

        const SYM_ALG: SymmetricKeyAlgorithm = SymmetricKeyAlgorithm::AES128;

        let mut session_key = [0; 16];
        rng.fill_bytes(&mut session_key);

        // Iterate over message sizes from 0 bytes through all 1-chunk and 2-chunk lengths
        // (ending with two chunks of a full 64 bytes)
        for size in 0..=512 {
            let mut message = vec![0; size];
            rng.fill_bytes(&mut message);

            for aead in [AeadAlgorithm::Ocb, AeadAlgorithm::Eax, AeadAlgorithm::Gcm] {
                println!("{size} bytes: {aead:?}");
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

    impl Arbitrary for Config {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            prop_oneof![
                Just(Config::V1),
                any::<(SymmetricKeyAlgorithm, AeadAlgorithm, ChunkSize)>()
                    .prop_flat_map(move |(sym_alg, aead, chunk_size)| {
                        (
                            Just(sym_alg),
                            Just(aead),
                            Just(chunk_size),
                            vec(0u8..=255u8, 32),
                        )
                    })
                    .prop_map(move |(sym_alg, aead, chunk_size, salt)| Config::V2 {
                        sym_alg,
                        aead,
                        chunk_size,
                        salt: salt.try_into().unwrap(),
                    })
            ]
            .boxed()
        }
    }

    impl Arbitrary for SymEncryptedProtectedData {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            any::<Config>()
                .prop_flat_map(move |config| (Just(config), vec(0u8..=255u8, 0..=2048)))
                .prop_map(move |(config, data)| {
                    let len = 1u32; // unused
                    let packet_header = PacketHeader::from_parts(
                        PacketHeaderVersion::New,
                        Tag::SymEncryptedProtectedData,
                        PacketLength::Fixed(len),
                    )
                    .unwrap();
                    SymEncryptedProtectedData {
                        config,
                        packet_header,
                        data: data.into(),
                    }
                })
                .boxed()
        }
    }

    proptest! {
        #[test]
        fn write_len(data: SymEncryptedProtectedData) {
            let mut buf = Vec::new();
            data.to_writer(&mut buf).unwrap();
            prop_assert_eq!(buf.len(), data.write_len());
        }


        #[test]
        fn packet_roundtrip(data: SymEncryptedProtectedData) {
            let mut buf = Vec::new();
            data.to_writer(&mut buf).unwrap();
            let new_data = SymEncryptedProtectedData::try_from_reader(data.packet_header, &mut &buf[..]).unwrap();
            prop_assert_eq!(data, new_data);
        }
    }
}

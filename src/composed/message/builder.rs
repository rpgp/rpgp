use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use bytes::Bytes;
use chrono::{SubsecRound, Utc};
use log::debug;
use rand::{CryptoRng, Rng};
use zeroize::Zeroizing;

use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::errors::Result;
use crate::packet::{
    DataMode, LiteralDataGenerator, LiteralDataHeader, PacketHeader, PublicKeyEncryptedSessionKey,
    SymEncryptedProtectedDataConfig, SymKeyEncryptedSessionKey,
};
use crate::ser::Serialize;
use crate::types::{
    CompressionAlgorithm, PacketHeaderVersion, PacketLength, PublicKeyTrait, StringToKey, Tag,
};
use crate::util::fill_buffer;
use crate::Esk;

type DummyReader = std::io::Cursor<Vec<u8>>;

pub struct Builder<R = DummyReader> {
    source: Source<R>,
    compression: CompressionAlgorithm,
    encryption: Option<Encryption>,
    /// The chunk size when generating partial packets
    chunk_size: u32,
}

enum Source<R = DummyReader> {
    Bytes { name: Bytes, bytes: Bytes },
    File(PathBuf),
    Reader { file_name: Bytes, reader: R },
}

#[allow(dead_code)]
enum Encryption {
    PasswordSeipdV1 {
        session_key: Zeroizing<Vec<u8>>,
        esk: SymKeyEncryptedSessionKey,
        sym_alg: SymmetricKeyAlgorithm,
    },
    KeysSeipdV1 {
        sym_alg: SymmetricKeyAlgorithm,
        session_key: Zeroizing<Vec<u8>>,
        esk: Vec<PublicKeyEncryptedSessionKey>,
    },
}

pub(crate) const DEFAULT_CHUNK_SIZE: u32 = 1024 * 512;

impl Builder<DummyReader> {
    pub fn from_file(path: impl AsRef<Path>) -> Self {
        Self {
            source: Source::File(path.as_ref().into()),
            compression: CompressionAlgorithm::Uncompressed,
            encryption: None,
            chunk_size: DEFAULT_CHUNK_SIZE,
        }
    }

    pub fn from_bytes(name: impl Into<Bytes>, bytes: impl Into<Bytes>) -> Self {
        Self {
            source: Source::Bytes {
                name: name.into(),
                bytes: bytes.into(),
            },
            compression: CompressionAlgorithm::Uncompressed,
            encryption: None,
            chunk_size: DEFAULT_CHUNK_SIZE,
        }
    }
}
impl<R: Read> Builder<R> {
    pub fn from_reader(file_name: impl Into<Bytes>, reader: R) -> Self {
        Self {
            source: Source::Reader {
                file_name: file_name.into(),
                reader,
            },
            compression: CompressionAlgorithm::Uncompressed,
            encryption: None,
            chunk_size: DEFAULT_CHUNK_SIZE,
        }
    }

    pub fn chunk_size(mut self, size: u32) -> Result<Self> {
        ensure!(size >= 512, "chunk size must be larger than 512");
        ensure!(size.is_power_of_two(), "chunk size must be a power of two");
        self.chunk_size = size;
        Ok(self)
    }

    pub fn compression(mut self, compression: CompressionAlgorithm) -> Self {
        self.compression = compression;
        self
    }

    pub fn plaintext(mut self) -> Self {
        self.encryption.take();
        self
    }

    pub fn encrypt_with_password_seipdv1<RAND, F>(
        mut self,
        mut rng: RAND,
        s2k: StringToKey,
        sym_alg: SymmetricKeyAlgorithm,
        msg_pw: F,
    ) -> Result<Self>
    where
        RAND: Rng + CryptoRng,
        F: FnOnce() -> String + Clone,
    {
        // 1. Generate a session key.
        let session_key = sym_alg.new_session_key(&mut rng);

        // 2. Encrypt (sym) the session key using the provided password.
        let esk = SymKeyEncryptedSessionKey::encrypt_v4(msg_pw, &session_key, s2k, sym_alg)?;

        self.encryption.replace(Encryption::PasswordSeipdV1 {
            sym_alg,
            esk,
            session_key,
        });

        Ok(self)
    }

    pub fn encrypt_to_keys_seipdv1<RAND>(
        mut self,
        mut rng: RAND,
        sym_alg: SymmetricKeyAlgorithm,
        pkeys: &[&impl PublicKeyTrait],
    ) -> Result<Self>
    where
        RAND: CryptoRng + Rng,
    {
        // 1. Generate a session key.
        let session_key = sym_alg.new_session_key(&mut rng);

        // 2. Encrypt (pub) the session key, to each PublicKey.
        let esk = pkeys
            .iter()
            .map(|pkey| {
                PublicKeyEncryptedSessionKey::from_session_key_v3(
                    &mut rng,
                    &session_key,
                    sym_alg,
                    pkey,
                )
            })
            .collect::<Result<_>>()?;

        self.encryption.replace(Encryption::KeysSeipdV1 {
            sym_alg,
            session_key,
            esk,
        });

        Ok(self)
    }

    pub fn to_writer<RAND, W>(self, mut rng: RAND, mut out: W) -> Result<()>
    where
        RAND: Rng + CryptoRng,
        W: std::io::Write,
    {
        // TODO: deal with compression

        match self.source {
            Source::Bytes { name, bytes } => {
                debug!("sourcing bytes {:?}: {} bytes", name, bytes.len());
                use bytes::Buf;
                let len = bytes.len();

                // Construct Literal Data Packet (inner)
                let literal_data_header = LiteralDataHeader {
                    mode: DataMode::Binary,
                    file_name: name,
                    created: Utc::now().trunc_subsecs(0),
                };

                let mut generator = LiteralDataGenerator::new(
                    literal_data_header,
                    bytes.reader(),
                    Some(len.try_into()?),
                    self.chunk_size,
                )?;
                if let Some(encryption) = self.encryption {
                    encrypt(&mut rng, generator, encryption, out)?;
                } else {
                    std::io::copy(&mut generator, &mut out)?;
                }
            }
            Source::File(path) => {
                let in_file = std::fs::File::open(&path)?;
                let in_meta = in_file.metadata()?;
                let in_file_size = usize::try_from(in_meta.len())?;

                let Some(in_file_name) = path.file_name() else {
                    bail!("{}: is not a valid input file", path.display());
                };
                let file_name: Bytes = in_file_name.as_encoded_bytes().to_vec().into();

                debug!("sourcing file {:?}: {} bytes", file_name, in_file_size);

                let in_file = BufReader::new(in_file);
                let literal_data_header = LiteralDataHeader {
                    mode: DataMode::Binary,
                    file_name,
                    created: Utc::now().trunc_subsecs(0),
                };

                let mut generator = LiteralDataGenerator::new(
                    literal_data_header,
                    in_file,
                    Some(in_file_size.try_into()?),
                    self.chunk_size,
                )?;
                if let Some(encryption) = self.encryption {
                    encrypt(&mut rng, generator, encryption, out)?;
                } else {
                    std::io::copy(&mut generator, &mut out)?;
                }
            }
            Source::Reader { file_name, reader } => {
                let literal_data_header = LiteralDataHeader {
                    mode: DataMode::Binary,
                    file_name,
                    created: Utc::now().trunc_subsecs(0),
                };

                let mut generator =
                    LiteralDataGenerator::new(literal_data_header, reader, None, self.chunk_size)?;

                if let Some(encryption) = self.encryption {
                    encrypt(&mut rng, generator, encryption, out)?;
                } else {
                    std::io::copy(&mut generator, &mut out)?;
                }
            }
        }
        Ok(())
    }

    pub fn to_file<RAND, P>(self, rng: RAND, out_path: P) -> Result<()>
    where
        RAND: Rng + CryptoRng,
        P: AsRef<Path>,
    {
        let out_path: &Path = out_path.as_ref();
        debug!("writing to file: {}", out_path.display());
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let out_file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(out_path)?;
        let mut out_file = BufWriter::new(out_file);

        self.to_writer(rng, &mut out_file)?;

        out_file.flush()?;

        Ok(())
    }
}

fn encrypt<R: Rng + CryptoRng, READ: std::io::Read, W: std::io::Write>(
    mut rng: R,
    generator: LiteralDataGenerator<READ>,
    encryption: Encryption,
    mut out: W,
) -> Result<()> {
    match encryption {
        Encryption::PasswordSeipdV1 {
            session_key,
            esk,
            sym_alg,
        } => {
            // Write out esk
            let esk = Esk::SymKeyEncryptedSessionKey(esk);
            esk.to_writer(&mut out)?;

            // Construct SEPD Packet (outer)
            let config = SymEncryptedProtectedDataConfig::V1;

            // Write the outer packet header
            match generator.len() {
                None => {
                    // partial
                    // rough plan
                    // unknown size:
                    //
                    // Literal Data
                    // - N - 1 partials
                    // - 1 fixed
                    //
                    // Compressed Data
                    // - M - 1 partials
                    // - 1 fixed
                    //
                    // Encrypted Data
                    // - L - 1 partials
                    // - 1 fixed
                    //
                    // Fixed(chunk_size): literal data
                    // Fixed(compressed_chunk_size): compressed data
                    // Partial(encrypted_compressed_chunk_size): encrypted data
                    //
                    // final packet:
                    // fixed size with the last part

                    let chunk_size = DEFAULT_CHUNK_SIZE as usize;
                    let config_len = config.write_len();

                    // headers are written only in the first chunk
                    // the partial length be a power of two, so subtract the overhead
                    let first_chunk_size = chunk_size - config_len;

                    let mut buffer = vec![0u8; chunk_size];

                    let mut is_first = true;

                    let mut encrypted =
                        sym_alg.stream_encryptor(&mut rng, &session_key, generator)?;

                    loop {
                        let (length, mut buf) = if is_first {
                            let read = fill_buffer(&mut encrypted, &mut buffer, None)?;

                            if read < first_chunk_size {
                                // finished reading, all data fits into a single chunk
                                (PacketLength::Fixed(read + config_len), &buffer[..read])
                            } else {
                                (PacketLength::Partial(chunk_size as u32), &buffer[..read])
                            }
                        } else {
                            let read = fill_buffer(&mut encrypted, &mut buffer, Some(chunk_size))?;

                            if read < chunk_size {
                                // last chunk
                                (PacketLength::Fixed(read), &buffer[..read])
                            } else {
                                (PacketLength::Partial(chunk_size as u32), &buffer[..read])
                            }
                        };

                        if is_first {
                            let packet_header = PacketHeader::from_parts(
                                PacketHeaderVersion::New,
                                Tag::SymEncryptedProtectedData,
                                length,
                            )?;
                            debug!("packet {:?}", packet_header);

                            packet_header.to_writer(&mut out)?;
                            config.to_writer(&mut out)?;
                            is_first = false;
                        } else {
                            debug!("packet {:?}", length);
                            length.to_writer_new(&mut out)?;
                        }

                        std::io::copy(&mut buf, &mut out)?;

                        if matches!(length, PacketLength::Fixed(_)) {
                            break;
                        }
                    }
                }
                Some(in_size) => {
                    // calculate expected encrypted file size
                    let enc_file_size = sym_alg.encrypted_protected_len(in_size.try_into()?);
                    let packet_len = config.write_len() + enc_file_size;

                    let packet_header = PacketHeader::from_parts(
                        PacketHeaderVersion::New,
                        Tag::SymEncryptedProtectedData,
                        PacketLength::Fixed(packet_len),
                    )?;
                    packet_header.to_writer(&mut out)?;
                    config.to_writer(&mut out)?;
                    sym_alg.encrypt_protected_stream(rng, &session_key, generator, &mut out)?;
                }
            }
        }
        Encryption::KeysSeipdV1 { .. } => {
            todo!()
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    use crate::crypto::sym::SymmetricKeyAlgorithm;
    use crate::{Deserializable, Message};

    #[test]
    fn binary_file_fixed_size_no_compression_roundtrip_password_seipdv1() {
        let _ = pretty_env_logger::try_init();
        let dir = tempfile::tempdir().unwrap();
        let mut rng = ChaCha20Rng::seed_from_u64(1);

        let plaintext_file = dir.path().join("plaintext.txt");
        let encrypted_file = dir.path().join("encrypted.cool");

        // Generate a file
        let file_size = 1024 * 14 + 8;
        let mut buf = vec![0u8; file_size];
        rng.fill(&mut buf[..]);
        std::fs::write(&plaintext_file, &buf).unwrap();

        // encrypt it
        let s2k = crate::types::StringToKey::new_default(&mut rng);

        let builder = Builder::from_file(&plaintext_file)
            .encrypt_with_password_seipdv1(&mut rng, s2k, SymmetricKeyAlgorithm::AES128, || {
                "hello world".to_string()
            })
            .unwrap();

        builder.to_file(&mut rng, &encrypted_file).unwrap();

        // decrypt it
        let encrypted_file_data = std::fs::read(&encrypted_file).unwrap();
        let message = Message::from_bytes(encrypted_file_data.into()).unwrap();
        dbg!(&message);
        let decrypted = message
            .decrypt_with_password(|| "hello world".to_string())
            .unwrap();

        let Message::Literal(l) = decrypted else {
            panic!("unexpected message: {:?}", decrypted);
        };

        assert_eq!(l.file_name(), "plaintext.txt");
        assert_eq!(l.data(), &buf);
    }

    #[test]
    fn binary_message_fixed_size_no_compression_roundtrip_password_seipdv1() {
        let _ = pretty_env_logger::try_init();

        let mut rng = ChaCha20Rng::seed_from_u64(1);

        // Generate a file
        let file_size = 128; // 1024 * 14 + 8;
        let mut buf = vec![0u8; file_size];
        rng.fill(&mut buf[..]);

        // encrypt it
        let s2k = crate::types::StringToKey::new_default(&mut rng);

        let builder = Builder::<DummyReader>::from_bytes("plaintext.txt", buf.clone())
            .encrypt_with_password_seipdv1(&mut rng, s2k, SymmetricKeyAlgorithm::AES128, || {
                "hello world".to_string()
            })
            .unwrap();

        let mut encrypted = Vec::new();
        builder.to_writer(&mut rng, &mut encrypted).unwrap();

        // decrypt it
        let message = Message::from_bytes(encrypted.into()).unwrap();
        dbg!(&message);
        let decrypted = message
            .decrypt_with_password(|| "hello world".to_string())
            .unwrap();

        let Message::Literal(l) = decrypted else {
            panic!("unexpected message: {:?}", decrypted);
        };

        assert_eq!(l.file_name(), "plaintext.txt");
        assert_eq!(l.data(), &buf);
    }

    #[test]
    fn binary_file_partial_size_no_compression_roundtrip_password_seipdv1() {
        let _ = pretty_env_logger::try_init();
        let mut rng = ChaCha20Rng::seed_from_u64(1);

        let chunk_size = 512u32;
        let max_file_size = 5 * chunk_size as usize + 100;

        for file_size in (1..=max_file_size).step_by(10) {
            println!("Size {}", file_size);

            // Generate data
            let mut buf = vec![0u8; file_size];
            rng.fill(&mut buf[..]);

            // encrypt it
            let s2k = crate::types::StringToKey::new_default(&mut rng);

            let builder = Builder::from_reader("plaintext.txt", &buf[..])
                .chunk_size(chunk_size)
                .unwrap()
                .encrypt_with_password_seipdv1(&mut rng, s2k, SymmetricKeyAlgorithm::AES128, || {
                    "hello world".to_string()
                })
                .expect("encryption");

            let mut encrypted = Vec::new();
            builder
                .to_writer(&mut rng, &mut encrypted)
                .expect("writing");

            // decrypt it
            let message = Message::from_bytes(encrypted.into()).expect("reading");
            let decrypted = message
                .decrypt_with_password(|| "hello world".to_string())
                .expect("decryption");

            let Message::Literal(l) = decrypted else {
                panic!("unexpected message: {:?}", decrypted);
            };

            assert_eq!(l.file_name(), "plaintext.txt");
            assert_eq!(l.data(), &buf);
        }
    }

    #[test]
    fn binary_file_partial_size_no_compression_roundtrip_no_encryption() {
        let _ = pretty_env_logger::try_init();
        let mut rng = ChaCha20Rng::seed_from_u64(1);

        let chunk_size = 512u32;
        let max_file_size = 5 * chunk_size as usize + 100;

        for file_size in (1..=max_file_size).step_by(10) {
            println!("Size {}", file_size);

            // Generate data
            let mut buf = vec![0u8; file_size];
            rng.fill(&mut buf[..]);

            let builder = Builder::from_reader("plaintext.txt", &buf[..])
                .chunk_size(chunk_size)
                .unwrap()
                .plaintext();

            let mut encoded = Vec::new();
            builder.to_writer(&mut rng, &mut encoded).expect("writing");

            // decrypt it
            let message = Message::from_bytes(encoded.into()).expect("reading");

            let Message::Literal(l) = message else {
                panic!("unexpected message: {:?}", message);
            };

            assert_eq!(l.file_name(), "plaintext.txt");
            assert_eq!(l.data(), &buf);
        }
    }
}

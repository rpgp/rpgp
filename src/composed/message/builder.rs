use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use bstr::BString;
use bytes::Bytes;
use chrono::{SubsecRound, Utc};
use log::debug;
use rand::{CryptoRng, Rng};
use zeroize::Zeroizing;

use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::errors::Result;
use crate::packet::{
    DataMode, LiteralDataHeader, PublicKeyEncryptedSessionKey, SymEncryptedProtectedDataConfig,
    SymKeyEncryptedSessionKey,
};
use crate::ser::Serialize;
use crate::types::{CompressionAlgorithm, PublicKeyTrait, StringToKey, Tag, Version};
use crate::Esk;

pub struct Builder {
    source: Source,
    compression: CompressionAlgorithm,
    encryption: Encryption,
}

enum Source {
    Bytes { name: BString, bytes: Bytes },
    File(PathBuf),
}

enum Encryption {
    None,
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

impl Builder {
    pub fn from_file(path: impl AsRef<Path>) -> Self {
        Self {
            source: Source::File(path.as_ref().into()),
            compression: CompressionAlgorithm::Uncompressed,
            encryption: Encryption::None,
        }
    }

    pub fn from_bytes(name: impl Into<BString>, bytes: impl Into<Bytes>) -> Self {
        Self {
            source: Source::Bytes {
                name: name.into(),
                bytes: bytes.into(),
            },
            compression: CompressionAlgorithm::Uncompressed,
            encryption: Encryption::None,
        }
    }

    pub fn compression(mut self, compression: CompressionAlgorithm) -> Self {
        self.compression = compression;
        self
    }

    pub fn plaintext(mut self) -> Self {
        self.encryption = Encryption::None;
        self
    }

    pub fn encrypt_with_password_seipdv1<R, F>(
        mut self,
        mut rng: R,
        s2k: StringToKey,
        sym_alg: SymmetricKeyAlgorithm,
        msg_pw: F,
    ) -> Result<Self>
    where
        R: Rng + CryptoRng,
        F: FnOnce() -> String + Clone,
    {
        // 1. Generate a session key.
        let session_key = sym_alg.new_session_key(&mut rng);

        // 2. Encrypt (sym) the session key using the provided password.
        let esk = SymKeyEncryptedSessionKey::encrypt_v4(msg_pw, &session_key, s2k, sym_alg)?;

        self.encryption = Encryption::PasswordSeipdV1 {
            sym_alg,
            esk,
            session_key,
        };

        Ok(self)
    }

    pub fn encrypt_to_keys_seipdv1<R>(
        mut self,
        mut rng: R,
        sym_alg: SymmetricKeyAlgorithm,
        pkeys: &[&impl PublicKeyTrait],
    ) -> Result<Self>
    where
        R: CryptoRng + Rng,
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

        self.encryption = Encryption::KeysSeipdV1 {
            sym_alg,
            session_key,
            esk,
        };

        Ok(self)
    }

    pub fn to_writer<R, W>(self, mut rng: R, out: W) -> Result<()>
    where
        R: Rng + CryptoRng,
        W: std::io::Write,
    {
        // TODO: handle compression

        fn encrypt<R: Rng + CryptoRng, W: std::io::Write>(
            rng: R,
            reader: impl BufRead,
            file_name: BString,
            in_size: usize,
            encryption: Encryption,
            mut out: W,
        ) -> Result<()> {
            match encryption {
                Encryption::None => {
                    todo!();
                }
                Encryption::PasswordSeipdV1 {
                    session_key,
                    esk,
                    sym_alg,
                } => {
                    // Write out esk
                    let esk = Esk::SymKeyEncryptedSessionKey(esk);
                    esk.to_writer(&mut out)?;

                    // Construct Literal Data Packet (inner)
                    let literal_data_header = LiteralDataHeader {
                        packet_version: Version::New,
                        mode: DataMode::Binary,
                        file_name,
                        created: Utc::now().trunc_subsecs(0),
                    };

                    let literal_data_header_len = literal_data_header.write_len();
                    let literal_data_packet_len = literal_data_header_len + in_size;
                    // the prefix to encrypt to make a Literal Data Packet
                    let mut prefix = Vec::new();
                    literal_data_header.packet_version.write_header(
                        &mut prefix,
                        Tag::LiteralData,
                        literal_data_packet_len,
                    )?;
                    literal_data_header.to_writer(&mut prefix)?;

                    // calculate expected encrypted file size
                    let enc_file_size = sym_alg.encrypted_protected_len(prefix.len() + in_size);

                    // chain the prefix to the input reader
                    let to_encode = prefix.chain(reader);

                    // Construct SEPD Packet (outer)
                    let config = SymEncryptedProtectedDataConfig::V1;

                    let outer_header_len = config.write_len();
                    let outer_packet_len = outer_header_len + enc_file_size;

                    // Write the outer packet header
                    Version::New.write_header(
                        &mut out,
                        Tag::SymEncryptedProtectedData,
                        outer_packet_len,
                    )?;
                    config.to_writer(&mut out)?;
                    sym_alg.encrypt_protected_stream(rng, &session_key, to_encode, &mut out)?;
                }
                Encryption::KeysSeipdV1 {
                    sym_alg,
                    session_key,
                    esk,
                } => {
                    todo!()
                }
            }
            Ok(())
        }

        match self.source {
            Source::Bytes { name, bytes } => {
                debug!("sourcing bytes {}: {} bytes", name, bytes.len());
                use bytes::Buf;
                let len = bytes.len();
                encrypt(&mut rng, bytes.reader(), name, len, self.encryption, out)?;
            }
            Source::File(path) => {
                let in_file = std::fs::File::open(&path)?;
                let in_meta = in_file.metadata()?;
                let in_file_size = usize::try_from(in_meta.len())?;

                let Some(in_file_name) = path.file_name() else {
                    bail!("{}: is not a vaild input file", path.display());
                };
                let file_name: BString = in_file_name.as_encoded_bytes().into();

                debug!("sourcing file {}: {} bytes", file_name, in_file_size);

                let in_file = BufReader::new(in_file);

                encrypt(
                    &mut rng,
                    in_file,
                    file_name,
                    in_file_size,
                    self.encryption,
                    out,
                )?;
            }
        }
        Ok(())
    }

    pub fn to_file<R, P>(self, rng: R, out_path: P) -> Result<()>
    where
        R: Rng + CryptoRng,
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
            .open(&out_path)?;
        let mut out_file = BufWriter::new(out_file);

        self.to_writer(rng, &mut out_file)?;

        out_file.flush()?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    use crate::crypto::sym::SymmetricKeyAlgorithm;
    use crate::{Deserializable, Message};

    #[test]
    fn binary_message_roundtrip_password_seipdv1() {
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
}

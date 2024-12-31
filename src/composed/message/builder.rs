use std::io::BufWriter;
use std::path::{Path, PathBuf};

use bytes::Bytes;
use rand::{CryptoRng, Rng};
use zeroize::Zeroizing;

use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::errors::Result;
use crate::packet::{PublicKeyEncryptedSessionKey, SymKeyEncryptedSessionKey};
use crate::types::{CompressionAlgorithm, PublicKeyTrait, StringToKey};

pub struct Builder {
    source: Source,
    compression: CompressionAlgorithm,
    encryption: Encryption,
}

enum Source {
    Bytes(Bytes),
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

    pub fn from_bytes(bytes: impl Into<Bytes>) -> Self {
        Self {
            source: Source::Bytes(bytes.into()),
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
        todo!()
    }

    pub fn to_file<R, P>(self, rng: R, out_path: P) -> Result<()>
    where
        R: Rng + CryptoRng,
        P: AsRef<Path>,
    {
        let out_path: &Path = out_path.as_ref();
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

        Ok(())
    }
}

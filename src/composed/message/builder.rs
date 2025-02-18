use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use bytes::{Bytes, BytesMut};
use chrono::{SubsecRound, Utc};
use crc24::Crc24Hasher;
use generic_array::typenum::U64;
use log::debug;
use rand::{CryptoRng, Rng};
use zeroize::Zeroizing;

use crate::armor;
use crate::crypto::aead::AeadAlgorithm;
use crate::crypto::hash::HashAlgorithm;
use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::errors::Result;
use crate::line_writer::{LineBreak, LineWriter};
use crate::packet::{
    ChunkSize, CompressedDataGenerator, DataMode, LiteralDataGenerator, LiteralDataHeader,
    OnePassSignature, PacketHeader, PacketTrait, PublicKeyEncryptedSessionKey, SignatureHasher,
    SignatureType, SignatureVersionSpecific, Subpacket, SubpacketData, SymEncryptedProtectedData,
    SymEncryptedProtectedDataConfig, SymKeyEncryptedSessionKey,
};
use crate::ser::Serialize;
use crate::types::{
    CompressionAlgorithm, Fingerprint, KeyVersion, PacketHeaderVersion, PacketLength, Password,
    SecretKeyTrait, StringToKey, Tag,
};
use crate::util::fill_buffer;
use crate::util::TeeWriter;
use crate::Esk;

use super::ArmorOptions;

type DummyReader = std::io::Cursor<Vec<u8>>;

/// Constructs message from a given data source.
///
/// All data is processed in a streaming fashion, with minimal memory allocations.
///
/// If the file size is known upfront (fixed buffer, or file source), the resulting packets
/// will be fixed size lengths (unless compression is involved).
///
/// If the file size is not known upfront, partial packets will be generated, at each level
/// (encryption, compression, literal data).
///
/// If the total data fits into a single chunk, a single fixed packet is generated.
pub struct Builder<'a, R = DummyReader, E = NoEncryption> {
    source: Source<R>,
    compression: Option<CompressionAlgorithm>,
    signing: Vec<SigningConfig<'a>>,
    encryption: E,
    /// The chunk size when generating partial packets
    chunk_size: u32,
    data_mode: DataMode,
}

#[derive(Clone)]
enum Source<R = DummyReader> {
    Bytes { name: Bytes, bytes: Bytes },
    File(PathBuf),
    Reader { file_name: Bytes, reader: R },
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub struct NoEncryption;

#[derive(Debug, PartialEq, Clone)]
pub struct EncryptionSeipdV1 {
    session_key: Zeroizing<Vec<u8>>,
    sym_esks: Vec<SymKeyEncryptedSessionKey>,
    pub_esks: Vec<PublicKeyEncryptedSessionKey>,
    sym_alg: SymmetricKeyAlgorithm,
}

#[derive(Debug, PartialEq, Clone)]
pub struct EncryptionSeipdV2 {
    session_key: Zeroizing<Vec<u8>>,
    sym_esks: Vec<SymKeyEncryptedSessionKey>,
    pub_esks: Vec<PublicKeyEncryptedSessionKey>,
    sym_alg: SymmetricKeyAlgorithm,
    aead: AeadAlgorithm,
    chunk_size: ChunkSize,
    salt: [u8; 32],
}

pub trait Encryption: PartialEq {
    fn encrypt<R, READ, W>(self, rng: R, generator: READ, len: Option<u32>, out: W) -> Result<()>
    where
        R: Rng + CryptoRng,
        READ: std::io::Read,
        W: std::io::Write;

    fn is_plaintext(&self) -> bool;
}

/// Configures a signing key and how to use it.
#[derive(Debug)]
pub struct SigningConfig<'a> {
    /// The key to sign with
    key: &'a dyn SecretKeyTrait,
    /// A password to unlock it
    key_pw: Password,
    /// The hash algorithm to be used when sigining.
    hash_algorithm: HashAlgorithm,
}

impl<'a> SigningConfig<'a> {
    /// Create a new signing configuration.
    pub fn new<K>(key: &'a K, key_pw: Password, hash: HashAlgorithm) -> Self
    where
        K: SecretKeyTrait,
    {
        Self {
            key,
            key_pw,
            hash_algorithm: hash,
        }
    }
}

/// Configures the version specific parts of
/// the Symmetric Encrypted and Integrity Data Packet.
pub enum Seipd {
    /// Version 1
    V1 { sym_alg: SymmetricKeyAlgorithm },
    /// Version 2
    V2 {
        sym_alg: SymmetricKeyAlgorithm,
        aead: AeadAlgorithm,
        chunk_size: ChunkSize,
    },
}

/// The default chunk size.
pub const DEFAULT_CHUNK_SIZE: u32 = 1024 * 512;

impl Builder<'_, DummyReader> {
    /// Source the data from the given file path.
    pub fn from_file(path: impl AsRef<Path>) -> Self {
        Self {
            source: Source::File(path.as_ref().into()),
            compression: None,
            encryption: NoEncryption,
            signing: Vec::new(),
            chunk_size: DEFAULT_CHUNK_SIZE,
            data_mode: DataMode::Binary,
        }
    }

    /// Source the data from the given byte buffer.
    pub fn from_bytes(name: impl Into<Bytes>, bytes: impl Into<Bytes>) -> Self {
        Self {
            source: Source::Bytes {
                name: name.into(),
                bytes: bytes.into(),
            },
            compression: None,
            encryption: NoEncryption,
            chunk_size: DEFAULT_CHUNK_SIZE,
            data_mode: DataMode::Binary,
            signing: Vec::new(),
        }
    }
}

fn prepare<R>(
    mut rng: R,
    typ: SignatureType,
    keys: &[SigningConfig<'_>],
) -> Result<Vec<(crate::packet::SignatureConfig, OnePassSignature)>>
where
    R: Rng + CryptoRng,
{
    let mut out = Vec::new();

    for config in keys {
        // Signature setup
        let key_id = config.key.key_id();
        let algorithm = config.key.algorithm();
        let hash_alg = config.hash_algorithm;

        let hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::IssuerFingerprint(config.key.fingerprint()))?,
            Subpacket::regular(SubpacketData::SignatureCreationTime(
                chrono::Utc::now().trunc_subsecs(0),
            ))?,
        ];
        let unhashed_subpackets = vec![Subpacket::regular(SubpacketData::Issuer(key_id))?];

        // prepare signing
        let mut sig_config = match config.key.version() {
            KeyVersion::V4 => crate::packet::SignatureConfig::v4(typ, algorithm, hash_alg),
            KeyVersion::V6 => {
                crate::packet::SignatureConfig::v6(&mut rng, typ, algorithm, hash_alg)?
            }
            v => bail!("unsupported key version {:?}", v),
        };
        sig_config.hashed_subpackets = hashed_subpackets;
        sig_config.unhashed_subpackets = unhashed_subpackets;

        let ops = match config.key.version() {
            KeyVersion::V4 => OnePassSignature::v3(typ, hash_alg, algorithm, key_id),
            KeyVersion::V6 => {
                let SignatureVersionSpecific::V6 { ref salt } = sig_config.version_specific else {
                    // This should never happen
                    bail!("Inconsistent Signature and OnePassSignature version")
                };

                let Fingerprint::V6(fp) = config.key.fingerprint() else {
                    bail!("Inconsistent Signature and Fingerprint version")
                };

                OnePassSignature::v6(typ, hash_alg, algorithm, salt.clone(), fp)
            }
            v => bail!("Unsupported key version {:?}", v),
        };
        out.push((sig_config, ops));
    }

    Ok(out)
}

impl<'a, R: Read> Builder<'a, R, NoEncryption> {
    /// Encrypt this message using Seipd V1.
    pub fn seipd_v1<RAND>(
        self,
        mut rng: RAND,
        sym_alg: SymmetricKeyAlgorithm,
    ) -> Builder<'a, R, EncryptionSeipdV1>
    where
        RAND: CryptoRng + Rng,
    {
        let session_key = sym_alg.new_session_key(&mut rng);

        Builder {
            source: self.source,
            compression: self.compression,
            chunk_size: self.chunk_size,
            data_mode: self.data_mode,
            encryption: EncryptionSeipdV1 {
                sym_alg,
                session_key,
                sym_esks: Vec::new(),
                pub_esks: Vec::new(),
            },
            signing: Vec::new(),
        }
    }
}

impl<'a, R: Read> Builder<'a, R, NoEncryption> {
    /// Encrypt this message using Seipd V2.
    pub fn seipd_v2<RAND>(
        self,
        mut rng: RAND,
        sym_alg: SymmetricKeyAlgorithm,
        aead: AeadAlgorithm,
        chunk_size: ChunkSize,
    ) -> Builder<'a, R, EncryptionSeipdV2>
    where
        RAND: CryptoRng + Rng,
    {
        let session_key = sym_alg.new_session_key(&mut rng);

        let mut salt = [0u8; 32];
        rng.fill_bytes(&mut salt);

        Builder {
            source: self.source,
            compression: self.compression,
            chunk_size: self.chunk_size,
            data_mode: self.data_mode,
            encryption: EncryptionSeipdV2 {
                sym_alg,
                session_key,
                chunk_size,
                aead,
                salt,
                sym_esks: Vec::new(),
                pub_esks: Vec::new(),
            },
            signing: Vec::new(),
        }
    }
}

impl<R: Read> Builder<'_, R, EncryptionSeipdV1> {
    /// Encrypt to a public key
    pub fn encrypt_to_key<RAND, K>(mut self, mut rng: RAND, pkey: &K) -> Result<Self>
    where
        RAND: CryptoRng + Rng,
        K: crate::types::PublicKeyTrait,
    {
        // Encrypt (sym) the session key using the provided password.
        let pkes = PublicKeyEncryptedSessionKey::from_session_key_v3(
            &mut rng,
            &self.encryption.session_key,
            self.encryption.sym_alg,
            pkey,
        )?;
        self.encryption.pub_esks.push(pkes);
        Ok(self)
    }

    /// Encrypt to a password.
    pub fn encrypt_with_password(mut self, s2k: StringToKey, msg_pw: &Password) -> Result<Self> {
        let esk = SymKeyEncryptedSessionKey::encrypt_v4(
            msg_pw,
            &self.encryption.session_key,
            s2k,
            self.encryption.sym_alg,
        )?;
        self.encryption.sym_esks.push(esk);
        Ok(self)
    }

    /// Returns the currently used session key.
    ///
    /// WARNING: this is sensitive material, and leaking it can lead to
    /// a compromise of the data.
    pub fn session_key(&self) -> &Zeroizing<Vec<u8>> {
        &self.encryption.session_key
    }
}

impl<R: Read> Builder<'_, R, EncryptionSeipdV2> {
    /// Encrypt to a public key
    pub fn encrypt_to_key<RAND, K>(mut self, mut rng: RAND, pkey: &K) -> Result<Self>
    where
        RAND: CryptoRng + Rng,
        K: crate::types::PublicKeyTrait,
    {
        // Encrypt (sym) the session key using the provided password.
        let pkes = PublicKeyEncryptedSessionKey::from_session_key_v6(
            &mut rng,
            &self.encryption.session_key,
            pkey,
        )?;

        self.encryption.pub_esks.push(pkes);

        Ok(self)
    }

    /// Encrypt to a password.
    pub fn encrypt_with_password<RAND>(
        mut self,
        mut rng: RAND,
        s2k: StringToKey,
        msg_pw: &Password,
    ) -> Result<Self>
    where
        RAND: Rng + CryptoRng,
    {
        // Encrypt (sym) the session key using the provided password.
        let esk = SymKeyEncryptedSessionKey::encrypt_v6(
            &mut rng,
            msg_pw,
            &self.encryption.session_key,
            s2k,
            self.encryption.sym_alg,
            self.encryption.aead,
        )?;
        self.encryption.sym_esks.push(esk);

        Ok(self)
    }

    /// Returns the currently used session key.
    ///
    /// WARNING: this is sensitive material, and leaking it can lead to
    /// a compromise of the data.
    pub fn session_key(&self) -> &Zeroizing<Vec<u8>> {
        &self.encryption.session_key
    }
}

impl<R: Read> Builder<'_, R, NoEncryption> {
    /// Source the data from a reader.
    pub fn from_reader(file_name: impl Into<Bytes>, reader: R) -> Self {
        Self {
            source: Source::Reader {
                file_name: file_name.into(),
                reader,
            },
            compression: None,
            encryption: NoEncryption,
            chunk_size: DEFAULT_CHUNK_SIZE,
            data_mode: DataMode::Binary,
            signing: Vec::new(),
        }
    }
}

impl<'a, R: Read, E: Encryption> Builder<'a, R, E> {
    /// Configure the [`DataMode`] for the literal data portion.
    ///
    /// Defaults to `DataMode::Binary`
    ///
    /// If the mode is set to `DataMode::Utf8`, line endings will be normalized.
    pub fn data_mode(mut self, mode: DataMode) -> Self {
        self.data_mode = mode;
        self
    }

    /// Set the chunk size, which controls how large partial packets
    /// will be.
    ///
    /// Due to the restrictions on partial packet lengths, this size
    /// - must be larger than `512`,
    /// - must be a power of 2.
    ///
    /// Defaults to [`DEFAULT_CHUNK_SIZE`].
    pub fn chunk_size(mut self, size: u32) -> Result<Self> {
        ensure!(size >= 512, "chunk size must be larger than 512");
        ensure!(size.is_power_of_two(), "chunk size must be a power of two");
        self.chunk_size = size;
        Ok(self)
    }

    /// Configure compression.
    ///
    /// Defaults to no compression.
    pub fn compression(mut self, compression: CompressionAlgorithm) -> Self {
        self.compression.replace(compression);
        self
    }

    pub fn sign(mut self, signer: SigningConfig<'a>) -> Self {
        self.signing.push(signer);
        self
    }

    fn sign_typ(&self) -> SignatureType {
        if self.encryption.is_plaintext()
            && self.compression.is_none()
            && self.data_mode == DataMode::Utf8
        {
            SignatureType::Text
        } else {
            SignatureType::Binary
        }
    }

    /// Sign this message, using the provided key.
    pub fn to_writer_signed<RAND, W>(mut self, mut rng: RAND, mut out: W) -> Result<()>
    where
        RAND: CryptoRng + Rng,
        W: std::io::Write,
    {
        let typ = if self.encryption.is_plaintext()
            && self.compression.is_none()
            && self.data_mode == DataMode::Utf8
        {
            SignatureType::Text
        } else {
            SignatureType::Binary
        };

        let prep = prepare(&mut rng, typ, &self.signing)?;

        let mut hashers = Vec::new();

        // 1. Write all OnePass Signature packets
        for (config, ops) in prep.into_iter() {
            ops.to_writer_with_header(&mut out)?;
            hashers.push(config.into_hasher()?);
        }

        let keys = std::mem::take(&mut self.signing);

        // 2. Write actual message
        {
            // Tee the writer with the hashers
            let mut tee_writer = TeeManyWriter::new(&mut out, &mut hashers);
            self.to_writer(&mut rng, &mut tee_writer)?;
            tee_writer.flush()?;
        }

        // 3. Write all Signatures (reverse order as One Pass Signatures)
        for (hasher, config) in hashers.into_iter().zip(keys.into_iter()).rev() {
            let signature = hasher.sign(config.key, &config.key_pw)?;
            signature.to_writer_with_header(&mut out)?;
        }

        Ok(())
    }

    /// Write the data out to a writer.
    pub fn to_writer<RAND, W>(mut self, mut rng: RAND, out: W) -> Result<()>
    where
        RAND: Rng + CryptoRng,
        W: std::io::Write,
    {
        let sign_typ = self.sign_typ();

        match self.source {
            Source::Bytes { name, bytes } => {
                debug!("sourcing bytes {:?}: {} bytes", name, bytes.len());
                use bytes::Buf;
                let len = bytes.len();

                // Construct Literal Data Packet (inner)
                let literal_data_header = LiteralDataHeader {
                    mode: self.data_mode,
                    file_name: name,
                    created: Utc::now().trunc_subsecs(0),
                };

                let literal_generator = LiteralDataGenerator::new(
                    literal_data_header,
                    bytes.reader(),
                    Some(len.try_into()?),
                    self.chunk_size,
                )?;

                match self.compression {
                    Some(compression) => {
                        let len = literal_generator.len();
                        let generator = CompressedDataGenerator::new(
                            compression,
                            literal_generator,
                            len,
                            self.chunk_size,
                        )?;

                        if self.signing.is_empty() {
                            self.encryption.encrypt(&mut rng, generator, None, out)?;
                        } else {
                            let singers = std::mem::take(&mut self.signing);
                            let generator =
                                SignGenerator::new(&mut rng, sign_typ, generator, singers, None)?;
                            self.encryption.encrypt(&mut rng, generator, None, out)?;
                        }
                    }
                    None => {
                        let len = literal_generator.len();
                        if self.signing.is_empty() {
                            self.encryption
                                .encrypt(&mut rng, literal_generator, len, out)?;
                        } else {
                            let singers = std::mem::take(&mut self.signing);
                            let generator = SignGenerator::new(
                                &mut rng,
                                sign_typ,
                                literal_generator,
                                singers,
                                len,
                            )?;
                            let len = generator.len();
                            self.encryption.encrypt(&mut rng, generator, len, out)?;
                        }
                    }
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
                    mode: self.data_mode,
                    file_name,
                    created: Utc::now().trunc_subsecs(0),
                };

                let literal_generator = LiteralDataGenerator::new(
                    literal_data_header,
                    in_file,
                    Some(in_file_size.try_into()?),
                    self.chunk_size,
                )?;

                match self.compression {
                    Some(compression) => {
                        let len = literal_generator.len();
                        let generator = CompressedDataGenerator::new(
                            compression,
                            literal_generator,
                            len,
                            self.chunk_size,
                        )?;

                        if self.signing.is_empty() {
                            self.encryption.encrypt(&mut rng, generator, None, out)?;
                        } else {
                            let singers = std::mem::take(&mut self.signing);
                            let generator =
                                SignGenerator::new(&mut rng, sign_typ, generator, singers, None)?;
                            self.encryption.encrypt(&mut rng, generator, None, out)?;
                        }
                    }
                    None => {
                        let len = literal_generator.len();
                        if self.signing.is_empty() {
                            self.encryption
                                .encrypt(&mut rng, literal_generator, len, out)?;
                        } else {
                            let singers = std::mem::take(&mut self.signing);
                            let generator = SignGenerator::new(
                                &mut rng,
                                sign_typ,
                                literal_generator,
                                singers,
                                len,
                            )?;
                            let len = generator.len();
                            self.encryption.encrypt(&mut rng, generator, len, out)?;
                        }
                    }
                }
            }
            Source::Reader { file_name, reader } => {
                let literal_data_header = LiteralDataHeader {
                    mode: self.data_mode,
                    file_name,
                    created: Utc::now().trunc_subsecs(0),
                };

                let literal_generator =
                    LiteralDataGenerator::new(literal_data_header, reader, None, self.chunk_size)?;

                match self.compression {
                    Some(compression) => {
                        let len = literal_generator.len();
                        let generator = CompressedDataGenerator::new(
                            compression,
                            literal_generator,
                            len,
                            self.chunk_size,
                        )?;

                        if self.signing.is_empty() {
                            self.encryption.encrypt(&mut rng, generator, None, out)?;
                        } else {
                            let singers = std::mem::take(&mut self.signing);
                            let generator =
                                SignGenerator::new(&mut rng, sign_typ, generator, singers, None)?;
                            self.encryption.encrypt(&mut rng, generator, None, out)?;
                        }
                    }

                    None => {
                        let len = literal_generator.len();

                        if self.signing.is_empty() {
                            self.encryption
                                .encrypt(&mut rng, literal_generator, len, out)?;
                        } else {
                            let singers = std::mem::take(&mut self.signing);
                            let generator = SignGenerator::new(
                                &mut rng,
                                sign_typ,
                                literal_generator,
                                singers,
                                len,
                            )?;
                            let len = generator.len();
                            self.encryption.encrypt(&mut rng, generator, len, out)?;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Write the data not as binary, but ascii armor encoded.
    pub fn to_armored_writer<RAND, W>(
        self,
        rng: RAND,
        opts: ArmorOptions<'_>,
        mut out: W,
    ) -> Result<()>
    where
        RAND: Rng + CryptoRng,
        W: std::io::Write,
    {
        let typ = armor::BlockType::Message;

        // write header
        armor::write_header(&mut out, typ, opts.headers)?;

        // write body
        let mut crc_hasher = opts.include_checksum.then(Crc24Hasher::new);
        {
            let crc_hasher = crc_hasher.as_mut();
            let mut line_wrapper = LineWriter::<_, U64>::new(out.by_ref(), LineBreak::Lf);
            let mut enc = armor::Base64Encoder::new(&mut line_wrapper);

            if let Some(crc_hasher) = crc_hasher {
                let mut tee = TeeWriter::new(crc_hasher, &mut enc);
                self.to_writer(rng, &mut tee)?;
            } else {
                self.to_writer(rng, &mut enc)?;
            }
        }

        // write footer
        armor::write_footer(&mut out, typ, crc_hasher)?;
        out.flush()?;

        Ok(())
    }

    /// Write the data not as binary, but ascii armor encoded.
    pub fn to_armored_writer_signed<RAND, W>(
        self,
        rng: RAND,
        opts: ArmorOptions<'_>,
        mut out: W,
    ) -> Result<()>
    where
        RAND: Rng + CryptoRng,
        W: std::io::Write,
    {
        let typ = armor::BlockType::Message;

        // write header
        armor::write_header(&mut out, typ, opts.headers)?;

        // write body
        let mut crc_hasher = opts.include_checksum.then(Crc24Hasher::new);
        {
            let crc_hasher = crc_hasher.as_mut();
            let mut line_wrapper = LineWriter::<_, U64>::new(&mut out, LineBreak::Lf);
            let mut enc = armor::Base64Encoder::new(&mut line_wrapper);

            if let Some(crc_hasher) = crc_hasher {
                let mut tee = TeeWriter::new(crc_hasher, &mut enc);
                self.to_writer_signed(rng, &mut tee)?;
            } else {
                self.to_writer_signed(rng, &mut enc)?;
            }
        }

        // write footer
        armor::write_footer(&mut out, typ, crc_hasher)?;
        out.flush()?;

        Ok(())
    }

    /// Write the data out directly to a file.
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

    /// Write the data out directly to a file.
    pub fn to_armored_file<RAND, P>(
        self,
        rng: RAND,
        out_path: P,
        opts: ArmorOptions<'_>,
    ) -> Result<()>
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

        self.to_armored_writer(rng, opts, &mut out_file)?;

        out_file.flush()?;

        Ok(())
    }

    /// Write the data out directly to a file.
    pub fn to_file_signed<RAND, P>(self, rng: RAND, out_path: P) -> Result<()>
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

        self.to_writer_signed(rng, &mut out_file)?;

        out_file.flush()?;

        Ok(())
    }

    /// Write the data out directly to a file.
    pub fn to_armored_file_signed<RAND, P>(
        self,
        rng: RAND,
        out_path: P,
        opts: ArmorOptions<'_>,
    ) -> Result<()>
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

        self.to_armored_writer_signed(rng, opts, &mut out_file)?;

        out_file.flush()?;

        Ok(())
    }

    /// Write the data out directly to a `Vec<u8>`.
    pub fn to_vec<RAND>(self, rng: RAND) -> Result<Vec<u8>>
    where
        RAND: Rng + CryptoRng,
    {
        let mut out = Vec::new();
        self.to_writer(rng, &mut out)?;
        Ok(out)
    }

    /// Write the data as ascii armored data, directly to a `String`.
    pub fn to_armored_string<RAND>(self, rng: RAND, opts: ArmorOptions<'_>) -> Result<String>
    where
        RAND: Rng + CryptoRng,
    {
        let mut out = Vec::new();
        self.to_armored_writer(rng, opts, &mut out)?;
        let out = std::string::String::from_utf8(out).expect("ascii armor is utf8");
        Ok(out)
    }

    pub fn to_vec_signed<RAND>(self, rng: RAND) -> Result<Vec<u8>>
    where
        RAND: CryptoRng + Rng,
    {
        let mut out = Vec::new();
        self.to_writer_signed(rng, &mut out)?;
        Ok(out)
    }

    pub fn to_armored_string_signed<RAND>(self, rng: RAND, opts: ArmorOptions<'_>) -> Result<String>
    where
        RAND: CryptoRng + Rng,
    {
        let mut out = Vec::new();
        self.to_armored_writer_signed(rng, opts, &mut out)?;
        let out = std::string::String::from_utf8(out).expect("ascii armor is utf8");
        Ok(out)
    }
}

impl Encryption for NoEncryption {
    fn encrypt<R, READ, W>(
        self,
        _rng: R,
        mut generator: READ,
        _len: Option<u32>,
        mut out: W,
    ) -> Result<()>
    where
        R: Rng + CryptoRng,
        READ: std::io::Read,
        W: std::io::Write,
    {
        std::io::copy(&mut generator, &mut out)?;
        Ok(())
    }

    fn is_plaintext(&self) -> bool {
        true
    }
}

impl Encryption for EncryptionSeipdV1 {
    fn encrypt<R, READ, W>(
        self,
        rng: R,
        generator: READ,
        len: Option<u32>,
        mut out: W,
    ) -> Result<()>
    where
        R: Rng + CryptoRng,
        READ: std::io::Read,
        W: std::io::Write,
    {
        let EncryptionSeipdV1 {
            session_key,
            sym_esks,
            pub_esks,
            sym_alg,
        } = self;
        // Write out symmetric esks
        for sym_esk in sym_esks {
            let esk = Esk::SymKeyEncryptedSessionKey(sym_esk);
            esk.to_writer(&mut out)?;
        }
        // Write out public esks
        for pub_esk in pub_esks {
            let esk = Esk::PublicKeyEncryptedSessionKey(pub_esk);
            esk.to_writer(&mut out)?;
        }

        let config = SymEncryptedProtectedDataConfig::V1;
        let encrypted = sym_alg.stream_encryptor(rng, &session_key, generator)?;

        encrypt_write(
            Tag::SymEncryptedProtectedData,
            sym_alg,
            config,
            len,
            encrypted,
            out,
        )
    }

    fn is_plaintext(&self) -> bool {
        false
    }
}

impl Encryption for EncryptionSeipdV2 {
    fn encrypt<R, READ, W>(
        self,
        _rng: R,
        generator: READ,
        len: Option<u32>,
        mut out: W,
    ) -> Result<()>
    where
        R: Rng + CryptoRng,
        READ: std::io::Read,
        W: std::io::Write,
    {
        let EncryptionSeipdV2 {
            session_key,
            sym_esks,
            pub_esks,
            sym_alg,
            aead,
            chunk_size,
            salt,
        } = self;
        ensure_eq!(
            session_key.len(),
            sym_alg.key_size(),
            "Unexpected session key length for {:?}",
            sym_alg
        );

        // Write out symmetric esks
        for sym_esk in sym_esks {
            let esk = Esk::SymKeyEncryptedSessionKey(sym_esk);
            esk.to_writer(&mut out)?;
        }
        // Write out public esks
        for pub_esk in pub_esks {
            let esk = Esk::PublicKeyEncryptedSessionKey(pub_esk);
            esk.to_writer(&mut out)?;
        }
        let config = SymEncryptedProtectedDataConfig::V2 {
            sym_alg,
            aead,
            chunk_size,
            salt,
        };

        let encrypted = SymEncryptedProtectedData::encrypt_seipdv2_stream(
            sym_alg,
            aead,
            chunk_size,
            &session_key,
            salt,
            generator,
        )?;

        encrypt_write(
            Tag::SymEncryptedProtectedData,
            sym_alg,
            config,
            len,
            encrypted,
            out,
        )
    }

    fn is_plaintext(&self) -> bool {
        false
    }
}

fn encrypt_write<R: std::io::Read, W: std::io::Write>(
    tag: Tag,
    sym_alg: SymmetricKeyAlgorithm,
    config: SymEncryptedProtectedDataConfig,
    len: Option<u32>,
    mut encrypted: R,
    mut out: W,
) -> Result<()> {
    match len {
        None => {
            let chunk_size = DEFAULT_CHUNK_SIZE as usize;
            let config_len = config.write_len();

            // headers are written only in the first chunk
            // the partial length be a power of two, so subtract the overhead
            let first_chunk_size = chunk_size - config_len;

            let mut buffer = vec![0u8; chunk_size];

            let mut is_first = true;

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
                    let packet_header =
                        PacketHeader::from_parts(PacketHeaderVersion::New, tag, length)?;
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
                tag,
                PacketLength::Fixed(packet_len),
            )?;
            packet_header.to_writer(&mut out)?;
            config.to_writer(&mut out)?;

            std::io::copy(&mut encrypted, &mut out)?;
        }
    }

    Ok(())
}

struct TeeManyWriter<'a, 'b, A> {
    writer: &'a mut A,
    hashers: &'b mut [SignatureHasher],
}

impl<'a, 'b, A> TeeManyWriter<'a, 'b, A> {
    fn new(writer: &'a mut A, hashers: &'b mut [SignatureHasher]) -> Self {
        Self { writer, hashers }
    }
}

impl<A: std::io::Write> std::io::Write for TeeManyWriter<'_, '_, A> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let written = self.writer.write(buf)?;

        for hasher in self.hashers.iter_mut() {
            hasher.write(&buf[..written])?;
        }
        Ok(written)
    }

    // custom impl, to work around Base64Encoder returning Ok(0) from write
    fn write_all(&mut self, mut buf: &[u8]) -> std::io::Result<()> {
        while !buf.is_empty() {
            match self.write(buf) {
                Ok(0) => {}
                Ok(n) => buf = &buf[n..],
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()?;
        for hasher in self.hashers.iter_mut() {
            hasher.flush()?;
        }

        Ok(())
    }
}

struct SignGenerator<'a, R> {
    typ: SignatureType,
    signers: Vec<SigningConfig<'a>>,
    hashers: Vec<SignatureHasher>,
    source: R,
    total_len: Option<u32>,
    state: State,
    /// Finished reading from the source?
    source_done: bool,
}

enum State {
    /// Buffer a single OPS
    Ops {
        ops: Vec<OnePassSignature>,
        buffer: BytesMut,
    },
    /// Pass through the source,
    /// sending the data to the hashers as well
    Body,
    /// Buffer a single Signature
    Signatures { buffer: BytesMut },
}

impl<'a, R> SignGenerator<'a, R> {
    fn new<RAND>(
        mut rng: RAND,
        typ: SignatureType,
        source: R,
        signers: Vec<SigningConfig<'a>>,
        len: Option<u32>,
    ) -> Result<Self>
    where
        RAND: CryptoRng + Rng,
    {
        let prep = prepare(&mut rng, typ, &signers)?;
        let mut hashers = Vec::with_capacity(prep.len());
        let mut ops = Vec::with_capacity(prep.len());
        for (config, op) in prep.into_iter() {
            ops.push(op);
            hashers.push(config.into_hasher()?);
        }

        let total_len = len.map(|l| {
            // calculate final length
            todo!()
        });

        Ok(Self {
            typ,
            signers,
            source,
            hashers,
            total_len,
            source_done: false,
            state: State::Ops {
                ops,
                buffer: BytesMut::new(),
            },
        })
    }

    /// Returns the expected write length if known upfront.
    fn len(&self) -> Option<u32> {
        self.total_len
    }
}

impl<R: std::io::Read> std::io::Read for SignGenerator<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use testresult::TestResult;

    use crate::crypto::sym::SymmetricKeyAlgorithm;
    use crate::line_writer::LineBreak;
    use crate::normalize_lines::normalize_lines;
    use crate::util::test::{check_strings, random_string, ChaosReader};
    use crate::{Deserializable, Message, SignedSecretKey};

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
        let s2k = crate::types::StringToKey::new_iterated(&mut rng, Default::default(), 2);

        let builder = Builder::from_file(&plaintext_file)
            .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES128)
            .encrypt_with_password(s2k, &"hello world".into())
            .unwrap();

        builder.to_file(&mut rng, &encrypted_file).unwrap();

        // decrypt it
        let encrypted_file_data = std::fs::read(&encrypted_file).unwrap();
        let message = Message::from_bytes(encrypted_file_data.into()).unwrap();

        let decrypted = message
            .decrypt_with_password(&"hello world".into())
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
        let s2k = crate::types::StringToKey::new_iterated(&mut rng, Default::default(), 2);

        let builder = Builder::<DummyReader>::from_bytes("plaintext.txt", buf.clone())
            .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES128)
            .encrypt_with_password(s2k, &"hello world".into())
            .unwrap();

        let encrypted = builder.to_vec(&mut rng).unwrap();

        // decrypt it
        let message = Message::from_bytes(encrypted.into()).unwrap();
        dbg!(&message);
        let decrypted = message
            .decrypt_with_password(&"hello world".into())
            .unwrap();

        let Message::Literal(l) = decrypted else {
            panic!("unexpected message: {:?}", decrypted);
        };

        assert_eq!(l.file_name(), "plaintext.txt");
        assert_eq!(l.data(), &buf);
    }

    #[test]
    fn binary_reader_partial_size_no_compression_roundtrip_password_seipdv1() {
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
            let s2k = crate::types::StringToKey::new_iterated(&mut rng, Default::default(), 2);

            let builder = Builder::from_reader("plaintext.txt", &buf[..])
                .chunk_size(chunk_size)
                .unwrap()
                .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES128)
                .encrypt_with_password(s2k, &"hello world".into())
                .expect("encryption");

            let encrypted = builder.to_vec(&mut rng).expect("writing");

            // decrypt it
            let message = Message::from_bytes(encrypted.into()).expect("reading");
            let decrypted = message
                .decrypt_with_password(&"hello world".into())
                .expect("decryption");

            let Message::Literal(l) = decrypted else {
                panic!("unexpected message: {:?}", decrypted);
            };

            assert_eq!(l.file_name(), "plaintext.txt");
            assert_eq!(l.data(), &buf);
        }
    }

    #[test]
    fn binary_reader_partial_size_no_compression_roundtrip_no_encryption() {
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
                .unwrap();

            let encoded = builder.to_vec(&mut rng).expect("writing");

            // decrypt it
            let message = Message::from_bytes(encoded.into()).expect("reading");

            let Message::Literal(l) = message else {
                panic!("unexpected message: {:?}", message);
            };

            assert_eq!(l.file_name(), "plaintext.txt");
            assert_eq!(l.data(), &buf);
        }
    }

    #[test]
    fn binary_reader_partial_size_no_compression_roundtrip_public_key_x25519_seipdv1() {
        let _ = pretty_env_logger::try_init();
        let mut rng = ChaCha20Rng::seed_from_u64(1);

        let (skey, _headers) = SignedSecretKey::from_armor_single(
            std::fs::File::open("./tests/autocrypt/alice@autocrypt.example.sec.asc").unwrap(),
        )
        .unwrap();
        // subkey[0] is the encryption key
        let pkey = skey.secret_subkeys[0].public_key();

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
                .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES128)
                .encrypt_to_key(&mut rng, &pkey)
                .expect("encryption");

            let encrypted = builder.to_vec(&mut rng).expect("writing");

            // decrypt it
            let message = Message::from_bytes(encrypted.into()).expect("reading");
            let (decrypted, _key_ids) = message
                .decrypt(&[Password::empty()], &[&skey])
                .expect("decryption");

            let Message::Literal(l) = decrypted else {
                panic!("unexpected message: {:?}", decrypted);
            };

            assert_eq!(l.file_name(), "plaintext.txt");
            assert_eq!(l.data(), &buf);
        }
    }

    #[test]
    fn binary_reader_partial_size_no_compression_roundtrip_public_key_x25519_and_password_seipdv1()
    {
        let _ = pretty_env_logger::try_init();
        let mut rng = ChaCha20Rng::seed_from_u64(1);

        let (skey, _headers) = SignedSecretKey::from_armor_single(
            std::fs::File::open("./tests/autocrypt/alice@autocrypt.example.sec.asc").unwrap(),
        )
        .unwrap();
        // subkey[0] is the encryption key
        let pkey = skey.secret_subkeys[0].public_key();

        let chunk_size = 512u32;
        let max_file_size = 5 * chunk_size as usize + 100;

        for file_size in (1..=max_file_size).step_by(10) {
            println!("Size {}", file_size);

            // Generate data
            let mut buf = vec![0u8; file_size];
            rng.fill(&mut buf[..]);

            let s2k = crate::types::StringToKey::new_iterated(&mut rng, Default::default(), 2);

            let builder = Builder::from_reader("plaintext.txt", &buf[..])
                .chunk_size(chunk_size)
                .unwrap()
                .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES128)
                .encrypt_to_key(&mut rng, &pkey)
                .expect("encryption")
                .encrypt_with_password(s2k, &"hello world".into())
                .expect("encryption sym");

            let encrypted = builder.to_vec(&mut rng).expect("writing");

            let message = Message::from_bytes(encrypted.into()).expect("reading");

            // decrypt it - public
            {
                let (decrypted, _key_ids) =
                    message.decrypt(&["".into()], &[&skey]).expect("decryption");

                let Message::Literal(l) = decrypted else {
                    panic!("unexpected message: {:?}", decrypted);
                };

                assert_eq!(l.file_name(), "plaintext.txt");
                assert_eq!(l.data(), &buf);
            }
            // decrypt it - password
            {
                let decrypted = message
                    .decrypt_with_password(&"hello world".into())
                    .expect("decryption sym");

                let Message::Literal(l) = decrypted else {
                    panic!("unexpected message: {:?}", decrypted);
                };

                assert_eq!(l.file_name(), "plaintext.txt");
                assert_eq!(l.data(), &buf);
            }
        }
    }

    #[test]
    fn utf8_reader_partial_size_no_compression_roundtrip_no_encryption() {
        let _ = pretty_env_logger::try_init();
        let mut rng = ChaCha20Rng::seed_from_u64(1);

        let chunk_size = 512u32;
        let max_file_size = 5 * chunk_size as usize + 100;

        for file_size in (1..=max_file_size).step_by(10) {
            println!("Size {}", file_size);

            // Generate data
            let buf = random_string(&mut rng, file_size);
            let mut reader = ChaosReader::new(rng.clone(), buf.clone());

            let builder = Builder::from_reader("plaintext.txt", &mut reader)
                .data_mode(DataMode::Utf8)
                .chunk_size(chunk_size)
                .unwrap();

            let encoded = builder.to_vec(&mut rng).expect("writing");

            // decrypt it
            let message = Message::from_bytes(encoded.into()).expect("reading");

            let Message::Literal(l) = message else {
                panic!("unexpected message: {:?}", message);
            };

            assert_eq!(l.file_name(), "plaintext.txt");
            check_strings(
                l.to_string().unwrap(),
                normalize_lines(&buf, LineBreak::Crlf),
            );
        }
    }

    #[test]
    fn utf8_reader_partial_size_no_compression_roundtrip_public_key_x25519_seipdv1() {
        let _ = pretty_env_logger::try_init();
        let mut rng = ChaCha20Rng::seed_from_u64(1);

        let (skey, _headers) = SignedSecretKey::from_armor_single(
            std::fs::File::open("./tests/autocrypt/alice@autocrypt.example.sec.asc").unwrap(),
        )
        .unwrap();
        // subkey[0] is the encryption key
        let pkey = skey.secret_subkeys[0].public_key();

        let chunk_size = 512u32;
        let max_file_size = 5 * chunk_size as usize + 100;

        for file_size in (1..=max_file_size).step_by(10) {
            println!("Size {}", file_size);

            // Generate data
            let buf = random_string(&mut rng, file_size);
            let mut reader = ChaosReader::new(rng.clone(), buf.clone());

            let builder = Builder::from_reader("plaintext.txt", &mut reader)
                .data_mode(DataMode::Utf8)
                .chunk_size(chunk_size)
                .unwrap()
                .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES128)
                .encrypt_to_key(&mut rng, &pkey)
                .expect("encryption");

            let encrypted = builder.to_vec(&mut rng).expect("writing");

            // decrypt it
            let message = Message::from_bytes(encrypted.into()).expect("reading");
            let (decrypted, _key_ids) =
                message.decrypt(&["".into()], &[&skey]).expect("decryption");

            let Message::Literal(l) = decrypted else {
                panic!("unexpected message: {:?}", decrypted);
            };

            assert_eq!(l.file_name(), "plaintext.txt");
            check_strings(
                l.to_string().unwrap(),
                normalize_lines(&buf, LineBreak::Crlf),
            );
        }
    }

    #[test]
    fn utf8_reader_partial_size_compression_zip_roundtrip_public_key_x25519_seipdv1() {
        let _ = pretty_env_logger::try_init();
        let mut rng = ChaCha20Rng::seed_from_u64(1);

        let (skey, _headers) = SignedSecretKey::from_armor_single(
            std::fs::File::open("./tests/autocrypt/alice@autocrypt.example.sec.asc").unwrap(),
        )
        .unwrap();
        // subkey[0] is the encryption key
        let pkey = skey.secret_subkeys[0].public_key();

        let chunk_size = 512u32;
        let max_file_size = 5 * chunk_size as usize + 100;

        for file_size in (1..=max_file_size).step_by(10) {
            println!("Size {}", file_size);

            // Generate data
            let buf = random_string(&mut rng, file_size);
            let mut reader = ChaosReader::new(rng.clone(), buf.clone());

            let builder = Builder::from_reader("plaintext.txt", &mut reader)
                .data_mode(DataMode::Utf8)
                .compression(CompressionAlgorithm::ZIP)
                .chunk_size(chunk_size)
                .unwrap()
                .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES128)
                .encrypt_to_key(&mut rng, &pkey)
                .expect("encryption");

            let encrypted = builder.to_vec(&mut rng).expect("writing");

            // decrypt it
            let message = Message::from_bytes(encrypted.into()).expect("reading");
            let (decrypted, _key_ids) = message
                .decrypt(&[Password::empty()], &[&skey])
                .expect("decryption");

            assert!(matches!(decrypted, Message::Compressed(_)));

            let decompressed = decrypted.decompress().expect("decompression");

            let Message::Literal(l) = decompressed else {
                panic!("unexpected message: {:?}", decompressed);
            };

            assert_eq!(l.file_name(), "plaintext.txt");
            check_strings(
                l.to_string().unwrap(),
                normalize_lines(&buf, LineBreak::Crlf),
            );
        }
    }

    #[test]
    fn utf8_reader_partial_size_compression_zip_roundtrip_public_key_x25519_seipdv1_sign() {
        let _ = pretty_env_logger::try_init();
        let mut rng = ChaCha20Rng::seed_from_u64(1);

        let (skey, _headers) = SignedSecretKey::from_armor_single(
            std::fs::File::open("./tests/autocrypt/alice@autocrypt.example.sec.asc").unwrap(),
        )
        .unwrap();
        // subkey[0] is the encryption key
        let pkey = skey.secret_subkeys[0].public_key();

        let chunk_size = 512u32;
        let max_file_size = 5 * chunk_size as usize + 100;

        for file_size in (1..=max_file_size).step_by(10) {
            println!("Size {}", file_size);

            // Generate data
            let buf = random_string(&mut rng, file_size);
            let mut reader = ChaosReader::new(rng.clone(), buf.clone());

            let builder = Builder::from_reader("plaintext.txt", &mut reader)
                .data_mode(DataMode::Utf8)
                .compression(CompressionAlgorithm::ZIP)
                .chunk_size(chunk_size)
                .unwrap()
                .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES128)
                .encrypt_to_key(&mut rng, &pkey)
                .expect("encryption");

            let sig_config = SigningConfig::new(&*skey, Password::empty(), HashAlgorithm::Sha256);

            let encrypted = builder
                .sign(sig_config)
                .to_vec_signed(&mut rng)
                .expect("writing");

            let message = Message::from_bytes(encrypted.into()).expect("reading");

            // verify signature
            assert!(message.is_one_pass_signed());
            message.verify(&*skey.public_key()).expect("signed");

            // decrypt it
            let (decrypted, _key_ids) = message
                .decrypt(&[Password::empty()], &[&skey])
                .expect("decryption");

            assert!(matches!(decrypted, Message::Compressed(_)));

            let decompressed = decrypted.decompress().expect("decompression");

            let Message::Literal(l) = decompressed else {
                panic!("unexpected message: {:?}", decompressed);
            };

            assert_eq!(l.file_name(), "plaintext.txt");
            check_strings(
                l.to_string().unwrap(),
                normalize_lines(&buf, LineBreak::Crlf),
            );
        }
    }

    #[test]
    fn binary_reader_partial_size_no_compression_roundtrip_password_seipdv2() {
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
            let s2k = crate::types::StringToKey::new_iterated(&mut rng, Default::default(), 2);

            let builder = Builder::from_reader("plaintext.txt", &buf[..])
                .chunk_size(chunk_size)
                .unwrap()
                .seipd_v2(
                    &mut rng,
                    SymmetricKeyAlgorithm::AES128,
                    AeadAlgorithm::Gcm,
                    ChunkSize::default(),
                )
                .encrypt_with_password(&mut rng, s2k, &"hello world".into())
                .expect("encryption");

            let encrypted = builder.to_vec(&mut rng).expect("writing");

            // decrypt it
            let message = Message::from_bytes(encrypted.into()).expect("reading");
            let decrypted = message
                .decrypt_with_password(&"hello world".into())
                .expect("decryption");

            let Message::Literal(l) = decrypted else {
                panic!("unexpected message: {:?}", decrypted);
            };

            assert_eq!(l.file_name(), "plaintext.txt");
            assert_eq!(l.data(), &buf);
        }
    }

    #[test]
    fn utf8_reader_partial_size_compression_zip_roundtrip_public_key_x25519_seipdv2_sign_once() {
        let _ = pretty_env_logger::try_init();
        let mut rng = ChaCha20Rng::seed_from_u64(1);

        let (skey, _headers) = SignedSecretKey::from_armor_single(
            std::fs::File::open("./tests/autocrypt/alice@autocrypt.example.sec.asc").unwrap(),
        )
        .unwrap();

        // subkey[0] is the encryption key
        let pkey = skey.secret_subkeys[0].public_key();

        let chunk_size = 512u32;
        let max_file_size = 5 * chunk_size as usize + 100;

        for file_size in (1..=max_file_size).step_by(10) {
            println!("Size {}", file_size);

            // Generate data
            let buf = random_string(&mut rng, file_size);
            let mut reader = ChaosReader::new(rng.clone(), buf.clone());

            let builder = Builder::from_reader("plaintext.txt", &mut reader)
                .data_mode(DataMode::Utf8)
                .compression(CompressionAlgorithm::ZIP)
                .chunk_size(chunk_size)
                .unwrap()
                .seipd_v2(
                    &mut rng,
                    SymmetricKeyAlgorithm::AES128,
                    AeadAlgorithm::Gcm,
                    ChunkSize::default(),
                )
                .encrypt_to_key(&mut rng, &pkey)
                .expect("encryption");

            let sig_config = SigningConfig::new(&*skey, Password::empty(), HashAlgorithm::Sha256);

            let encrypted = builder
                .sign(sig_config)
                .to_vec_signed(&mut rng)
                .expect("writing");

            let message = Message::from_bytes(encrypted.into()).expect("reading");

            // verify signature
            assert!(message.is_one_pass_signed());
            message.verify(&*skey.public_key()).expect("signed");

            // decrypt it
            let (decrypted, _key_ids) = message
                .decrypt(&[Password::empty()], &[&skey])
                .expect("decryption");

            assert!(matches!(decrypted, Message::Compressed(_)));

            let decompressed = decrypted.decompress().expect("decompression");

            let Message::Literal(l) = decompressed else {
                panic!("unexpected message: {:?}", decompressed);
            };

            assert_eq!(l.file_name(), "plaintext.txt");
            check_strings(
                l.to_string().unwrap(),
                normalize_lines(&buf, LineBreak::Crlf),
            );
        }
    }

    #[derive(Debug)]
    enum Encoding<'a> {
        Binary,
        Armor(ArmorOptions<'a>),
    }

    #[test]
    fn utf8_reader_partial_size_compression_zip_roundtrip_public_key_x25519_seipdv2_sign_twice(
    ) -> TestResult {
        let _ = pretty_env_logger::try_init();
        let mut rng = ChaCha20Rng::seed_from_u64(1);

        let (skey1, _headers) = SignedSecretKey::from_armor_single(std::fs::File::open(
            "./tests/autocrypt/alice@autocrypt.example.sec.asc",
        )?)?;

        // subkey[0] is the encryption key
        let pkey1 = skey1.secret_subkeys[0].public_key();

        let (skey2, _headers) = SignedSecretKey::from_armor_single(std::fs::File::open(
            "./tests/autocrypt/bob@autocrypt.example.sec.asc",
        )?)?;

        let chunk_size = 512u32;
        let max_file_size = 5 * chunk_size as usize + 100;

        for file_size in (1..=max_file_size).step_by(10) {
            for encoding in [
                Encoding::Binary,
                Encoding::Armor(ArmorOptions {
                    headers: None,
                    include_checksum: true,
                }),
                Encoding::Armor(ArmorOptions {
                    headers: None,
                    include_checksum: false,
                }),
            ] {
                println!("-- Size: {} encoding: {:?}", file_size, encoding);

                // Generate data
                let buf = random_string(&mut rng, file_size);
                let mut reader = ChaosReader::new(rng.clone(), buf.clone());

                let builder = Builder::from_reader("plaintext.txt", &mut reader)
                    .data_mode(DataMode::Utf8)
                    .compression(CompressionAlgorithm::ZIP)
                    .chunk_size(chunk_size)?
                    .seipd_v2(
                        &mut rng,
                        SymmetricKeyAlgorithm::AES128,
                        AeadAlgorithm::Gcm,
                        ChunkSize::default(),
                    )
                    .encrypt_to_key(&mut rng, &pkey1)?
                    .sign(SigningConfig::new(
                        &*skey1,
                        Password::empty(),
                        HashAlgorithm::Sha256,
                    ))
                    .sign(SigningConfig::new(
                        &*skey2,
                        Password::empty(),
                        HashAlgorithm::Sha512,
                    ));

                let message = match encoding {
                    Encoding::Armor(opts) => {
                        let encrypted = builder.to_armored_string_signed(&mut rng, opts)?;

                        println!("{}", encrypted);

                        let (message, _) = Message::from_armor_single(encrypted.as_bytes())?;
                        message
                    }
                    Encoding::Binary => {
                        let encrypted = builder.to_vec_signed(&mut rng)?;

                        println!("{}", hex::encode(&encrypted));
                        Message::from_bytes(encrypted.into())?
                    }
                };

                // verify signature outer
                assert!(message.is_one_pass_signed());
                message.verify(&*skey1.public_key())?;

                // verify inner signature
                match message {
                    Message::Signed { ref message, .. } => {
                        let message = message.as_ref().unwrap();
                        assert!(message.is_one_pass_signed());
                        message.verify(&*skey2.public_key())?;
                    }
                    _ => {
                        panic!("invalid structure: {:?}", message);
                    }
                };

                // decrypt it
                let (decrypted, _key_ids) = message.decrypt(&[Password::empty()], &[&skey1])?;

                assert!(matches!(decrypted, Message::Compressed(_)));

                let decompressed = decrypted.decompress()?;

                let Message::Literal(l) = decompressed else {
                    panic!("unexpected message: {:?}", decompressed);
                };

                assert_eq!(l.file_name(), "plaintext.txt");
                check_strings(
                    l.to_string().unwrap(),
                    normalize_lines(&buf, LineBreak::Crlf),
                );
            }
        }
        Ok(())
    }
}

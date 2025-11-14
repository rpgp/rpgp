use aes::{Aes128, Aes192, Aes256};
use blowfish::Blowfish;
use bytes::{Buf, Bytes, BytesMut};
use camellia::{Camellia128, Camellia192, Camellia256};
use cast5::Cast5;
use cfb_mode::{cipher::KeyIvInit, BufEncryptor};
use cipher::{BlockCipherEncrypt, BlockSizeUser};
use des::TdesEde3;
use idea::Idea;
use log::debug;
use rand::{CryptoRng, RngCore};
use sha1::{Digest, Sha1};
use twofish::Twofish;

use crate::{
    crypto::sym::SymmetricKeyAlgorithm,
    errors::{bail, unsupported_err, Result},
    util::fill_buffer,
};

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum StreamEncryptor<R>
where
    R: std::io::Read,
{
    Idea(StreamEncryptorInner<Idea, R>),
    TripleDes(StreamEncryptorInner<TdesEde3, R>),
    Cast5(StreamEncryptorInner<Cast5, R>),
    Blowfish(StreamEncryptorInner<Blowfish, R>),
    Aes128(StreamEncryptorInner<Aes128, R>),
    Aes192(StreamEncryptorInner<Aes192, R>),
    Aes256(StreamEncryptorInner<Aes256, R>),
    Twofish(StreamEncryptorInner<Twofish, R>),
    Camellia128(StreamEncryptorInner<Camellia128, R>),
    Camellia192(StreamEncryptorInner<Camellia192, R>),
    Camellia256(StreamEncryptorInner<Camellia256, R>),
}

impl<R: std::io::Read> StreamEncryptor<R> {
    pub fn new<B: RngCore + CryptoRng + ?Sized>(
        rng: &mut B,
        alg: SymmetricKeyAlgorithm,
        key: &[u8],
        plaintext: R,
    ) -> Result<Self> {
        match alg {
            SymmetricKeyAlgorithm::Plaintext => {
                bail!("'Plaintext' is not a legal cipher for encrypted data")
            }
            SymmetricKeyAlgorithm::IDEA => Ok(StreamEncryptor::Idea(StreamEncryptorInner::new(
                rng, plaintext, key,
            )?)),
            SymmetricKeyAlgorithm::TripleDES => Ok(StreamEncryptor::TripleDes(
                StreamEncryptorInner::new(rng, plaintext, key)?,
            )),
            SymmetricKeyAlgorithm::CAST5 => Ok(StreamEncryptor::Cast5(StreamEncryptorInner::new(
                rng, plaintext, key,
            )?)),
            SymmetricKeyAlgorithm::Blowfish => Ok(StreamEncryptor::Blowfish(
                StreamEncryptorInner::new(rng, plaintext, key)?,
            )),
            SymmetricKeyAlgorithm::AES128 => Ok(StreamEncryptor::Aes128(
                StreamEncryptorInner::new(rng, plaintext, key)?,
            )),
            SymmetricKeyAlgorithm::AES192 => Ok(StreamEncryptor::Aes192(
                StreamEncryptorInner::new(rng, plaintext, key)?,
            )),
            SymmetricKeyAlgorithm::AES256 => Ok(StreamEncryptor::Aes256(
                StreamEncryptorInner::new(rng, plaintext, key)?,
            )),
            SymmetricKeyAlgorithm::Twofish => Ok(StreamEncryptor::Twofish(
                StreamEncryptorInner::new(rng, plaintext, key)?,
            )),
            SymmetricKeyAlgorithm::Camellia128 => Ok(StreamEncryptor::Camellia128(
                StreamEncryptorInner::new(rng, plaintext, key)?,
            )),
            SymmetricKeyAlgorithm::Camellia192 => Ok(StreamEncryptor::Camellia192(
                StreamEncryptorInner::new(rng, plaintext, key)?,
            )),
            SymmetricKeyAlgorithm::Camellia256 => Ok(StreamEncryptor::Camellia256(
                StreamEncryptorInner::new(rng, plaintext, key)?,
            )),
            SymmetricKeyAlgorithm::Private10 | SymmetricKeyAlgorithm::Other(_) => {
                unsupported_err!("SymmetricKeyAlgorithm {:?}")
            }
        }
    }
}

impl<R> std::io::Read for StreamEncryptor<R>
where
    R: std::io::Read,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Idea(ref mut i) => i.read(buf),
            Self::TripleDes(ref mut i) => i.read(buf),
            Self::Cast5(ref mut i) => i.read(buf),
            Self::Blowfish(ref mut i) => i.read(buf),
            Self::Aes128(ref mut i) => i.read(buf),
            Self::Aes192(ref mut i) => i.read(buf),
            Self::Aes256(ref mut i) => i.read(buf),
            Self::Twofish(ref mut i) => i.read(buf),
            Self::Camellia128(ref mut i) => i.read(buf),
            Self::Camellia192(ref mut i) => i.read(buf),
            Self::Camellia256(ref mut i) => i.read(buf),
        }
    }

    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> std::io::Result<usize> {
        match self {
            Self::Idea(ref mut i) => i.read_to_end(buf),
            Self::TripleDes(ref mut i) => i.read_to_end(buf),
            Self::Cast5(ref mut i) => i.read_to_end(buf),
            Self::Blowfish(ref mut i) => i.read_to_end(buf),
            Self::Aes128(ref mut i) => i.read_to_end(buf),
            Self::Aes192(ref mut i) => i.read_to_end(buf),
            Self::Aes256(ref mut i) => i.read_to_end(buf),
            Self::Twofish(ref mut i) => i.read_to_end(buf),
            Self::Camellia128(ref mut i) => i.read_to_end(buf),
            Self::Camellia192(ref mut i) => i.read_to_end(buf),
            Self::Camellia256(ref mut i) => i.read_to_end(buf),
        }
    }
}

#[derive(derive_more::Debug)]
pub enum StreamEncryptorInner<M, R>
where
    M: BlockCipherEncrypt,
    BufEncryptor<M>: KeyIvInit,
    R: std::io::Read,
{
    Prefix {
        // We use regular sha1 for MDC, not sha1_checked. Collisions are not currently a concern with MDC.
        hasher: Sha1,
        #[debug("BufEncryptor")]
        encryptor: BufEncryptor<M>,
        prefix: Bytes,
        source: R,
    },
    Data {
        hasher: Sha1,
        #[debug("BufEncryptor")]
        encryptor: BufEncryptor<M>,
        buffer: BytesMut,
        /// set to `None` once the source is fully read
        source: Option<R>,
    },
    Mdc {
        mdc: Bytes,
    },
    Done,
    Unknown,
}

impl<M, R> StreamEncryptorInner<M, R>
where
    M: BlockCipherEncrypt,
    BufEncryptor<M>: KeyIvInit,
    R: std::io::Read,
{
    fn new<RAND>(rng: &mut RAND, source: R, key: &[u8]) -> Result<Self>
    where
        RAND: RngCore + CryptoRng + ?Sized,
    {
        debug!("protected encrypt stream");

        let bs = <M as BlockSizeUser>::block_size();
        let mut prefix = vec![0u8; bs + 2];

        // prefix
        rng.fill_bytes(&mut prefix[..bs]);

        // add quick check
        prefix[bs] = prefix[bs - 2];
        prefix[bs + 1] = prefix[bs - 1];

        // checksum over unencrypted data
        let mut hasher = Sha1::default();

        // IV is all zeroes
        let iv_vec = vec![0u8; bs];

        let mut encryptor = BufEncryptor::<M>::new_from_slices(key, &iv_vec)?;

        // pre ingest prefix and encrypt it
        hasher.update(&prefix);
        encryptor.encrypt(&mut prefix);

        Ok(Self::Prefix {
            hasher,
            encryptor,
            prefix: prefix.into(),
            source,
        })
    }

    fn buffer_size() -> usize {
        8 * 1024
    }

    fn fill_inner(&mut self) -> std::io::Result<()> {
        match self {
            Self::Prefix { prefix, .. } => {
                if prefix.has_remaining() {
                    return Ok(());
                }
            }
            Self::Data {
                hasher,
                encryptor,
                buffer,
                source,
            } => {
                if buffer.has_remaining() {
                    return Ok(());
                }
                // needs filling
                let mdc = if let Some(source) = source {
                    // fill buffer
                    // TODO: require source to be a BufRead
                    // let read = fill_buffer_bytes(source, buffer, Self::buffer_size())?;
                    buffer.resize(Self::buffer_size(), 0);
                    let read = fill_buffer(source, buffer, None)?;
                    if read < buffer.len() {
                        // done reading
                        // shorten buffer accordingly
                        buffer.truncate(read);
                    }
                    if buffer.is_empty() {
                        // nothing left
                        true
                    } else {
                        // encrypt it
                        hasher.update(&buffer);
                        encryptor.encrypt(buffer);
                        false
                    }
                } else {
                    true
                };

                if !mdc {
                    return Ok(());
                }
            }
            Self::Mdc { mdc } => {
                if mdc.has_remaining() {
                    return Ok(());
                }
            }
            Self::Done => {
                return Ok(());
            }
            Self::Unknown => {
                panic!("encryption panicked");
            }
        };

        match std::mem::replace(self, Self::Unknown) {
            Self::Prefix {
                mut hasher,
                mut encryptor,
                mut source,
                ..
            } => {
                // prefix written, transition to data
                let mut buffer = BytesMut::zeroed(Self::buffer_size());

                // fill buffer
                let read = fill_buffer(&mut source, &mut buffer, None)?;
                let source = if read < buffer.len() {
                    // done reading
                    // shorten buffer accordingly
                    buffer.truncate(read);
                    None
                } else {
                    Some(source)
                };

                // encrypt it
                hasher.update(&buffer);
                encryptor.encrypt(&mut buffer);

                *self = Self::Data {
                    hasher,
                    encryptor,
                    buffer,
                    source,
                };
            }
            Self::Data {
                mut hasher,
                mut encryptor,
                ..
            } => {
                // source is fully read, move on to Mdc
                // mdc header
                let mdc_header = [0xD3, 0x14];
                hasher.update(mdc_header);

                let mut mdc = BytesMut::zeroed(22);
                mdc[..2].copy_from_slice(&mdc_header);

                // mdc body
                let checksum = &hasher.finalize()[..20];
                mdc[2..22].copy_from_slice(checksum);

                encryptor.encrypt(&mut mdc[..]);
                *self = Self::Mdc { mdc: mdc.freeze() };
            }
            Self::Mdc { .. } => {
                *self = Self::Done;
            }
            Self::Done => {}
            Self::Unknown => {
                panic!("encryption panicked");
            }
        }
        Ok(())
    }
}

impl<M, R> std::io::Read for StreamEncryptorInner<M, R>
where
    M: BlockCipherEncrypt,
    BufEncryptor<M>: KeyIvInit,
    R: std::io::Read,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.fill_inner()?;
        match self {
            Self::Prefix { prefix, .. } => {
                // Prefix
                let to_write = buf.len().min(prefix.remaining());
                prefix.copy_to_slice(&mut buf[..to_write]);
                Ok(to_write)
            }
            Self::Data { buffer, .. } => {
                let to_write = buf.len().min(buffer.remaining());
                buffer.copy_to_slice(&mut buf[..to_write]);
                Ok(to_write)
            }
            Self::Mdc { mdc } => {
                let to_write = buf.len().min(mdc.remaining());
                mdc.copy_to_slice(&mut buf[..to_write]);
                Ok(to_write)
            }
            Self::Done => Ok(0),
            Self::Unknown => unreachable!("error state"),
        }
    }

    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> std::io::Result<usize> {
        let mut read = 0;
        loop {
            self.fill_inner()?;
            match self {
                Self::Prefix { prefix, .. } => {
                    // Prefix
                    let to_write = prefix.remaining();
                    buf.extend_from_slice(&prefix[..to_write]);
                    prefix.advance(to_write);
                    read += to_write;
                }
                Self::Data { buffer, .. } => {
                    let to_write = buffer.remaining();
                    buf.extend_from_slice(&buffer[..to_write]);
                    buffer.advance(to_write);
                    read += to_write;
                }
                Self::Mdc { mdc } => {
                    let to_write = mdc.remaining();
                    buf.extend_from_slice(&mdc[..to_write]);
                    mdc.advance(to_write);
                    read += to_write;
                }
                Self::Done => {
                    break;
                }
                Self::Unknown => unreachable!("error state"),
            }
        }

        Ok(read)
    }
}

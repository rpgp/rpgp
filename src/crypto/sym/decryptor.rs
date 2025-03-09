use std::io::{self, BufRead, Read};

use aes::{Aes128, Aes192, Aes256};
use blowfish::Blowfish;
use bytes::{Buf, BytesMut};
use camellia::{Camellia128, Camellia192, Camellia256};
use cast5::Cast5;
use cfb_mode::cipher::KeyIvInit;
use cfb_mode::BufDecryptor;
use cipher::{BlockCipher, BlockDecrypt, BlockEncryptMut, BlockSizeUser};
use des::TdesEde3;
use idea::Idea;
use log::debug;
use sha1::{Digest, Sha1};
use twofish::Twofish;

use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::errors::Result;
use crate::util::fill_buffer;

const MDC_LEN: usize = 22;
const BUFFER_SIZE: usize = 512;

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum StreamDecryptor<R>
where
    R: BufRead,
{
    Idea(StreamDecryptorInner<Idea, R>),
    TripleDes(StreamDecryptorInner<TdesEde3, R>),
    Cast5(StreamDecryptorInner<Cast5, R>),
    Blowfish(StreamDecryptorInner<Blowfish, R>),
    Aes128(StreamDecryptorInner<Aes128, R>),
    Aes192(StreamDecryptorInner<Aes192, R>),
    Aes256(StreamDecryptorInner<Aes256, R>),
    Twofish(StreamDecryptorInner<Twofish, R>),
    Camellia128(StreamDecryptorInner<Camellia128, R>),
    Camellia192(StreamDecryptorInner<Camellia192, R>),
    Camellia256(StreamDecryptorInner<Camellia256, R>),
}

impl<R> BufRead for StreamDecryptor<R>
where
    R: BufRead,
{
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        match self {
            Self::Idea(i) => i.fill_buf(),
            Self::TripleDes(i) => i.fill_buf(),
            Self::Cast5(i) => i.fill_buf(),
            Self::Blowfish(i) => i.fill_buf(),
            Self::Aes128(i) => i.fill_buf(),
            Self::Aes192(i) => i.fill_buf(),
            Self::Aes256(i) => i.fill_buf(),
            Self::Twofish(i) => i.fill_buf(),
            Self::Camellia128(i) => i.fill_buf(),
            Self::Camellia192(i) => i.fill_buf(),
            Self::Camellia256(i) => i.fill_buf(),
        }
    }

    fn consume(&mut self, amt: usize) {
        match self {
            Self::Idea(i) => i.consume(amt),
            Self::TripleDes(i) => i.consume(amt),
            Self::Cast5(i) => i.consume(amt),
            Self::Blowfish(i) => i.consume(amt),
            Self::Aes128(i) => i.consume(amt),
            Self::Aes192(i) => i.consume(amt),
            Self::Aes256(i) => i.consume(amt),
            Self::Twofish(i) => i.consume(amt),
            Self::Camellia128(i) => i.consume(amt),
            Self::Camellia192(i) => i.consume(amt),
            Self::Camellia256(i) => i.consume(amt),
        }
    }
}

impl<R> Read for StreamDecryptor<R>
where
    R: BufRead,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Idea(i) => i.read(buf),
            Self::TripleDes(i) => i.read(buf),
            Self::Cast5(i) => i.read(buf),
            Self::Blowfish(i) => i.read(buf),
            Self::Aes128(i) => i.read(buf),
            Self::Aes192(i) => i.read(buf),
            Self::Aes256(i) => i.read(buf),
            Self::Twofish(i) => i.read(buf),
            Self::Camellia128(i) => i.read(buf),
            Self::Camellia192(i) => i.read(buf),
            Self::Camellia256(i) => i.read(buf),
        }
    }
}

impl<R> StreamDecryptor<R>
where
    R: BufRead,
{
    pub fn new(
        alg: SymmetricKeyAlgorithm,
        protected: bool,
        key: &[u8],
        ciphertext: R,
    ) -> Result<Self> {
        match alg {
            SymmetricKeyAlgorithm::Plaintext => {
                bail!("'Plaintext' is not a legal cipher for encrypted data")
            }
            SymmetricKeyAlgorithm::IDEA => Ok(StreamDecryptor::Idea(StreamDecryptorInner::new(
                protected, ciphertext, key,
            )?)),
            SymmetricKeyAlgorithm::TripleDES => Ok(StreamDecryptor::TripleDes(
                StreamDecryptorInner::new(protected, ciphertext, key)?,
            )),
            SymmetricKeyAlgorithm::CAST5 => Ok(StreamDecryptor::Cast5(StreamDecryptorInner::new(
                protected, ciphertext, key,
            )?)),
            SymmetricKeyAlgorithm::Blowfish => Ok(StreamDecryptor::Blowfish(
                StreamDecryptorInner::new(protected, ciphertext, key)?,
            )),
            SymmetricKeyAlgorithm::AES128 => Ok(StreamDecryptor::Aes128(
                StreamDecryptorInner::new(protected, ciphertext, key)?,
            )),
            SymmetricKeyAlgorithm::AES192 => Ok(StreamDecryptor::Aes192(
                StreamDecryptorInner::new(protected, ciphertext, key)?,
            )),
            SymmetricKeyAlgorithm::AES256 => Ok(StreamDecryptor::Aes256(
                StreamDecryptorInner::new(protected, ciphertext, key)?,
            )),
            SymmetricKeyAlgorithm::Twofish => Ok(StreamDecryptor::Twofish(
                StreamDecryptorInner::new(protected, ciphertext, key)?,
            )),
            SymmetricKeyAlgorithm::Camellia128 => Ok(StreamDecryptor::Camellia128(
                StreamDecryptorInner::new(protected, ciphertext, key)?,
            )),
            SymmetricKeyAlgorithm::Camellia192 => Ok(StreamDecryptor::Camellia192(
                StreamDecryptorInner::new(protected, ciphertext, key)?,
            )),
            SymmetricKeyAlgorithm::Camellia256 => Ok(StreamDecryptor::Camellia256(
                StreamDecryptorInner::new(protected, ciphertext, key)?,
            )),
            SymmetricKeyAlgorithm::Private10 | SymmetricKeyAlgorithm::Other(_) => {
                bail!("SymmetricKeyAlgorithm {} is unsupported", u8::from(alg))
            }
        }
    }

    pub fn into_inner(self) -> R {
        match self {
            Self::Idea(i) => i.into_inner(),
            Self::TripleDes(i) => i.into_inner(),
            Self::Cast5(i) => i.into_inner(),
            Self::Blowfish(i) => i.into_inner(),
            Self::Aes128(i) => i.into_inner(),
            Self::Aes192(i) => i.into_inner(),
            Self::Aes256(i) => i.into_inner(),
            Self::Twofish(i) => i.into_inner(),
            Self::Camellia128(i) => i.into_inner(),
            Self::Camellia192(i) => i.into_inner(),
            Self::Camellia256(i) => i.into_inner(),
        }
    }

    pub fn get_ref(&self) -> &R {
        match self {
            Self::Idea(i) => i.get_ref(),
            Self::TripleDes(i) => i.get_ref(),
            Self::Cast5(i) => i.get_ref(),
            Self::Blowfish(i) => i.get_ref(),
            Self::Aes128(i) => i.get_ref(),
            Self::Aes192(i) => i.get_ref(),
            Self::Aes256(i) => i.get_ref(),
            Self::Twofish(i) => i.get_ref(),
            Self::Camellia128(i) => i.get_ref(),
            Self::Camellia192(i) => i.get_ref(),
            Self::Camellia256(i) => i.get_ref(),
        }
    }
}

// TODO: cleanup state management between protected and non protected

#[derive(derive_more::Debug)]
pub enum StreamDecryptorInner<M, R>
where
    M: BlockDecrypt + BlockEncryptMut + BlockCipher,
    BufDecryptor<M>: KeyIvInit,
    R: BufRead,
{
    Prefix {
        // We use regular sha1 for MDC, not sha1_checked. Collisions are not currently a concern with MDC.
        hasher: Sha1,
        #[debug("BufDecryptor")]
        decryptor: BufDecryptor<M>,
        prefix: BytesMut,
        #[debug("source")]
        source: R,
        /// True if this uses MDC protection
        protected: bool,
        key: Vec<u8>,
    },
    Data {
        hasher: Sha1,
        /// How much data has been decrypted and hashed and is available
        /// in the `buffer`, without MDC.
        data_available: usize,
        #[debug("BufDecryptor")]
        decryptor: BufDecryptor<M>,
        buffer: BytesMut,
        #[debug("source")]
        source: R,
        protected: bool,
    },
    Done {
        buffer: BytesMut,
        source: R,
    },
    Error,
}

impl<M, R> StreamDecryptorInner<M, R>
where
    M: BlockDecrypt + BlockEncryptMut + BlockCipher,
    BufDecryptor<M>: KeyIvInit,
    R: BufRead,
{
    fn new(protected: bool, source: R, key: &[u8]) -> Result<Self> {
        debug!("protected decrypt stream");

        let bs = <M as BlockSizeUser>::block_size();

        // checksum over unencrypted data
        let hasher = Sha1::default();

        // IV is all zeroes
        let iv_vec = vec![0u8; bs];

        let encryptor = BufDecryptor::<M>::new_from_slices(key, &iv_vec)?;
        let prefix_len = bs + 2;

        Ok(Self::Prefix {
            hasher,
            decryptor: encryptor,
            prefix: BytesMut::zeroed(prefix_len),
            source,
            protected,
            key: key.to_vec(),
        })
    }

    fn into_inner(self) -> R {
        match self {
            Self::Prefix { source, .. } => source,
            Self::Data { source, .. } => source,
            Self::Done { source, .. } => source,
            Self::Error => panic!("error state"),
        }
    }

    fn get_ref(&self) -> &R {
        match self {
            Self::Prefix { source, .. } => source,
            Self::Data { source, .. } => source,
            Self::Done { source, .. } => source,
            Self::Error => panic!("error state"),
        }
    }

    fn fill_inner(&mut self) -> io::Result<()> {
        loop {
            match std::mem::replace(self, Self::Error) {
                Self::Prefix {
                    mut hasher,
                    decryptor: mut encryptor,
                    mut prefix,
                    mut source,
                    protected,
                    key,
                } => {
                    let bs = <M as BlockSizeUser>::block_size();

                    // reading the prefix
                    let read = fill_buffer(&mut source, &mut prefix, Some(bs + 2))?;
                    if read < bs + 2 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "missing quick check",
                        ));
                    }

                    if !protected {
                        // legacy resyncing
                        let encrypted_prefix = prefix[2..].to_vec();
                        encryptor.decrypt(&mut prefix);
                        encryptor = BufDecryptor::<M>::new_from_slices(&key, &encrypted_prefix)
                            .map_err(|e| {
                                io::Error::new(io::ErrorKind::InvalidInput, e.to_string())
                            })?;
                    } else {
                        encryptor.decrypt(&mut prefix);
                    }

                    // We do not do use "quick check" here.
                    // See the "Security Considerations" section
                    // in <https://www.rfc-editor.org/rfc/rfc9580.html#name-risks-of-a-quick-check-orac>
                    // and the paper <https://eprint.iacr.org/2005/033>
                    // for details.

                    hasher.update(&prefix);

                    *self = Self::Data {
                        hasher,
                        data_available: 0,
                        decryptor: encryptor,
                        buffer: BytesMut::with_capacity(BUFFER_SIZE),
                        source,
                        protected,
                    };
                    // continue to data
                }
                Self::Data {
                    mut hasher,
                    mut data_available,
                    mut decryptor,
                    mut buffer,
                    mut source,
                    protected,
                } => {
                    // need to keep at least a full mdc len in the buffer, to make sure we process
                    // that at the end, and to return it

                    if protected && buffer.remaining() > MDC_LEN
                        || !protected && buffer.has_remaining()
                    {
                        *self = Self::Data {
                            hasher,
                            data_available,
                            decryptor,
                            buffer,
                            source,
                            protected,
                        };

                        return Ok(());
                    }

                    // fill buffer
                    let current_len = buffer.remaining();
                    buffer.resize(BUFFER_SIZE, 0);

                    let to_read = BUFFER_SIZE - current_len;
                    let read = fill_buffer(&mut source, &mut buffer[current_len..], Some(to_read))?;
                    buffer.truncate(current_len + read);

                    decryptor.decrypt(&mut buffer[current_len..]);

                    if read < to_read {
                        // last read

                        if protected {
                            if buffer.remaining() < MDC_LEN {
                                return Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "missing MDC",
                                ));
                            }

                            // grab the MDC from the end
                            // MDC is 1 byte packet tag, 1 byte length prefix and 20 bytes SHA1 hash.
                            let mdc = buffer.split_off(buffer.len() - MDC_LEN);

                            hasher.update(&buffer);
                            hasher.update(&mdc[..2]);
                            let sha1: [u8; 20] = hasher.finalize().into();

                            if mdc[0] != 0xD3 || // Invalid MDC tag
                            mdc[1] != 0x14 || // Invalid MDC length
                            mdc[2..] != sha1[..]
                            {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidInput,
                                    "invalid MDC ",
                                ));
                            }
                            *self = Self::Done { buffer, source };
                        } else {
                            hasher.update(&buffer);
                            *self = Self::Done { buffer, source };
                        }
                    } else {
                        let start = data_available;
                        let end = if protected {
                            debug_assert!(buffer.len() >= MDC_LEN);
                            buffer.len() - MDC_LEN
                        } else {
                            buffer.len()
                        };

                        if start < end {
                            hasher.update(&buffer[start..end]);
                            data_available += end - start;
                        }

                        *self = Self::Data {
                            hasher,
                            data_available,
                            decryptor,
                            buffer,
                            source,
                            protected,
                        };
                    }
                    return Ok(());
                }
                Self::Done { buffer, source } => {
                    *self = Self::Done { buffer, source };
                    return Ok(());
                }
                Self::Error => panic!("error state"),
            }
        }
    }
}

impl<M, R> BufRead for StreamDecryptorInner<M, R>
where
    M: BlockDecrypt + BlockEncryptMut + BlockCipher,
    BufDecryptor<M>: KeyIvInit,
    R: BufRead,
{
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.fill_inner()?;
        match self {
            Self::Prefix { .. } => panic!("invalid state"),
            Self::Data {
                buffer,
                data_available,
                ..
            } => Ok(&buffer[..*data_available]),
            Self::Done { buffer, .. } => Ok(&buffer[..]),
            Self::Error => unreachable!("error state "),
        }
    }

    fn consume(&mut self, amt: usize) {
        match self {
            Self::Prefix { .. } => panic!("invalid state"),
            Self::Data {
                buffer,
                data_available,
                ..
            } => {
                buffer.advance(amt);
                *data_available -= amt;
            }
            Self::Done { buffer, .. } => {
                buffer.advance(amt);
            }
            Self::Error => unreachable!("error state "),
        }
    }
}

impl<M, R> Read for StreamDecryptorInner<M, R>
where
    M: BlockDecrypt + BlockEncryptMut + BlockCipher,
    BufDecryptor<M>: KeyIvInit,
    R: BufRead,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.fill_inner()?;
        match self {
            Self::Prefix { .. } => panic!("invalid state"),
            Self::Data {
                buffer,
                data_available,
                ..
            } => {
                let to_write = (*data_available).min(buf.len());
                buffer.copy_to_slice(&mut buf[..to_write]);
                *data_available -= to_write;
                Ok(to_write)
            }
            Self::Done { buffer, .. } => {
                let to_write = buffer.remaining().min(buf.len());
                buffer.copy_to_slice(&mut buf[..to_write]);
                Ok(to_write)
            }
            Self::Error => unreachable!("error state "),
        }
    }
}

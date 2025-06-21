use std::io::{self, BufRead, Read};

use aes::{Aes128, Aes192, Aes256};
use blowfish::Blowfish;
use bytes::{Buf, BytesMut};
use camellia::{Camellia128, Camellia192, Camellia256};
use cast5::Cast5;
use cfb_mode::{cipher::KeyIvInit, BufDecryptor};
use cipher::{BlockCipherEncrypt, BlockSizeUser};
use des::TdesEde3;
use idea::Idea;
use log::debug;
use sha1::{Digest, Sha1};
use twofish::Twofish;
use zeroize::Zeroizing;

use crate::{
    crypto::sym::SymmetricKeyAlgorithm,
    errors::{bail, Result},
    util::fill_buffer,
};

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

    pub fn get_mut(&mut self) -> &mut R {
        match self {
            Self::Idea(i) => i.get_mut(),
            Self::TripleDes(i) => i.get_mut(),
            Self::Cast5(i) => i.get_mut(),
            Self::Blowfish(i) => i.get_mut(),
            Self::Aes128(i) => i.get_mut(),
            Self::Aes192(i) => i.get_mut(),
            Self::Aes256(i) => i.get_mut(),
            Self::Twofish(i) => i.get_mut(),
            Self::Camellia128(i) => i.get_mut(),
            Self::Camellia192(i) => i.get_mut(),
            Self::Camellia256(i) => i.get_mut(),
        }
    }
}

#[derive(derive_more::Debug)]
pub enum MaybeProtected {
    Protected {
        // We use regular sha1 for MDC, not sha1_checked. Collisions are not currently a concern with MDC.
        hasher: Sha1,
    },
    Unprotected {
        key: Zeroizing<Vec<u8>>,
    },
}

impl MaybeProtected {
    fn is_protected(&self) -> bool {
        matches!(self, Self::Protected { .. })
    }
}

#[derive(derive_more::Debug)]
pub enum StreamDecryptorInner<M, R>
where
    M: BlockCipherEncrypt,
    BufDecryptor<M>: KeyIvInit,
    R: BufRead,
{
    Prefix {
        #[debug("BufDecryptor")]
        decryptor: BufDecryptor<M>,
        prefix: BytesMut,
        source: R,
        protected: MaybeProtected,
    },
    Data {
        /// How much data has been decrypted and hashed and is available
        /// in the `buffer`, without MDC.
        data_available: usize,
        #[debug("BufDecryptor")]
        decryptor: BufDecryptor<M>,
        buffer: BytesMut,
        source: R,
        protected: MaybeProtected,
    },
    Done {
        buffer: BytesMut,
        source: R,
    },
    Error,
}

impl<M, R> StreamDecryptorInner<M, R>
where
    M: BlockCipherEncrypt,
    BufDecryptor<M>: KeyIvInit,
    R: BufRead,
{
    fn new(protected: bool, source: R, key: &[u8]) -> Result<Self> {
        debug!("protected decrypt stream");

        let bs = <M as BlockSizeUser>::block_size();

        // IV is all zeroes
        let iv_vec = vec![0u8; bs];

        let decryptor = BufDecryptor::<M>::new_from_slices(key, &iv_vec)?;
        let prefix_len = bs + 2;

        let protected = if protected {
            // checksum over unencrypted data
            let hasher = Sha1::default();
            MaybeProtected::Protected { hasher }
        } else {
            MaybeProtected::Unprotected {
                key: key.to_vec().into(),
            }
        };

        Ok(Self::Prefix {
            decryptor,
            prefix: BytesMut::zeroed(prefix_len),
            source,
            protected,
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

    fn get_mut(&mut self) -> &mut R {
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
                    decryptor: mut encryptor,
                    mut prefix,
                    mut source,
                    mut protected,
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

                    match protected {
                        MaybeProtected::Unprotected { ref key } => {
                            // legacy resyncing
                            let encrypted_prefix = prefix[2..].to_vec();
                            encryptor.decrypt(&mut prefix);
                            encryptor = BufDecryptor::<M>::new_from_slices(key, &encrypted_prefix)
                                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
                        }
                        MaybeProtected::Protected { ref mut hasher } => {
                            encryptor.decrypt(&mut prefix);
                            hasher.update(&prefix);
                        }
                    }

                    // We do not do use "quick check" here.
                    // See the "Security Considerations" section
                    // in <https://www.rfc-editor.org/rfc/rfc9580.html#name-risks-of-a-quick-check-orac>
                    // and the paper <https://eprint.iacr.org/2005/033>
                    // for details.

                    *self = Self::Data {
                        data_available: 0,
                        decryptor: encryptor,
                        buffer: BytesMut::with_capacity(BUFFER_SIZE),
                        source,
                        protected,
                    };
                    // continue to data
                }
                Self::Data {
                    mut data_available,
                    mut decryptor,
                    mut buffer,
                    mut source,
                    mut protected,
                } => {
                    // need to keep at least a full mdc len in the buffer, to make sure we process
                    // that at the end, and to return it

                    if protected.is_protected() && buffer.remaining() > MDC_LEN
                        || !protected.is_protected() && buffer.has_remaining()
                    {
                        *self = Self::Data {
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

                    let is_last_read = read < to_read;

                    match protected {
                        MaybeProtected::Protected { mut hasher } if is_last_read => {
                            // last read
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
                        }
                        MaybeProtected::Protected { ref mut hasher } => {
                            let start = data_available;
                            debug_assert!(buffer.len() >= MDC_LEN);
                            let end = buffer.len() - MDC_LEN;

                            if start < end {
                                hasher.update(&buffer[start..end]);
                                data_available += end - start;
                            }

                            *self = Self::Data {
                                data_available,
                                decryptor,
                                buffer,
                                source,
                                protected,
                            }
                        }
                        MaybeProtected::Unprotected { .. } => {
                            if is_last_read {
                                *self = Self::Done { buffer, source };
                            } else {
                                let start = data_available;
                                let end = buffer.len();

                                if start < end {
                                    data_available += end - start;
                                }

                                *self = Self::Data {
                                    data_available,
                                    decryptor,
                                    buffer,
                                    source,
                                    protected,
                                }
                            }
                        }
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
    M: BlockCipherEncrypt,
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
    M: BlockCipherEncrypt,
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

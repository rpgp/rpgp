use std::io::{self, BufRead, Read};

use bytes::{Buf, BytesMut};

use crate::crypto::{aead::AeadAlgorithm, sym::SymmetricKeyAlgorithm};
use crate::errors::Result;
use crate::packet::{ChunkSize, PacketHeader, StreamDecryptor, SymEncryptedProtectedDataConfig};
use crate::types::Tag;
use crate::PlainSessionKey;

use super::{fill_buffer, PacketBodyReader};

#[derive(derive_more::Debug)]
pub enum SymEncryptedProtectedDataReader<R: BufRead> {
    Init {
        source: PacketBodyReader<R>,
        config: SymEncryptedProtectedDataConfig,
    },
    Body {
        source: PacketBodyReader<R>,
        buffer: BytesMut,
        config: SymEncryptedProtectedDataConfig,
        decryptor: Option<StreamDecryptor>,
    },
    Done {
        source: PacketBodyReader<R>,
        config: SymEncryptedProtectedDataConfig,
    },
    Error,
}

impl<R: BufRead> SymEncryptedProtectedDataReader<R> {
    pub fn new(mut source: PacketBodyReader<R>) -> Result<Self> {
        debug_assert_eq!(source.packet_header().tag(), Tag::SymEncryptedProtectedData);
        let config = SymEncryptedProtectedDataConfig::try_from_reader(&mut source)?;

        Ok(Self::Init { source, config })
    }

    pub fn decrypt(&mut self, session_key: &PlainSessionKey) -> Result<()> {
        match std::mem::replace(self, Self::Error) {
            Self::Init { source, config } => {
                let decryptor = match config {
                    SymEncryptedProtectedDataConfig::V1 => {
                        let (sym_alg, session_key) = match session_key {
                            PlainSessionKey::V3_4 { sym_alg, key } => (sym_alg, key),
                            PlainSessionKey::V5 { .. } => {
                                unsupported_err!("v5 is not supported");
                            }
                            PlainSessionKey::V6 { .. } => {
                                bail!("missmatch between session key and edata config");
                            }
                            PlainSessionKey::Unknown { sym_alg, key } => (sym_alg, key),
                        };

                        StreamDecryptor::v1(*sym_alg, &session_key)?
                    }
                    SymEncryptedProtectedDataConfig::V2 {
                        sym_alg,
                        aead,
                        chunk_size,
                        salt,
                    } => {
                        let (sym_alg_session_key, session_key) = match session_key {
                            PlainSessionKey::V3_4 { .. } => {
                                bail!("missmatch between session key and edata config");
                            }
                            PlainSessionKey::V5 { .. } => {
                                unsupported_err!("v5 is not supported");
                            }
                            PlainSessionKey::V6 { key } => (None, key),
                            PlainSessionKey::Unknown { sym_alg, key } => (Some(sym_alg), key),
                        };
                        if let Some(sym_alg_session_key) = sym_alg_session_key {
                            ensure_eq!(
                                sym_alg,
                                *sym_alg_session_key,
                                "missmatching symmetric key algorithm"
                            );
                        }

                        ensure_eq!(
                            session_key.len(),
                            sym_alg.key_size(),
                            "Unexpected session key length for {:?}",
                            sym_alg
                        );
                        StreamDecryptor::v2(sym_alg, aead, chunk_size, &salt, &session_key)?
                    }
                };

                *self = Self::Body {
                    source,
                    buffer: BytesMut::with_capacity(1024),
                    config,
                    decryptor: Some(decryptor),
                };
                Ok(())
            }
            Self::Body {
                source,
                buffer,
                config,
                decryptor,
            } => {
                *self = Self::Body {
                    source,
                    buffer,
                    config,
                    decryptor,
                };
                bail!("cannot decrypt after starting to read")
            }
            Self::Done { source, config } => {
                *self = Self::Done { source, config };
                bail!("cannot decrypt after finishing to read")
            }
            Self::Error => panic!("error state"),
        }
    }

    pub(crate) fn new_done(
        config: SymEncryptedProtectedDataConfig,
        source: PacketBodyReader<R>,
    ) -> Self {
        Self::Done { source, config }
    }

    pub fn config(&self) -> &SymEncryptedProtectedDataConfig {
        match self {
            Self::Init { config, .. } => config,
            Self::Body { config, .. } => config,
            Self::Done { config, .. } => config,
            Self::Error => panic!("error state"),
        }
    }

    pub fn is_done(&self) -> bool {
        matches!(self, Self::Done { .. })
    }

    pub fn into_inner(self) -> PacketBodyReader<R> {
        match self {
            Self::Init { source, .. } => source,
            Self::Body { source, .. } => source,
            Self::Done { source, .. } => source,
            Self::Error => panic!("error state"),
        }
    }

    pub fn packet_header(&self) -> PacketHeader {
        match self {
            Self::Init { source, .. } => source.packet_header(),
            Self::Body { source, .. } => source.packet_header(),
            Self::Done { source, .. } => source.packet_header(),
            Self::Error => panic!("error state"),
        }
    }

    fn fill_inner(&mut self) -> io::Result<()> {
        if matches!(self, Self::Done { .. }) {
            return Ok(());
        }

        loop {
            match std::mem::replace(self, Self::Error) {
                Self::Init { mut source, config } => {
                    *self = Self::Body {
                        source,
                        buffer: BytesMut::with_capacity(1024),
                        config,
                        decryptor: None,
                    }
                }
                Self::Body {
                    mut source,
                    mut buffer,
                    config,
                    mut decryptor,
                } => {
                    if buffer.has_remaining() {
                        *self = Self::Body {
                            source,
                            buffer,
                            config,
                            decryptor,
                        };
                        return Ok(());
                    }

                    buffer.resize(1024, 0);
                    let read = fill_buffer(&mut source, &mut buffer, None)?;
                    buffer.truncate(read);

                    // decrypt data in the buffer

                    if read == 0 {
                        *self = Self::Done { source, config };
                    } else {
                        *self = Self::Body {
                            source,
                            buffer,
                            config,
                            decryptor,
                        };
                    }
                    return Ok(());
                }
                Self::Done { source, config } => {
                    *self = Self::Done { source, config };
                    return Ok(());
                }
                Self::Error => {
                    panic!("CompressedReader errored");
                }
            }
        }
    }
}

impl<R: BufRead> BufRead for SymEncryptedProtectedDataReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.fill_inner()?;
        match self {
            Self::Init { .. } => panic!("invalid state"),
            Self::Body { ref mut buffer, .. } => Ok(&buffer[..]),
            Self::Done { .. } => Ok(&[][..]),
            Self::Error => panic!("error state"),
        }
    }

    fn consume(&mut self, amt: usize) {
        match self {
            Self::Init { .. } => panic!("invalid state"),
            Self::Body { ref mut buffer, .. } => {
                buffer.advance(amt);
            }
            Self::Done { .. } => {}
            Self::Error => panic!("error state"),
        }
    }
}

impl<R: BufRead> Read for SymEncryptedProtectedDataReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.fill_inner()?;
        match self {
            Self::Init { .. } => panic!("invalid state"),
            Self::Body { ref mut buffer, .. } => {
                let to_write = buffer.remaining().min(buf.len());
                buffer.copy_to_slice(&mut buf[..to_write]);
                Ok(to_write)
            }
            Self::Done { .. } => Ok(0),
            Self::Error => unreachable!("error state "),
        }
    }
}

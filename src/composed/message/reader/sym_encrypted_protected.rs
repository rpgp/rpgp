use std::io::{self, BufRead, Read};

use crate::errors::Result;
use crate::packet::{PacketHeader, StreamDecryptor, SymEncryptedProtectedDataConfig};
use crate::types::Tag;
use crate::{DebugBufRead, PlainSessionKey};

use super::PacketBodyReader;

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum SymEncryptedProtectedDataReader<R: DebugBufRead> {
    Init {
        source: PacketBodyReader<R>,
        config: SymEncryptedProtectedDataConfig,
    },
    Body {
        config: SymEncryptedProtectedDataConfig,
        decryptor: MaybeDecryptor<PacketBodyReader<R>>,
    },
    Done {
        source: PacketBodyReader<R>,
        config: SymEncryptedProtectedDataConfig,
    },
    Error,
}

#[derive(derive_more::Debug)]
#[allow(clippy::large_enum_variant)]
pub enum MaybeDecryptor<R: DebugBufRead> {
    Raw(#[debug("R")] R),
    Decryptor(StreamDecryptor<R>),
}

impl<R: DebugBufRead> MaybeDecryptor<R> {
    pub fn into_inner(self) -> R {
        match self {
            Self::Raw(r) => r,
            Self::Decryptor(r) => r.into_inner(),
        }
    }

    pub fn get_ref(&self) -> &R {
        match self {
            Self::Raw(r) => r,
            Self::Decryptor(r) => r.get_ref(),
        }
    }

    pub fn get_mut(&mut self) -> &mut R {
        match self {
            Self::Raw(r) => r,
            Self::Decryptor(r) => r.get_mut(),
        }
    }
}

impl<R: DebugBufRead> BufRead for MaybeDecryptor<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        match self {
            Self::Raw(r) => r.fill_buf(),
            Self::Decryptor(r) => r.fill_buf(),
        }
    }

    fn consume(&mut self, amt: usize) {
        match self {
            Self::Raw(r) => r.consume(amt),
            Self::Decryptor(r) => r.consume(amt),
        }
    }
}

impl<R: DebugBufRead> Read for MaybeDecryptor<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Raw(r) => r.read(buf),
            Self::Decryptor(r) => r.read(buf),
        }
    }
}

impl<R: DebugBufRead> SymEncryptedProtectedDataReader<R> {
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
                                bail!("mismatch between session key and edata config");
                            }
                            PlainSessionKey::Unknown { sym_alg, key } => (sym_alg, key),
                        };

                        StreamDecryptor::v1(*sym_alg, session_key, source)?
                    }
                    SymEncryptedProtectedDataConfig::V2 {
                        sym_alg,
                        aead,
                        chunk_size,
                        salt,
                    } => {
                        let (sym_alg_session_key, session_key) = match session_key {
                            PlainSessionKey::V3_4 { .. } => {
                                bail!("mismatch between session key and edata config");
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
                                "mismatching symmetric key algorithm"
                            );
                        }

                        ensure_eq!(
                            session_key.len(),
                            sym_alg.key_size(),
                            "Unexpected session key length for {:?}",
                            sym_alg
                        );
                        StreamDecryptor::v2(sym_alg, aead, chunk_size, &salt, session_key, source)?
                    }
                };

                *self = Self::Body {
                    config,
                    decryptor: MaybeDecryptor::Decryptor(decryptor),
                };
                Ok(())
            }
            Self::Body { config, decryptor } => {
                *self = Self::Body { config, decryptor };
                bail!("cannot decrypt after starting to read")
            }
            Self::Done { source, config } => {
                *self = Self::Done { source, config };
                bail!("cannot decrypt after finishing to read")
            }
            Self::Error => bail!("SymEncryptedProtectedDataReader errored"),
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
            Self::Error => {
                panic!("SymEncryptedProtectedDataReader errored")
            }
        }
    }

    pub fn is_done(&self) -> bool {
        matches!(self, Self::Done { .. })
    }

    pub fn into_inner(self) -> PacketBodyReader<R> {
        match self {
            Self::Init { source, .. } => source,
            Self::Body { decryptor, .. } => decryptor.into_inner(),
            Self::Done { source, .. } => source,
            Self::Error => {
                panic!("SymEncryptedProtectedDataReader errored")
            }
        }
    }

    pub fn get_mut(&mut self) -> &mut PacketBodyReader<R> {
        match self {
            Self::Init { source, .. } => source,
            Self::Body { decryptor, .. } => decryptor.get_mut(),
            Self::Done { source, .. } => source,
            Self::Error => {
                panic!("SymEncryptedProtectedDataReader errored")
            }
        }
    }

    pub fn packet_header(&self) -> PacketHeader {
        match self {
            Self::Init { source, .. } => source.packet_header(),
            Self::Body { decryptor, .. } => decryptor.get_ref().packet_header(),
            Self::Done { source, .. } => source.packet_header(),
            Self::Error => {
                panic!("SymEncryptedProtectedDataReader errored")
            }
        }
    }

    fn fill_inner(&mut self) -> io::Result<()> {
        if matches!(self, Self::Done { .. }) {
            return Ok(());
        }

        loop {
            match std::mem::replace(self, Self::Error) {
                Self::Init { source, config } => {
                    *self = Self::Body {
                        config,
                        decryptor: MaybeDecryptor::Raw(source),
                    }
                }
                Self::Body {
                    config,
                    mut decryptor,
                } => {
                    let buf = decryptor.fill_buf()?;
                    if buf.is_empty() {
                        let source = decryptor.into_inner();

                        *self = Self::Done { source, config };
                    } else {
                        *self = Self::Body { config, decryptor };
                    }
                    return Ok(());
                }
                Self::Done { source, config } => {
                    *self = Self::Done { source, config };
                    return Ok(());
                }
                Self::Error => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "SymEncryptedProtectedDataReader errored",
                    ));
                }
            }
        }
    }
}

impl<R: DebugBufRead> BufRead for SymEncryptedProtectedDataReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.fill_inner()?;
        match self {
            Self::Init { .. } => unreachable!("invalid state"),
            Self::Body { decryptor, .. } => decryptor.fill_buf(),

            Self::Done { .. } => Ok(&[][..]),
            Self::Error => Err(io::Error::new(
                io::ErrorKind::Other,
                "SymEncryptedProtectedDataReader errored",
            )),
        }
    }

    fn consume(&mut self, amt: usize) {
        match self {
            Self::Init { .. } => unreachable!("invalid state"),
            Self::Body { decryptor, .. } => decryptor.consume(amt),
            Self::Done { .. } => {}
            Self::Error => {
                panic!("SymEncryptedProtectedDataReader errored")
            }
        }
    }
}

impl<R: DebugBufRead> Read for SymEncryptedProtectedDataReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.fill_inner()?;
        match self {
            Self::Init { .. } => unreachable!("invalid state"),
            Self::Body { decryptor, .. } => decryptor.read(buf),
            Self::Done { .. } => Ok(0),
            Self::Error => Err(io::Error::new(
                io::ErrorKind::Other,
                "SymEncryptedProtectedDataReader errored",
            )),
        }
    }
}

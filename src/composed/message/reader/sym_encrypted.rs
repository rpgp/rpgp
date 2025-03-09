use std::io::{self, BufRead, Read};

use crate::crypto::sym::StreamDecryptor;
use crate::errors::Result;
use crate::packet::PacketHeader;
use crate::types::Tag;
use crate::PlainSessionKey;

use super::PacketBodyReader;

#[derive(derive_more::Debug)]
pub enum SymEncryptedDataReader<R: BufRead> {
    Init {
        source: PacketBodyReader<R>,
    },
    Body {
        decryptor: MaybeDecryptor<PacketBodyReader<R>>,
    },
    Done {
        source: PacketBodyReader<R>,
    },
    Error,
}

impl<R: BufRead> SymEncryptedDataReader<R> {
    pub fn new(source: PacketBodyReader<R>) -> Result<Self> {
        debug_assert_eq!(source.packet_header().tag(), Tag::SymEncryptedData);

        Ok(Self::Init { source })
    }

    pub(crate) fn new_done(source: PacketBodyReader<R>) -> Self {
        Self::Done { source }
    }

    pub fn is_done(&self) -> bool {
        matches!(self, Self::Done { .. })
    }

    pub fn into_inner(self) -> PacketBodyReader<R> {
        match self {
            Self::Init { source, .. } => source,
            Self::Body { decryptor, .. } => decryptor.into_inner(),
            Self::Done { source, .. } => source,
            Self::Error => panic!("error state"),
        }
    }

    pub fn packet_header(&self) -> PacketHeader {
        match self {
            Self::Init { source, .. } => source.packet_header(),
            Self::Body { decryptor, .. } => decryptor.get_ref().packet_header(),
            Self::Done { source, .. } => source.packet_header(),
            Self::Error => panic!("error state"),
        }
    }

    pub fn decrypt(&mut self, session_key: &PlainSessionKey) -> Result<()> {
        let (sym_alg, key) = match session_key {
            PlainSessionKey::V3_4 { sym_alg, key } | PlainSessionKey::Unknown { sym_alg, key } => {
                (*sym_alg, key)
            }
            PlainSessionKey::V5 { .. } | PlainSessionKey::V6 { .. } => {
                bail!("must not combine unprotected encryption with new session keys");
            }
        };

        match std::mem::replace(self, Self::Error) {
            Self::Init { source } => {
                let decryptor = sym_alg.stream_decryptor_unprotected(key, source)?;
                let decryptor = MaybeDecryptor::Decryptor(decryptor);

                *self = Self::Body { decryptor };
                Ok(())
            }
            Self::Body { decryptor } => {
                *self = Self::Body { decryptor };
                bail!("cannot decrypt after starting to read")
            }
            Self::Done { source } => {
                *self = Self::Done { source };
                bail!("cannot decrypt after finishing to read")
            }
            Self::Error => panic!("error state"),
        }
    }
}

impl<R: BufRead> BufRead for SymEncryptedDataReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        match self {
            Self::Init { .. } => panic!("invalid state"),
            Self::Body { decryptor } => decryptor.fill_buf(),
            Self::Done { .. } => Ok(&[][..]),
            Self::Error => panic!("error state"),
        }
    }

    fn consume(&mut self, amt: usize) {
        match self {
            Self::Init { .. } => panic!("invalid state"),
            Self::Body { decryptor } => decryptor.consume(amt),
            Self::Done { .. } => {}
            Self::Error => panic!("error state"),
        }
    }
}

impl<R: BufRead> Read for SymEncryptedDataReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Init { .. } => panic!("invalid state"),
            Self::Body { decryptor } => decryptor.read(buf),
            Self::Done { .. } => Ok(0),
            Self::Error => unreachable!("error state "),
        }
    }
}

#[derive(derive_more::Debug)]
#[allow(clippy::large_enum_variant)]
pub enum MaybeDecryptor<R: BufRead> {
    Raw(#[debug("R")] R),
    Decryptor(StreamDecryptor<R>),
}

impl<R: BufRead> MaybeDecryptor<R> {
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
}

impl<R: BufRead> BufRead for MaybeDecryptor<R> {
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

impl<R: BufRead> Read for MaybeDecryptor<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Raw(r) => r.read(buf),
            Self::Decryptor(r) => r.read(buf),
        }
    }
}

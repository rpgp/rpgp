use std::io::{self, BufRead, Read};

use crate::errors::Result;
use crate::packet::PacketHeader;
use crate::types::Tag;
use crate::PlainSessionKey;

use super::PacketBodyReader;

#[derive(derive_more::Debug)]
pub enum SymEncryptedDataReader<R: BufRead> {
    Init { source: PacketBodyReader<R> },
    Body { decryptor: PacketBodyReader<R> },
    Done { source: PacketBodyReader<R> },
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
            Self::Body { decryptor, .. } => decryptor,
            Self::Done { source, .. } => source,
            Self::Error => panic!("error state"),
        }
    }

    pub fn packet_header(&self) -> PacketHeader {
        match self {
            Self::Init { source, .. } => source.packet_header(),
            Self::Body { decryptor, .. } => decryptor.packet_header(),
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
            Self::Init { .. } => {
                // still need to implement the streaming decryptor without MDC
                todo!();
                // let decryptor = *self = Self::Body {
                //     config,
                //     decryptor: MaybeDecryptor::Decryptor(decryptor),
                // };
                // Ok(())
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

    fn fill_inner(&mut self) -> io::Result<()> {
        todo!()
    }
}

impl<R: BufRead> BufRead for SymEncryptedDataReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.fill_inner()?;
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
        self.fill_inner()?;
        match self {
            Self::Init { .. } => panic!("invalid state"),
            Self::Body { decryptor } => decryptor.read(buf),
            Self::Done { .. } => Ok(0),
            Self::Error => unreachable!("error state "),
        }
    }
}

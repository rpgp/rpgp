use std::io::{self, BufRead, Read};

use super::PacketBodyReader;
use crate::{
    composed::PlainSessionKey,
    crypto::sym::StreamDecryptor,
    errors::{bail, Result},
    packet::PacketHeader,
    types::Tag,
};

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum SymEncryptedDataReader<R: BufRead> {
    Body {
        decryptor: MaybeDecryptor<PacketBodyReader<R>>,
    },
    Error,
}

impl<R: BufRead> SymEncryptedDataReader<R> {
    pub fn new(source: PacketBodyReader<R>) -> Result<Self> {
        debug_assert_eq!(source.packet_header().tag(), Tag::SymEncryptedData);

        Ok(Self::Body {
            decryptor: MaybeDecryptor::Raw(source),
        })
    }

    pub fn into_inner(self) -> PacketBodyReader<R> {
        match self {
            Self::Body { decryptor, .. } => decryptor.into_inner(),
            Self::Error => panic!("SymEncryptedDataReader errored"),
        }
    }

    pub fn get_mut(&mut self) -> &mut PacketBodyReader<R> {
        match self {
            Self::Body { decryptor, .. } => decryptor.get_mut(),
            Self::Error => panic!("SymEncryptedDataReader errored"),
        }
    }

    pub fn packet_header(&self) -> PacketHeader {
        match self {
            Self::Body { decryptor, .. } => decryptor.get_ref().packet_header(),
            Self::Error => panic!("SymEncryptedDataReader errored"),
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
            Self::Body {
                decryptor: MaybeDecryptor::Raw(source),
            } => {
                let decryptor = sym_alg.stream_decryptor_unprotected(key, source)?;
                let decryptor = MaybeDecryptor::Decryptor(decryptor);
                *self = Self::Body { decryptor };
                Ok(())
            }
            Self::Body {
                decryptor: MaybeDecryptor::Decryptor(_),
            } => {
                bail!("already decrypting")
            }
            Self::Error => panic!("SymEncryptedDataReader errored"),
        }
    }
}

impl<R: BufRead> BufRead for SymEncryptedDataReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        match self {
            Self::Body { ref mut decryptor } => decryptor.fill_buf(),
            Self::Error => {
                panic!("SymEncryptedDataReader errored")
            }
        }
    }

    fn consume(&mut self, amt: usize) {
        match self {
            Self::Body { decryptor } => decryptor.consume(amt),
            Self::Error => panic!("SymEncryptedDataReader errored"),
        }
    }
}

impl<R: BufRead> Read for SymEncryptedDataReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Body { decryptor } => decryptor.read(buf),
            Self::Error => Err(io::Error::other("SymEncryptedDataReader errored")),
        }
    }
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum MaybeDecryptor<R: BufRead> {
    Raw(R),
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

    pub fn get_mut(&mut self) -> &mut R {
        match self {
            Self::Raw(r) => r,
            Self::Decryptor(r) => r.get_mut(),
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

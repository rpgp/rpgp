use std::io::{self, BufRead, Read};

use bytes::BytesMut;

use crate::errors::Result;
use crate::packet::PacketHeader;
use crate::packet::SymEncryptedProtectedDataConfig;
use crate::types::Tag;

use super::PacketBodyReader;

#[derive(derive_more::Debug)]
pub enum SymEncryptedProtectedDataReader<R: BufRead> {
    Body {
        source: PacketBodyReader<R>,
        buffer: BytesMut,
        config: SymEncryptedProtectedDataConfig,
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

        Ok(Self::Body {
            source,
            buffer: BytesMut::with_capacity(1024),
            config,
        })
    }

    pub(crate) fn new_done(
        config: SymEncryptedProtectedDataConfig,
        source: PacketBodyReader<R>,
    ) -> Self {
        Self::Done { source, config }
    }

    pub fn config(&self) -> &SymEncryptedProtectedDataConfig {
        match self {
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
            Self::Body { source, .. } => source,
            Self::Done { source, .. } => source,
            Self::Error => panic!("error state"),
        }
    }

    pub fn packet_header(&self) -> PacketHeader {
        match self {
            Self::Body { source, .. } => source.packet_header(),
            Self::Done { source, .. } => source.packet_header(),
            Self::Error => panic!("error state"),
        }
    }
}

impl<R: BufRead> BufRead for SymEncryptedProtectedDataReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        todo!()
    }

    fn consume(&mut self, amt: usize) {
        todo!()
    }
}

impl<R: BufRead> Read for SymEncryptedProtectedDataReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        todo!()
    }
}

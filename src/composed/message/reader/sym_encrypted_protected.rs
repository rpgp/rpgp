use std::io::{self, BufRead, Read};

use bytes::BytesMut;

use crate::packet::PacketHeader;
use crate::types::Tag;

use super::PacketBodyReader;

#[derive(derive_more::Debug)]
pub enum SymEncryptedProtectedDataReader<R: BufRead> {
    Header {
        source: PacketBodyReader<R>,
        buffer: BytesMut,
    },
    Body {
        source: PacketBodyReader<R>,
        buffer: BytesMut,
        config: crate::packet::SymEncryptedProtectedDataConfig,
    },
    Done {
        source: PacketBodyReader<R>,
    },
    Error,
}

impl<R: BufRead> SymEncryptedProtectedDataReader<R> {
    pub fn new(source: PacketBodyReader<R>) -> io::Result<Self> {
        debug_assert_eq!(source.packet_header().tag(), Tag::SymEncryptedProtectedData);

        Ok(Self::Header {
            source,
            buffer: BytesMut::with_capacity(1024),
        })
    }

    pub fn is_done(&self) -> bool {
        matches!(self, Self::Done { .. })
    }

    pub fn into_inner(self) -> PacketBodyReader<R> {
        match self {
            Self::Header { source, .. } => source,
            Self::Body { source, .. } => source,
            Self::Done { source, .. } => source,
            Self::Error => panic!("error state"),
        }
    }

    pub fn packet_header(&self) -> PacketHeader {
        match self {
            Self::Header { source, .. } => source.packet_header(),
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

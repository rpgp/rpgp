use std::io::{self, BufRead, Read};

use bytes::BytesMut;

use crate::packet::PacketHeader;
use crate::types::Tag;

use super::PacketBodyReader;

#[derive(derive_more::Debug)]
pub enum SymEncryptedDataReader<R: BufRead> {
    Body {
        source: PacketBodyReader<R>,
        buffer: BytesMut,
    },
    Done {
        source: PacketBodyReader<R>,
    },
    Error,
}

impl<R: BufRead> BufRead for SymEncryptedDataReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        todo!()
    }

    fn consume(&mut self, amt: usize) {
        todo!()
    }
}

impl<R: BufRead> Read for SymEncryptedDataReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        todo!()
    }
}

impl<R: BufRead> SymEncryptedDataReader<R> {
    pub fn new(source: PacketBodyReader<R>) -> io::Result<Self> {
        debug_assert_eq!(source.packet_header().tag(), Tag::SymEncryptedData);

        Ok(Self::Body {
            source,
            buffer: BytesMut::with_capacity(1024),
        })
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

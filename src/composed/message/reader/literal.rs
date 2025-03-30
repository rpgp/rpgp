use std::io::{self, BufRead, Read};

use bytes::{Buf, BytesMut};
use log::debug;

use super::PacketBodyReader;
use crate::{
    packet::{LiteralDataHeader, PacketHeader},
    types::Tag,
    util::fill_buffer,
};

/// Read the underlying literal data.
#[derive(derive_more::Debug)]
pub enum LiteralDataReader<R: BufRead> {
    Body {
        header: LiteralDataHeader,
        source: PacketBodyReader<R>,
        #[debug("{}", hex::encode(buffer))]
        buffer: BytesMut,
    },
    Done {
        header: LiteralDataHeader,
        source: PacketBodyReader<R>,
        #[debug("{}", hex::encode(buffer))]
        buffer: BytesMut,
    },
    Error,
}

impl<R: BufRead> LiteralDataReader<R> {
    pub fn new(mut source: PacketBodyReader<R>) -> io::Result<Self> {
        debug_assert_eq!(source.packet_header().tag(), Tag::LiteralData);
        let header = LiteralDataHeader::try_from_reader(&mut source)?;

        Ok(Self::Body {
            source,
            buffer: BytesMut::with_capacity(1024),
            header,
        })
    }

    pub(crate) fn new_done(source: PacketBodyReader<R>, header: LiteralDataHeader) -> Self {
        Self::Done {
            source,
            header,
            buffer: BytesMut::new(),
        }
    }

    pub fn is_done(&self) -> bool {
        match self {
            Self::Done { buffer, .. } => !buffer.has_remaining(),
            Self::Body { .. } => false,
            Self::Error => panic!("LiteralDataReader errored"),
        }
    }

    pub fn into_inner(self) -> PacketBodyReader<R> {
        match self {
            Self::Body { source, .. } => source,
            Self::Done { source, .. } => source,
            Self::Error => panic!("LiteralDataReader errored"),
        }
    }

    pub fn get_mut(&mut self) -> &mut PacketBodyReader<R> {
        match self {
            Self::Body { source, .. } => source,
            Self::Done { source, .. } => source,
            Self::Error => panic!("LiteralDataReader errored"),
        }
    }

    pub fn packet_header(&self) -> PacketHeader {
        match self {
            Self::Body { ref source, .. } => source.packet_header(),
            Self::Done { ref source, .. } => source.packet_header(),
            Self::Error => panic!("LiteralDataReader errored"),
        }
    }

    pub fn data_header(&self) -> &LiteralDataHeader {
        match self {
            Self::Body { ref header, .. } => header,
            Self::Done { ref header, .. } => header,
            Self::Error => panic!("LiteralDataReader errored"),
        }
    }

    fn fill_inner(&mut self) -> io::Result<()> {
        if self.is_done() {
            return Ok(());
        }

        match std::mem::replace(self, Self::Error) {
            Self::Body {
                mut source,
                mut buffer,
                header,
            } => {
                if buffer.has_remaining() {
                    *self = Self::Body {
                        source,
                        header,
                        buffer,
                    };
                    return Ok(());
                }

                debug!("literal packet: filling buffer");
                buffer.resize(1024, 0);
                let read = fill_buffer(&mut source, &mut buffer, Some(1024))?;
                buffer.truncate(read);

                if read < 1024 {
                    // done reading the source
                    *self = Self::Done {
                        source,
                        header,
                        buffer,
                    };
                } else {
                    *self = Self::Body {
                        source,
                        header,
                        buffer,
                    };
                }
                Ok(())
            }
            Self::Done {
                source,
                header,
                buffer,
            } => {
                *self = Self::Done {
                    source,
                    header,
                    buffer,
                };
                Ok(())
            }
            Self::Error => Err(io::Error::new(
                io::ErrorKind::Other,
                "LiteralDataReader errored",
            )),
        }
    }
}

impl<R: BufRead> BufRead for LiteralDataReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.fill_inner()?;
        match self {
            Self::Body { buffer, .. } | Self::Done { buffer, .. } => Ok(&buffer[..]),
            Self::Error => Err(io::Error::new(
                io::ErrorKind::Other,
                "LiteralDataReader errored",
            )),
        }
    }

    fn consume(&mut self, amt: usize) {
        match self {
            Self::Body { buffer, .. } | Self::Done { buffer, .. } => {
                buffer.advance(amt);
            }
            Self::Error => panic!("LiteralReader errored"),
        }
    }
}

impl<R: BufRead> Read for LiteralDataReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.fill_inner()?;
        match self {
            Self::Body { buffer, .. } | Self::Done { buffer, .. } => {
                let to_write = buffer.remaining().min(buf.len());
                buffer.copy_to_slice(&mut buf[..to_write]);
                Ok(to_write)
            }
            Self::Error => Err(io::Error::new(
                io::ErrorKind::Other,
                "LiteralDataReader errored",
            )),
        }
    }
}

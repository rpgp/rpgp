use std::io::{self, BufRead, Read};

use bytes::{Buf, BytesMut};
use log::debug;

use super::PacketBodyReader;
use crate::{
    packet::{LiteralDataHeader, PacketHeader},
    types::Tag,
    util::{fill_buffer_bytes, FinalizingBufRead},
};

const BUFFER_SIZE: usize = 8 * 1024;

/// Read the underlying literal data.
#[derive(derive_more::Debug)]
pub enum LiteralDataReader<R: FinalizingBufRead> {
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

impl<R: FinalizingBufRead> LiteralDataReader<R> {
    pub fn new(mut source: PacketBodyReader<R>) -> io::Result<Self> {
        debug_assert_eq!(source.packet_header().tag(), Tag::LiteralData);
        let header = LiteralDataHeader::try_from_reader(&mut source)?;

        Ok(Self::Body {
            source,
            buffer: BytesMut::with_capacity(BUFFER_SIZE),
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
                let read = fill_buffer_bytes(&mut source, &mut buffer, BUFFER_SIZE)?;
                let source_is_done = source.is_done();
                dbg!(read, source_is_done);

                if read < BUFFER_SIZE || source_is_done {
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
            Self::Error => Err(io::Error::other("LiteralDataReader errored")),
        }
    }
}

impl<R: FinalizingBufRead> FinalizingBufRead for LiteralDataReader<R> {
    fn is_done(&self) -> bool {
        match self {
            Self::Body { .. } => false,
            Self::Done { buffer, .. } => !buffer.has_remaining(),
            Self::Error => panic!("LiteralDataReader errored"),
        }
    }
}

impl<R: FinalizingBufRead> BufRead for LiteralDataReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.fill_inner()?;
        match self {
            Self::Body { buffer, .. } | Self::Done { buffer, .. } => Ok(&buffer[..]),
            Self::Error => Err(io::Error::other("LiteralDataReader errored")),
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

impl<R: FinalizingBufRead> Read for LiteralDataReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.fill_inner()?;
        match self {
            Self::Body { buffer, .. } | Self::Done { buffer, .. } => {
                let to_write = buffer.remaining().min(buf.len());
                buffer.copy_to_slice(&mut buf[..to_write]);
                Ok(to_write)
            }
            Self::Error => Err(io::Error::other("LiteralDataReader errored")),
        }
    }

    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {
        let mut read = 0;
        loop {
            self.fill_inner()?;
            match self {
                Self::Body { buffer, .. } => {
                    read += buffer.len();
                    buf.extend_from_slice(buffer);
                    buffer.clear();
                }
                Self::Done { buffer, .. } => {
                    read += buffer.len();
                    buf.extend_from_slice(buffer);
                    buffer.clear();
                    break;
                }
                Self::Error => return Err(io::Error::other("LiteralDataReader errored")),
            }
        }

        Ok(read)
    }
}

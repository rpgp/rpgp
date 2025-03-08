use std::io::{self, BufRead, Read};

use bytes::{Buf, BytesMut};
use log::debug;

use crate::packet::{LiteralDataHeader, PacketHeader};
use crate::types::Tag;
use crate::util::fill_buffer;

use super::PacketBodyReader;

/// Read the underlying literal data.
#[derive(derive_more::Debug)]
pub enum LiteralDataReader<R: BufRead> {
    Body {
        source: PacketBodyReader<R>,
        buffer: BytesMut,
        header: LiteralDataHeader,
    },
    Done {
        source: PacketBodyReader<R>,
        header: LiteralDataHeader,
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
        Self::Done { source, header }
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
            Self::Body { ref source, .. } => source.packet_header(),
            Self::Done { ref source, .. } => source.packet_header(),
            Self::Error => panic!("error state"),
        }
    }

    fn fill_inner(&mut self) -> io::Result<()> {
        if matches!(self, Self::Done { .. }) {
            return Ok(());
        }

        match std::mem::replace(self, Self::Error) {
            Self::Body {
                mut source,
                mut buffer,
                header,
            } => {
                debug!("literal packet: body");
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
                let read = fill_buffer(&mut source, &mut buffer, None)?;

                buffer.truncate(read);

                if read == 0 {
                    // done reading the source
                    *self = Self::Done { source, header };
                } else {
                    *self = Self::Body {
                        source,
                        header,
                        buffer,
                    };
                }
                Ok(())
            }
            Self::Done { source, header } => {
                debug!("literal packet: done");
                *self = Self::Done { source, header };
                Ok(())
            }
            Self::Error => {
                panic!("LiteralReader errored");
            }
        }
    }
}

impl<R: BufRead> BufRead for LiteralDataReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.fill_inner()?;
        match self {
            Self::Body { ref mut buffer, .. } => Ok(&buffer[..]),
            Self::Done { .. } => Ok(&[][..]),
            Self::Error => panic!("LiteralReader errored"),
        }
    }

    fn consume(&mut self, amt: usize) {
        match self {
            Self::Body { ref mut buffer, .. } => {
                buffer.advance(amt);
            }
            Self::Error => panic!("LiteralReader errored"),
            Self::Done { .. } => {}
        }
    }
}

impl<R: BufRead> Read for LiteralDataReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.fill_inner()?;
        match self {
            Self::Body { ref mut buffer, .. } => {
                let to_write = buffer.remaining().min(buf.len());
                buffer.copy_to_slice(&mut buf[..to_write]);
                Ok(to_write)
            }
            Self::Done { .. } => Ok(0),
            _ => unreachable!("invalid state"),
        }
    }
}

impl<R: BufRead> LiteralDataReader<R> {
    pub fn data_header(&self) -> &LiteralDataHeader {
        match self {
            Self::Body { ref header, .. } => header,
            Self::Done { ref header, .. } => header,
            Self::Error => panic!("error state"),
        }
    }
}

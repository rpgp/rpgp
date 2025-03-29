use std::io::{self, BufRead, Read};

use bytes::{Buf, BytesMut};

use super::{fill_buffer, PacketBodyReader};
use crate::{
    packet::{Decompressor, PacketHeader},
    types::Tag,
    DebugBufRead,
};

#[derive(Debug)]
pub enum CompressedDataReader<R: DebugBufRead> {
    Body {
        source: MaybeDecompress<PacketBodyReader<R>>,
        buffer: BytesMut,
    },
    Done {
        source: PacketBodyReader<R>,
    },
    Error,
}

impl<R: DebugBufRead> CompressedDataReader<R> {
    pub fn new(source: PacketBodyReader<R>, decompress: bool) -> io::Result<Self> {
        debug_assert_eq!(source.packet_header().tag(), Tag::CompressedData);

        let source = if decompress {
            let dec = Decompressor::from_reader(source)?;
            MaybeDecompress::Decompress(dec)
        } else {
            MaybeDecompress::Raw(source)
        };

        Ok(Self::Body {
            source,
            buffer: BytesMut::with_capacity(1024),
        })
    }

    pub fn new_done(source: PacketBodyReader<R>) -> Self {
        Self::Done { source }
    }

    pub fn is_done(&self) -> bool {
        matches!(self, Self::Done { .. })
    }

    pub fn into_inner(self) -> PacketBodyReader<R> {
        match self {
            Self::Body { source, .. } => source.into_inner(),
            Self::Done { source, .. } => source,
            Self::Error => {
                panic!("CompressedDataReader errored")
            }
        }
    }

    pub fn get_mut(&mut self) -> &mut PacketBodyReader<R> {
        match self {
            Self::Body { source, .. } => source.get_mut(),
            Self::Done { source, .. } => source,
            Self::Error => {
                panic!("CompressedDataReader errored")
            }
        }
    }

    pub fn packet_header(&self) -> PacketHeader {
        match self {
            Self::Body { ref source, .. } => match source {
                MaybeDecompress::Raw(r) => r.packet_header(),
                MaybeDecompress::Decompress(r) => r.get_ref().packet_header(),
            },
            Self::Done { ref source, .. } => source.packet_header(),
            Self::Error => {
                panic!("CompressedDataReader errored")
            }
        }
    }

    /// Enables decompression
    pub fn decompress(self) -> io::Result<Self> {
        match self {
            Self::Body { source, buffer } => Ok(Self::Body {
                source: source.decompress()?,
                buffer,
            }),
            Self::Done { .. } => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "already finished",
            )),
            Self::Error => Err(io::Error::new(
                io::ErrorKind::Other,
                "CompressedDataReader errored",
            )),
        }
    }
}

impl<R: DebugBufRead> BufRead for CompressedDataReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.fill_inner()?;
        match self {
            Self::Body { ref mut buffer, .. } => Ok(&buffer[..]),
            Self::Done { .. } => Ok(&[][..]),
            Self::Error => Err(io::Error::new(
                io::ErrorKind::Other,
                "CompressedDataReader errored",
            )),
        }
    }

    fn consume(&mut self, amt: usize) {
        match self {
            Self::Body { ref mut buffer, .. } => {
                buffer.advance(amt);
            }
            Self::Done { .. } => {}
            Self::Error => {
                panic!("CompressedDataReader errored");
            }
        }
    }
}

impl<R: DebugBufRead> Read for CompressedDataReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.fill_inner()?;
        match self {
            Self::Body { ref mut buffer, .. } => {
                let to_write = buffer.remaining().min(buf.len());
                buffer.copy_to_slice(&mut buf[..to_write]);
                Ok(to_write)
            }
            Self::Done { .. } => Ok(0),
            Self::Error => Err(io::Error::new(
                io::ErrorKind::Other,
                "CompressedDataReader errored",
            )),
        }
    }
}

impl<R: DebugBufRead> CompressedDataReader<R> {
    fn fill_inner(&mut self) -> io::Result<()> {
        if matches!(self, Self::Done { .. }) {
            return Ok(());
        }

        match std::mem::replace(self, Self::Error) {
            Self::Body {
                mut source,
                mut buffer,
            } => {
                if buffer.has_remaining() {
                    *self = Self::Body { source, buffer };
                    return Ok(());
                }

                buffer.resize(1024, 0);
                let read = fill_buffer(&mut source, &mut buffer, None)?;
                buffer.truncate(read);

                if read == 0 {
                    let source = source.into_inner();

                    *self = Self::Done { source };
                } else {
                    *self = Self::Body { source, buffer };
                }
                Ok(())
            }
            Self::Done { source } => {
                *self = Self::Done { source };
                Ok(())
            }
            Self::Error => Err(io::Error::new(
                io::ErrorKind::Other,
                "CompressedDataReader errored",
            )),
        }
    }
}

#[derive(Debug)]
pub enum MaybeDecompress<R: DebugBufRead> {
    Raw(R),
    Decompress(Decompressor<R>),
}

impl<R: DebugBufRead> MaybeDecompress<R> {
    fn decompress(self) -> io::Result<Self> {
        match self {
            Self::Raw(r) => Ok(Self::Decompress(Decompressor::from_reader(r)?)),
            Self::Decompress(_) => {
                // already decompressing
                Ok(self)
            }
        }
    }
}

impl<R: DebugBufRead> MaybeDecompress<R> {
    fn into_inner(self) -> R {
        match self {
            Self::Raw(r) => r,
            Self::Decompress(r) => r.into_inner(),
        }
    }
    fn get_mut(&mut self) -> &mut R {
        match self {
            Self::Raw(r) => r,
            Self::Decompress(r) => r.get_mut(),
        }
    }
}

impl<R: DebugBufRead> BufRead for MaybeDecompress<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        match self {
            Self::Raw(ref mut r) => r.fill_buf(),
            Self::Decompress(ref mut r) => r.fill_buf(),
        }
    }
    fn consume(&mut self, amt: usize) {
        match self {
            Self::Raw(ref mut r) => r.consume(amt),
            Self::Decompress(ref mut r) => r.consume(amt),
        }
    }
}

impl<R: DebugBufRead> Read for MaybeDecompress<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Raw(ref mut r) => r.read(buf),
            Self::Decompress(ref mut r) => r.read(buf),
        }
    }
}

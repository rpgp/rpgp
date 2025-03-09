use std::io::{self, BufRead, Read};

use bytes::{Buf, BytesMut};

use crate::packet::{Decompressor, PacketHeader};
use crate::types::Tag;

use super::{fill_buffer, PacketBodyReader};

#[derive(Debug)]
pub struct CompressedDataReader<R: BufRead> {
    state: CompressedReaderState<R>,
}

impl<R: BufRead> CompressedDataReader<R> {
    pub fn new(source: PacketBodyReader<R>, decompress: bool) -> io::Result<Self> {
        debug_assert_eq!(source.packet_header().tag(), Tag::CompressedData);

        let source = if decompress {
            let dec = Decompressor::from_reader(source)?;
            MaybeDecompress::Decompress(dec)
        } else {
            MaybeDecompress::Raw(source)
        };

        Ok(Self {
            state: CompressedReaderState::Body {
                source,
                buffer: BytesMut::with_capacity(1024),
            },
        })
    }

    pub fn new_done(source: PacketBodyReader<R>) -> Self {
        Self {
            state: CompressedReaderState::Done { source },
        }
    }

    pub fn is_done(&self) -> bool {
        matches!(self.state, CompressedReaderState::Done { .. })
    }

    pub fn into_inner(self) -> PacketBodyReader<R> {
        match self.state {
            CompressedReaderState::Body { source, .. } => source.into_inner(),
            CompressedReaderState::Done { source, .. } => source,
            CompressedReaderState::Error => panic!("error state"),
        }
    }

    pub fn get_mut(&mut self) -> &mut PacketBodyReader<R> {
        match &mut self.state {
            CompressedReaderState::Body { source, .. } => source.get_mut(),
            CompressedReaderState::Done { source, .. } => source,
            CompressedReaderState::Error => panic!("error state"),
        }
    }

    pub fn packet_header(&self) -> PacketHeader {
        match self.state {
            CompressedReaderState::Body { ref source, .. } => match source {
                MaybeDecompress::Raw(r) => r.packet_header(),
                MaybeDecompress::Decompress(r) => r.get_ref().packet_header(),
            },
            CompressedReaderState::Done { ref source, .. } => source.packet_header(),
            CompressedReaderState::Error => panic!("error state"),
        }
    }

    /// Enables decompression
    pub fn decompress(self) -> io::Result<Self> {
        match self.state {
            CompressedReaderState::Body { source, buffer } => Ok(Self {
                state: CompressedReaderState::Body {
                    source: source.decompress()?,
                    buffer,
                },
            }),
            CompressedReaderState::Done { .. } => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "already finished",
            )),
            CompressedReaderState::Error => {
                Err(io::Error::new(io::ErrorKind::InvalidInput, "errored"))
            }
        }
    }
}

#[derive(Debug)]
enum CompressedReaderState<R: BufRead> {
    Body {
        source: MaybeDecompress<PacketBodyReader<R>>,
        buffer: BytesMut,
    },
    Done {
        source: PacketBodyReader<R>,
    },
    Error,
}

impl<R: BufRead> BufRead for CompressedDataReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.fill_inner()?;
        match self.state {
            CompressedReaderState::Body { ref mut buffer, .. } => Ok(&buffer[..]),
            CompressedReaderState::Done { .. } => Ok(&[][..]),
            CompressedReaderState::Error => panic!("CompressedReader errored"),
        }
    }

    fn consume(&mut self, amt: usize) {
        match self.state {
            CompressedReaderState::Body { ref mut buffer, .. } => {
                buffer.advance(amt);
            }
            CompressedReaderState::Error => panic!("CompressedReader errored"),
            CompressedReaderState::Done { .. } => {}
        }
    }
}

impl<R: BufRead> Read for CompressedDataReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.fill_inner()?;
        match self.state {
            CompressedReaderState::Body { ref mut buffer, .. } => {
                let to_write = buffer.remaining().min(buf.len());
                buffer.copy_to_slice(&mut buf[..to_write]);
                Ok(to_write)
            }
            CompressedReaderState::Done { .. } => Ok(0),
            _ => unreachable!("invalid state"),
        }
    }
}

impl<R: BufRead> CompressedDataReader<R> {
    fn fill_inner(&mut self) -> io::Result<()> {
        if matches!(self.state, CompressedReaderState::Done { .. }) {
            return Ok(());
        }

        match std::mem::replace(&mut self.state, CompressedReaderState::Error) {
            CompressedReaderState::Body {
                mut source,
                mut buffer,
            } => {
                if buffer.has_remaining() {
                    self.state = CompressedReaderState::Body { source, buffer };
                    return Ok(());
                }

                buffer.resize(1024, 0);
                let read = fill_buffer(&mut source, &mut buffer, None)?;
                buffer.truncate(read);

                if read == 0 {
                    let source = source.into_inner();
                    self.state = CompressedReaderState::Done { source };
                } else {
                    self.state = CompressedReaderState::Body { source, buffer };
                }
                Ok(())
            }
            CompressedReaderState::Done { source } => {
                self.state = CompressedReaderState::Done { source };
                Ok(())
            }
            CompressedReaderState::Error => {
                panic!("CompressedReader errored");
            }
        }
    }
}

#[derive(Debug)]
enum MaybeDecompress<R: BufRead> {
    Raw(R),
    Decompress(Decompressor<R>),
}

impl<R: BufRead> MaybeDecompress<R> {
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

impl<R: BufRead> MaybeDecompress<R> {
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

impl<R: BufRead> BufRead for MaybeDecompress<R> {
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

impl<R: BufRead> Read for MaybeDecompress<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Raw(ref mut r) => r.read(buf),
            Self::Decompress(ref mut r) => r.read(buf),
        }
    }
}

use std::io::{self, BufRead, BufReader, Read};
use std::path::Path;

use bytes::{Buf, Bytes, BytesMut};

use crate::packet::{Decompressor, LiteralDataHeader, PacketHeader};
use crate::ser::Serialize;
use crate::types::Tag;
use crate::util::fill_buffer;

use super::DummyReader;

/// Efficiently parse messages.
pub struct MessageReader<R = DummyReader> {
    source: Source<R>,
}

pub enum Source<R = DummyReader> {
    Bytes(bytes::buf::Reader<Bytes>),
    File(BufReader<std::fs::File>),
    Reader(BufReader<R>),
}

impl<R: Read> Read for Source<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Bytes(ref mut r) => r.read(buf),
            Self::File(ref mut r) => r.read(buf),
            Self::Reader(ref mut r) => r.read(buf),
        }
    }
}

impl<R: Read> BufRead for Source<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        match self {
            Self::Bytes(ref mut r) => r.fill_buf(),
            Self::File(ref mut r) => r.fill_buf(),
            Self::Reader(ref mut r) => r.fill_buf(),
        }
    }

    fn consume(&mut self, amt: usize) {
        match self {
            Self::Bytes(ref mut r) => r.consume(amt),
            Self::File(ref mut r) => r.consume(amt),
            Self::Reader(ref mut r) => r.consume(amt),
        }
    }
}

impl MessageReader<DummyReader> {
    /// Source the data from the given file path.
    pub fn from_file(path: impl AsRef<Path>) -> io::Result<Self> {
        let file = std::fs::File::open(path)?;
        let source = Source::File(BufReader::new(file));

        Ok(Self { source })
    }

    /// Source the data from the given byte buffer.
    pub fn from_bytes(bytes: impl Into<Bytes>) -> Self {
        let reader = bytes.into().reader();
        let source = Source::Bytes(reader);

        Self { source }
    }
}

impl<R: Read> MessageReader<R> {
    pub fn from_reader(reader: R) -> Self {
        let source = Source::Reader(BufReader::new(reader));

        Self { source }
    }

    pub fn get_literal_reader(&mut self) -> LiteralReader<&'_ mut Source<R>> {
        LiteralReader {
            state: LiteralReaderState::Header {
                source: &mut self.source,
            },
        }
    }

    pub fn get_literal_decompress_reader(
        &mut self,
        decompress: bool,
    ) -> LiteralReader<CompressedReader<&'_ mut Source<R>>> {
        LiteralReader {
            state: LiteralReaderState::Header {
                source: CompressedReader {
                    state: CompressedReaderState::Header {
                        source: &mut self.source,
                        decompress,
                    },
                },
            },
        }
    }
}

#[derive(Debug)]
pub struct CompressedReader<R: BufRead> {
    state: CompressedReaderState<R>,
}

#[derive(Debug)]
enum CompressedReaderState<R: BufRead> {
    Header {
        source: R,
        decompress: bool,
    },
    Body {
        packet_header: PacketHeader,
        source: MaybeDecompress<R>,
        buffer: BytesMut,
    },
    Done {
        packet_header: PacketHeader,
        source: MaybeDecompress<R>,
    },
    Error,
}

impl<R: BufRead> BufRead for CompressedReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.fill_inner()?;
        match self.state {
            CompressedReaderState::Body { ref mut buffer, .. } => Ok(&buffer[..]),
            CompressedReaderState::Done { .. } => Ok(&[][..]),
            CompressedReaderState::Error => panic!("CompressedReader errored"),
            CompressedReaderState::Header { .. } => unreachable!("invalid state"),
        }
    }

    fn consume(&mut self, amt: usize) {
        match self.state {
            CompressedReaderState::Body { ref mut buffer, .. } => {
                buffer.advance(amt);
            }
            _ => panic!("invalid call"),
        }
    }
}

impl<R: BufRead> Read for CompressedReader<R> {
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

impl<R: BufRead> CompressedReader<R> {
    fn fill_inner(&mut self) -> io::Result<()> {
        if matches!(self.state, CompressedReaderState::Done { .. }) {
            return Ok(());
        }

        loop {
            match std::mem::replace(&mut self.state, CompressedReaderState::Error) {
                CompressedReaderState::Header {
                    mut source,
                    decompress,
                } => {
                    let packet_header = PacketHeader::from_reader(&mut source)?;
                    if packet_header.tag() != Tag::CompressedData {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("unexpected tag: {:?}", packet_header.tag()),
                        ));
                    }

                    // TODO: deal with partial packets

                    let source = if decompress {
                        let dec = Decompressor::from_reader(source)?;
                        MaybeDecompress::Decompress(dec)
                    } else {
                        MaybeDecompress::Raw(source)
                    };

                    self.state = CompressedReaderState::Body {
                        packet_header,
                        source,
                        buffer: BytesMut::with_capacity(1024),
                    }
                }
                CompressedReaderState::Body {
                    packet_header,
                    mut source,
                    mut buffer,
                } => {
                    if buffer.has_remaining() {
                        self.state = CompressedReaderState::Body {
                            packet_header,
                            source,
                            buffer,
                        };
                        return Ok(());
                    }

                    buffer.resize(1024, 0);
                    let read = fill_buffer(&mut source, &mut buffer, None)?;
                    buffer.truncate(read);

                    if read == 0 {
                        self.state = CompressedReaderState::Done {
                            packet_header,
                            source,
                        };
                    } else {
                        self.state = CompressedReaderState::Body {
                            packet_header,
                            source,
                            buffer,
                        };
                    }
                    return Ok(());
                }
                CompressedReaderState::Done {
                    packet_header,
                    source,
                } => {
                    self.state = CompressedReaderState::Done {
                        packet_header,
                        source,
                    };
                    return Ok(());
                }
                CompressedReaderState::Error => {
                    panic!("CompressedReader errored");
                }
            }
        }
    }
}

/// Read the underlying literal data.
#[derive(Debug)]
pub struct LiteralReader<R: BufRead> {
    state: LiteralReaderState<R>,
}

#[derive(derive_more::Debug)]
enum MaybeDecompress<R: BufRead> {
    Raw(R),
    Decompress(Decompressor<R>),
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

#[derive(Debug)]
enum LiteralReaderState<R: BufRead> {
    Header {
        source: R,
    },
    LiteralHeader {
        source: R,
        packet_header: PacketHeader,
        total_read: usize,
    },
    Body {
        source: R,
        buffer: BytesMut,
        packet_header: PacketHeader,
        header: LiteralDataHeader,
        /// How many bytes have been read of the "packet" part
        /// where "read" means, actually externalized
        total_read: usize,
    },
    Done {
        source: R,
        packet_header: PacketHeader,
        header: LiteralDataHeader,
    },
    Error,
}

impl<R: BufRead> Read for LiteralReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if matches!(self.state, LiteralReaderState::Done { .. }) {
            return Ok(0);
        }

        loop {
            match std::mem::replace(&mut self.state, LiteralReaderState::Error) {
                LiteralReaderState::Header { mut source } => {
                    let header = PacketHeader::from_reader(&mut source)?;
                    if header.tag() != Tag::LiteralData {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("unexpected tag: {:?}", header.tag()),
                        ));
                    }

                    // TODO: deal with partial packets

                    self.state = LiteralReaderState::LiteralHeader {
                        source,
                        packet_header: header,
                        total_read: 0,
                    };
                }
                LiteralReaderState::LiteralHeader {
                    mut source,
                    packet_header,
                    mut total_read,
                } => {
                    let header = LiteralDataHeader::from_reader(&mut source)?;
                    total_read += header.write_len();

                    self.state = LiteralReaderState::Body {
                        source,
                        buffer: BytesMut::with_capacity(1024),
                        packet_header,
                        header,
                        total_read,
                    }
                }
                LiteralReaderState::Body {
                    mut source,
                    mut buffer,
                    packet_header,
                    header,
                    mut total_read,
                } => {
                    if !buffer.has_remaining() {
                        let limit = packet_header
                            .packet_length()
                            .maybe_len()
                            .map(|limit| 1024.min(limit as usize - total_read));

                        buffer.resize(1024, 0);
                        let read = fill_buffer(&mut source, &mut buffer, limit)?;

                        buffer.truncate(read);
                        total_read += read;

                        if read == 0 {
                            // done reading the source
                            self.state = LiteralReaderState::Done {
                                source,
                                packet_header,
                                header,
                            };
                            continue;
                        }
                    }
                    let to_write = buffer.remaining().min(buf.len());
                    buffer.copy_to_slice(&mut buf[..to_write]);

                    self.state = LiteralReaderState::Body {
                        source,
                        buffer,
                        packet_header,
                        header,
                        total_read,
                    };

                    return Ok(to_write);
                }
                LiteralReaderState::Done {
                    source,
                    packet_header,
                    header,
                } => {
                    self.state = LiteralReaderState::Done {
                        source,
                        packet_header,
                        header,
                    };
                    return Ok(0);
                }
                LiteralReaderState::Error => {
                    panic!("LiteralReader errored");
                }
            }
        }
    }
}

impl<R: BufRead> LiteralReader<R> {
    pub fn data_header(&self) -> Option<&LiteralDataHeader> {
        match self.state {
            LiteralReaderState::Done { ref header, .. } => Some(header),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::types::CompressionAlgorithm;
    use crate::util::test::{check_strings, random_string, ChaosReader};

    use super::*;

    use crate::message::Builder;
    use crate::packet::DataMode;

    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;
    use testresult::TestResult;

    #[test]
    fn test_read_literal_data_no_compression() -> TestResult {
        let _ = pretty_env_logger::try_init();
        let mut rng = ChaCha8Rng::seed_from_u64(1);

        for file_size in (1..2048).step_by(10) {
            let buf = random_string(&mut rng, file_size);
            let message = Builder::from_bytes("test.txt", buf.clone())
                .data_mode(DataMode::Binary)
                .to_vec(&mut rng)?;

            let mut reader = ChaosReader::new(rng.clone(), message.clone());
            let mut msg_reader = MessageReader::from_reader(&mut reader);
            let mut lit_reader = msg_reader.get_literal_reader();

            let mut out = String::new();
            lit_reader.read_to_string(&mut out)?;

            check_strings(out, buf);

            let header = lit_reader.data_header().unwrap();
            assert_eq!(header.file_name, &b"test.txt"[..]);
            assert_eq!(header.mode, DataMode::Binary);
        }
        Ok(())
    }

    #[test]
    fn test_read_literal_data_compression_zip() -> TestResult {
        let _ = pretty_env_logger::try_init();
        let mut rng = ChaCha8Rng::seed_from_u64(1);

        for file_size in (1..2048).step_by(10) {
            println!("--- size: {file_size}");
            let buf = random_string(&mut rng, file_size);

            let message = Builder::from_bytes("test.txt", buf.clone())
                .data_mode(DataMode::Binary)
                .compression(CompressionAlgorithm::ZIP)
                .to_vec(&mut rng)?;

            let mut reader = ChaosReader::new(rng.clone(), message.clone());
            let mut msg_reader = MessageReader::from_reader(&mut reader);
            let mut lit_reader = msg_reader.get_literal_decompress_reader(true);

            let mut out = String::new();
            lit_reader.read_to_string(&mut out)?;

            check_strings(out, buf);

            let header = lit_reader.data_header().unwrap();
            assert_eq!(header.file_name, &b"test.txt"[..]);
            assert_eq!(header.mode, DataMode::Binary);
        }
        Ok(())
    }
}

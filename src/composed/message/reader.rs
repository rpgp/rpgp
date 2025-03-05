use std::io::{self, BufRead, BufReader, Read};
use std::path::Path;

use bytes::{Buf, Bytes, BytesMut};
use log::debug;

use super::DummyReader;
use crate::packet::{Decompressor, LiteralDataHeader, PacketHeader};
use crate::types::{PacketLength, Tag};
use crate::util::fill_buffer;

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

    pub fn get_literal_reader(&mut self) -> LiteralDataReader<&'_ mut Source<R>> {
        todo!()
    }

    pub fn get_literal_decompress_reader(
        &mut self,
        decompress: bool,
    ) -> LiteralDataReader<CompressedDataReader<&'_ mut Source<R>>> {
        todo!()
    }
}

#[derive(derive_more::Debug)]
pub struct PacketBodyReader<R: BufRead> {
    packet_header: PacketHeader,
    state: PacketBodyReaderState<R>,
}

#[derive(derive_more::Debug)]
enum PacketBodyReaderState<R: BufRead> {
    Header {
        #[debug("source")]
        source: R,
    },
    Body {
        buffer: BytesMut,
        source: LimitedSource<R>,
    },
    Done {
        #[debug("source")]
        source: R,
    },
    Error,
}

impl<R: BufRead> BufRead for PacketBodyReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.fill_inner()?;
        match self.state {
            PacketBodyReaderState::Body { ref mut buffer, .. } => Ok(&buffer[..]),
            PacketBodyReaderState::Done { .. } => Ok(&[][..]),
            PacketBodyReaderState::Header { .. } => unreachable!("invalid state: header"),
            PacketBodyReaderState::Error => panic!("PacketBodyReader errored"),
        }
    }

    fn consume(&mut self, amt: usize) {
        match self.state {
            PacketBodyReaderState::Body { ref mut buffer, .. } => {
                buffer.advance(amt);
            }
            PacketBodyReaderState::Error => panic!("PacketBodyreader errored"),
            PacketBodyReaderState::Header { .. } => unreachable!("invalid state: header"),
            PacketBodyReaderState::Done { .. } => {}
        }
    }
}

impl<R: BufRead> Read for PacketBodyReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.fill_inner()?;
        match self.state {
            PacketBodyReaderState::Body { ref mut buffer, .. } => {
                let to_write = buffer.remaining().min(buf.len());
                buffer.copy_to_slice(&mut buf[..to_write]);
                Ok(to_write)
            }
            PacketBodyReaderState::Done { .. } => Ok(0),
            _ => unreachable!("invalid state"),
        }
    }
}

impl<R: BufRead> PacketBodyReader<R> {
    pub fn new(packet_header: PacketHeader, source: R) -> Self {
        Self {
            packet_header,
            state: PacketBodyReaderState::Header { source },
        }
    }

    pub fn into_inner(self) -> R {
        match self.state {
            PacketBodyReaderState::Header { source } => source,
            PacketBodyReaderState::Body { source, .. } => source.into_inner(),
            PacketBodyReaderState::Done { source } => source,
            PacketBodyReaderState::Error => panic!("PacketBodyReader errored"),
        }
    }

    pub fn packet_header(&self) -> PacketHeader {
        self.packet_header
    }

    fn fill_inner(&mut self) -> io::Result<()> {
        if matches!(self.state, PacketBodyReaderState::Done { .. }) {
            return Ok(());
        }

        loop {
            match std::mem::replace(&mut self.state, PacketBodyReaderState::Error) {
                PacketBodyReaderState::Header { source } => {
                    let source = match self.packet_header.packet_length() {
                        PacketLength::Fixed(len) => LimitedSource::Fixed(source.take(len as u64)),
                        PacketLength::Indeterminate => LimitedSource::Indeterminate(source),
                        PacketLength::Partial(len) => {
                            // https://www.rfc-editor.org/rfc/rfc9580.html#name-partial-body-lengths
                            // "An implementation MAY use Partial Body Lengths for data packets, be
                            // they literal, compressed, or encrypted [...]
                            // Partial Body Lengths MUST NOT be used for any other packet types"
                            if !matches!(
                                self.packet_header.tag(),
                                Tag::LiteralData
                                    | Tag::CompressedData
                                    | Tag::SymEncryptedData
                                    | Tag::SymEncryptedProtectedData
                            ) {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidInput,
                                    format!(
                                        "Partial body length is not allowed for packet type {:?}",
                                        self.packet_header.tag()
                                    ),
                                ));
                            }

                            // https://www.rfc-editor.org/rfc/rfc9580.html#section-4.2.1.4-5
                            // "The first partial length MUST be at least 512 octets long."
                            if len < 512 {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidInput,
                                    format!("Illegal first partial body length {} (shorter than 512 bytes)", len)
                                ));
                            }

                            LimitedSource::Partial(source.take(len as u64))
                        }
                    };

                    self.state = PacketBodyReaderState::Body {
                        source,
                        buffer: BytesMut::with_capacity(1024),
                    };
                }
                PacketBodyReaderState::Body {
                    mut buffer,
                    mut source,
                } => {
                    if buffer.has_remaining() {
                        self.state = PacketBodyReaderState::Body { source, buffer };
                        return Ok(());
                    }

                    buffer.resize(1024, 0);
                    let read = fill_buffer(&mut source, &mut buffer, None)?;
                    buffer.truncate(read);

                    if read == 0 {
                        match source {
                            LimitedSource::Fixed(r) => {
                                self.state = PacketBodyReaderState::Done {
                                    source: r.into_inner(),
                                };
                            }
                            LimitedSource::Indeterminate(source) => {
                                self.state = PacketBodyReaderState::Done { source };
                            }
                            LimitedSource::Partial(r) => {
                                // new round
                                let mut source = r.into_inner();
                                let packet_length = PacketLength::from_reader(&mut source)?;

                                let source = match packet_length {
                                    PacketLength::Fixed(len) => {
                                        // the last one
                                        debug!("fixed partial packet {}", len);
                                        LimitedSource::Fixed(source.take(len as u64))
                                    }
                                    PacketLength::Partial(len) => {
                                        // another one
                                        debug!("intermediary partial packet {}", len);
                                        LimitedSource::Partial(source.take(len as u64))
                                    }
                                    PacketLength::Indeterminate => {
                                        return Err(io::Error::new(
                                            io::ErrorKind::InvalidInput,
                                            "invalid indeterminate packet length",
                                        ));
                                    }
                                };

                                self.state = PacketBodyReaderState::Body { source, buffer };
                                continue;
                            }
                        };
                    } else {
                        self.state = PacketBodyReaderState::Body { source, buffer };
                    }
                    return Ok(());
                }
                PacketBodyReaderState::Done { source } => {
                    self.state = PacketBodyReaderState::Done { source };
                    return Ok(());
                }
                PacketBodyReaderState::Error => {
                    panic!("PacketBodyReader errored");
                }
            }
        }
    }
}

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

    pub fn packet_header(&self) -> PacketHeader {
        match self {
            Self::Header { source, .. } => source.packet_header(),
            Self::Body { source, .. } => source.packet_header(),
            Self::Done { source, .. } => source.packet_header(),
            Self::Error => panic!("error state"),
        }
    }
}

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

impl<R: BufRead> SymEncryptedDataReader<R> {
    pub fn new(source: PacketBodyReader<R>) -> io::Result<Self> {
        debug_assert_eq!(source.packet_header().tag(), Tag::SymEncryptedData);

        Ok(Self::Body {
            source,
            buffer: BytesMut::with_capacity(1024),
        })
    }

    pub fn packet_header(&self) -> PacketHeader {
        match self {
            Self::Body { source, .. } => source.packet_header(),
            Self::Done { source, .. } => source.packet_header(),
            Self::Error => panic!("error state"),
        }
    }
}

#[derive(derive_more::Debug)]
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

    /// Enables decompression
    pub fn decompress(self) -> io::Result<Self> {
        match self.state {
            CompressedReaderState::Body { mut source, buffer } => Ok(Self {
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

#[derive(derive_more::Debug)]
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

        loop {
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
                    return Ok(());
                }
                CompressedReaderState::Done { source } => {
                    self.state = CompressedReaderState::Done { source };
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
#[derive(derive_more::Debug)]
pub struct LiteralDataReader<R: BufRead> {
    state: LiteralReaderState<R>,
}

#[derive(derive_more::Debug)]
enum MaybeDecompress<R: BufRead> {
    Raw(#[debug("R")] R),
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

#[derive(derive_more::Debug)]
enum LiteralReaderState<R: BufRead> {
    LiteralHeader {
        source: PacketBodyReader<R>,
    },
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
    pub fn new(source: PacketBodyReader<R>) -> Self {
        debug_assert_eq!(source.packet_header().tag(), Tag::LiteralData);
        Self {
            state: LiteralReaderState::LiteralHeader { source },
        }
    }
}

#[derive(derive_more::Debug)]
enum LimitedSource<R: BufRead> {
    Fixed(#[debug("Take<R>")] io::Take<R>),
    Indeterminate(#[debug("R")] R),
    Partial(#[debug("Take<R>")] io::Take<R>),
}

impl<R: BufRead> BufRead for LimitedSource<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        match self {
            Self::Fixed(ref mut r) => r.fill_buf(),
            Self::Indeterminate(ref mut r) => r.fill_buf(),
            Self::Partial(ref mut r) => r.fill_buf(),
        }
    }

    fn consume(&mut self, amt: usize) {
        match self {
            Self::Fixed(ref mut r) => r.consume(amt),
            Self::Indeterminate(ref mut r) => r.consume(amt),
            Self::Partial(ref mut r) => r.consume(amt),
        }
    }
}

impl<R: BufRead> Read for LimitedSource<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Fixed(ref mut r) => r.read(buf),
            Self::Indeterminate(ref mut r) => r.read(buf),
            Self::Partial(ref mut r) => r.read(buf),
        }
    }
}

impl<R: BufRead> LimitedSource<R> {
    fn into_inner(self) -> R {
        match self {
            Self::Fixed(source) => source.into_inner(),
            Self::Indeterminate(source) => source,
            Self::Partial(source) => source.into_inner(),
        }
    }
}

impl<R: BufRead> Read for LiteralDataReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if matches!(self.state, LiteralReaderState::Done { .. }) {
            return Ok(0);
        }

        loop {
            match std::mem::replace(&mut self.state, LiteralReaderState::Error) {
                LiteralReaderState::LiteralHeader { mut source } => {
                    debug!("literal packet: literal header");
                    let header = LiteralDataHeader::from_reader(&mut source)?;

                    self.state = LiteralReaderState::Body {
                        source,
                        buffer: BytesMut::with_capacity(1024),
                        header,
                    }
                }
                LiteralReaderState::Body {
                    mut source,
                    mut buffer,
                    header,
                } => {
                    debug!("literal packet: body");

                    if !buffer.has_remaining() {
                        debug!("literal packet: filling buffer");

                        buffer.resize(1024, 0);
                        let read = fill_buffer(&mut source, &mut buffer, None)?;

                        buffer.truncate(read);

                        if read == 0 {
                            // done reading the source
                            self.state = LiteralReaderState::Done { source, header };
                            continue;
                        }
                    }
                    let to_write = buffer.remaining().min(buf.len());
                    buffer.copy_to_slice(&mut buf[..to_write]);

                    self.state = LiteralReaderState::Body {
                        source,
                        buffer,
                        header,
                    };

                    return Ok(to_write);
                }
                LiteralReaderState::Done { source, header } => {
                    debug!("literal packet: done");
                    self.state = LiteralReaderState::Done { source, header };
                    return Ok(0);
                }
                LiteralReaderState::Error => {
                    panic!("LiteralReader errored");
                }
            }
        }
    }
}

impl<R: BufRead> LiteralDataReader<R> {
    pub fn data_header(&self) -> Option<&LiteralDataHeader> {
        match self.state {
            LiteralReaderState::Done { ref header, .. } => Some(header),
            _ => None,
        }
    }
}

#[derive(Debug)]
struct DebugPacketBodyReader(PacketBodyReader<Box<dyn BufRead>>);
#[derive(Debug)]
struct DebugMaybeDecompress(MaybeDecompress<PacketBodyReader<Box<dyn BufRead>>>);

#[derive(Debug)]
struct DebugB(CompressedReaderState<Box<dyn BufRead>>);

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;
    use testresult::TestResult;

    use super::*;
    use crate::message::Builder;
    use crate::packet::DataMode;
    use crate::types::CompressionAlgorithm;
    use crate::util::test::{check_strings, random_string, ChaosReader};

    #[test]
    fn test_read_literal_data_no_compression() -> TestResult {
        let _ = pretty_env_logger::try_init();
        let mut rng = ChaCha8Rng::seed_from_u64(1);

        for file_size in (1..1024 * 10).step_by(100) {
            for is_partial in [true, false] {
                println!("--- size: {file_size}, is_partial: {is_partial}");

                let buf = random_string(&mut rng, file_size);
                let message = if is_partial {
                    Builder::from_reader("test.txt", buf.as_bytes())
                        .data_mode(DataMode::Binary)
                        .partial_chunk_size(512)?
                        .to_vec(&mut rng)?
                } else {
                    Builder::from_bytes("test.txt", buf.clone())
                        .data_mode(DataMode::Binary)
                        .to_vec(&mut rng)?
                };

                let mut reader = ChaosReader::new(rng.clone(), message.clone());
                let mut msg_reader = MessageReader::from_reader(&mut reader);
                let mut lit_reader = msg_reader.get_literal_reader();

                let mut out = String::new();
                lit_reader.read_to_string(&mut out)?;

                check_strings(out, buf);

                let header = lit_reader.data_header().unwrap();
                assert_eq!(header.file_name(), &b""[..]);
                assert_eq!(header.mode(), DataMode::Binary);
            }
        }
        Ok(())
    }

    #[test]
    fn test_read_literal_data_compression_zip() -> TestResult {
        let _ = pretty_env_logger::try_init();
        let mut rng = ChaCha8Rng::seed_from_u64(1);

        for file_size in (1..1024 * 10).step_by(100) {
            for is_partial in [true, false] {
                println!("--- size: {file_size}, is_partial: {is_partial}");
                let buf = random_string(&mut rng, file_size);

                let message = if is_partial {
                    Builder::from_reader("test.txt", buf.as_bytes())
                        .data_mode(DataMode::Binary)
                        .compression(CompressionAlgorithm::ZIP)
                        .partial_chunk_size(512)?
                        .to_vec(&mut rng)?
                } else {
                    Builder::from_bytes("test.txt", buf.clone())
                        .data_mode(DataMode::Binary)
                        .compression(CompressionAlgorithm::ZIP)
                        .to_vec(&mut rng)?
                };
                let mut reader = ChaosReader::new(rng.clone(), message.clone());
                let mut msg_reader = MessageReader::from_reader(&mut reader);
                let mut lit_reader = msg_reader.get_literal_decompress_reader(true);

                let mut out = String::new();
                lit_reader.read_to_string(&mut out)?;

                check_strings(out, buf);

                let header = lit_reader.data_header().unwrap();
                assert_eq!(header.file_name(), &b""[..]);
                assert_eq!(header.mode(), DataMode::Binary);
            }
        }
        Ok(())
    }
}

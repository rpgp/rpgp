use std::io::{self, BufRead, BufReader, Read};

use byteorder::WriteBytesExt;
use bytes::{Buf, BufMut, Bytes, BytesMut};
#[cfg(feature = "bzip2")]
use bzip2::bufread::BzDecoder;
use flate2::bufread::{DeflateDecoder, ZlibDecoder};
use log::debug;

use crate::{
    errors::{ensure, unsupported_err, Result},
    packet::{PacketHeader, PacketTrait},
    parsing_reader::BufReadParsing,
    ser::Serialize,
    types::{CompressionAlgorithm, PacketHeaderVersion, PacketLength, Tag},
    util::fill_buffer,
};

/// Packet for compressed data.
///
/// Ref <https://www.rfc-editor.org/rfc/rfc9580.html#name-compressed-data-packet-type>
#[derive(Clone, PartialEq, Eq, derive_more::Debug)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct CompressedData {
    packet_header: PacketHeader,
    compression_algorithm: CompressionAlgorithm,
    #[debug("{}", hex::encode(compressed_data))]
    #[cfg_attr(test, proptest(strategy = "tests::compressed_data_gen()"))]
    compressed_data: Bytes,
}

/// Structure to decompress a given reader.
#[derive(derive_more::Debug)]
pub enum Decompressor<R> {
    Uncompressed(R),
    Zip(BufReader<DeflateDecoder<R>>),
    Zlib(BufReader<ZlibDecoder<R>>),
    #[cfg(feature = "bzip2")]
    Bzip2(#[debug("BzDecoder")] BufReader<BzDecoder<R>>),
}

impl<R: BufRead> Decompressor<R> {
    pub fn from_reader(mut r: R) -> io::Result<Self> {
        debug!("reading decompressor");
        let alg = r.read_u8().map(CompressionAlgorithm::from)?;
        Self::from_algorithm(alg, r)
    }

    pub fn from_algorithm(alg: CompressionAlgorithm, r: R) -> io::Result<Self> {
        debug!("creating decompressor for {alg:?}");
        match alg {
            CompressionAlgorithm::Uncompressed => Ok(Self::Uncompressed(r)),
            CompressionAlgorithm::ZIP => Ok(Self::Zip(BufReader::new(DeflateDecoder::new(r)))),
            CompressionAlgorithm::ZLIB => Ok(Self::Zlib(BufReader::new(ZlibDecoder::new(r)))),
            #[cfg(feature = "bzip2")]
            CompressionAlgorithm::BZip2 => Ok(Self::Bzip2(BufReader::new(BzDecoder::new(r)))),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported compression algorithm {alg:?}"),
            )),
        }
    }

    pub fn get_ref(&self) -> &R {
        match self {
            Self::Uncompressed(r) => r,
            Self::Zip(r) => r.get_ref().get_ref(),
            Self::Zlib(r) => r.get_ref().get_ref(),
            #[cfg(feature = "bzip2")]
            Self::Bzip2(r) => r.get_ref().get_ref(),
        }
    }

    pub fn get_mut(&mut self) -> &mut R {
        match self {
            Self::Uncompressed(r) => r,
            Self::Zip(r) => r.get_mut().get_mut(),
            Self::Zlib(r) => r.get_mut().get_mut(),
            #[cfg(feature = "bzip2")]
            Self::Bzip2(r) => r.get_mut().get_mut(),
        }
    }

    pub fn into_inner(self) -> R {
        match self {
            Self::Uncompressed(r) => r,
            Self::Zip(r) => r.into_inner().into_inner(),
            Self::Zlib(r) => r.into_inner().into_inner(),
            #[cfg(feature = "bzip2")]
            Self::Bzip2(r) => r.into_inner().into_inner(),
        }
    }
}

impl<R: BufRead> BufRead for Decompressor<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        match self {
            Decompressor::Uncompressed(ref mut c) => c.fill_buf(),
            Decompressor::Zip(ref mut c) => c.fill_buf(),
            Decompressor::Zlib(ref mut c) => c.fill_buf(),
            #[cfg(feature = "bzip2")]
            Decompressor::Bzip2(ref mut c) => c.fill_buf(),
        }
    }

    fn consume(&mut self, amt: usize) {
        match self {
            Decompressor::Uncompressed(ref mut c) => c.consume(amt),
            Decompressor::Zip(ref mut c) => c.consume(amt),
            Decompressor::Zlib(ref mut c) => c.consume(amt),
            #[cfg(feature = "bzip2")]
            Decompressor::Bzip2(ref mut c) => c.consume(amt),
        }
    }
}

impl<R: BufRead> Read for Decompressor<R> {
    fn read(&mut self, into: &mut [u8]) -> io::Result<usize> {
        match self {
            Decompressor::Uncompressed(ref mut c) => c.read(into),
            Decompressor::Zip(ref mut c) => c.read(into),
            Decompressor::Zlib(ref mut c) => c.read(into),
            #[cfg(feature = "bzip2")]
            Decompressor::Bzip2(ref mut c) => c.read(into),
        }
    }
}

impl CompressedData {
    /// Parses a `CompressedData` packet from the given `Buf`.
    pub fn try_from_reader<B: BufRead>(packet_header: PacketHeader, mut input: B) -> Result<Self> {
        let alg = input.read_u8().map(CompressionAlgorithm::from)?;

        Ok(CompressedData {
            packet_header,
            compression_algorithm: alg,
            compressed_data: input.rest()?.freeze(),
        })
    }

    /// Create the structure from the raw compressed data.
    #[cfg(test)]
    fn from_compressed(alg: CompressionAlgorithm, data: impl Into<Bytes>) -> Result<Self> {
        let compressed_data = data.into();
        let len = 1 + compressed_data.len();
        let packet_header = PacketHeader::new_fixed(Tag::CompressedData, len.try_into()?);

        Ok(CompressedData {
            packet_header,
            compression_algorithm: alg,
            compressed_data,
        })
    }

    /// Creates a decompressor.
    pub fn decompress(&self) -> Result<Decompressor<&[u8]>> {
        let decompressor =
            Decompressor::from_algorithm(self.compression_algorithm, &self.compressed_data[..])?;
        Ok(decompressor)
    }

    /// Returns a reference to raw compressed data.
    pub fn compressed_data(&self) -> &[u8] {
        &self.compressed_data
    }
}

impl Serialize for CompressedData {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u8(self.compression_algorithm.into())?;
        writer.write_all(&self.compressed_data)?;

        Ok(())
    }

    fn write_len(&self) -> usize {
        1 + self.compressed_data.len()
    }
}

impl PacketTrait for CompressedData {
    fn packet_header(&self) -> &PacketHeader {
        &self.packet_header
    }
}

pub(crate) enum Compressor<R: io::Read> {
    Uncompressed(R),
    Zip(flate2::read::DeflateEncoder<R>),
    Zlib(flate2::read::ZlibEncoder<R>),
    #[cfg(feature = "bzip2")]
    Bzip2(bzip2::read::BzEncoder<R>),
}

impl<R: io::Read> io::Read for Compressor<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Uncompressed(r) => r.read(buf),
            Self::Zip(r) => r.read(buf),
            Self::Zlib(r) => r.read(buf),
            #[cfg(feature = "bzip2")]
            Self::Bzip2(r) => r.read(buf),
        }
    }
}

impl<R: io::Read> Compressor<R> {
    fn new(alg: CompressionAlgorithm, source: R) -> Result<Self> {
        match alg {
            CompressionAlgorithm::Uncompressed => Ok(Self::Uncompressed(source)),
            CompressionAlgorithm::ZIP => Ok(Self::Zip(flate2::read::DeflateEncoder::new(
                source,
                Default::default(),
            ))),
            CompressionAlgorithm::ZLIB => Ok(Compressor::Zlib(flate2::read::ZlibEncoder::new(
                source,
                Default::default(),
            ))),
            #[cfg(feature = "bzip2")]
            CompressionAlgorithm::BZip2 => Ok(Compressor::Bzip2(bzip2::read::BzEncoder::new(
                source,
                Default::default(),
            ))),
            #[cfg(not(feature = "bzip2"))]
            CompressionAlgorithm::BZip2 => {
                unsupported_err!("Bzip2 compression is unsupported");
            }
            CompressionAlgorithm::Private10 | CompressionAlgorithm::Other(_) => {
                unsupported_err!("CompressionAlgorithm {:?} is unsupported", alg)
            }
        }
    }

    fn algorithm(&self) -> CompressionAlgorithm {
        match self {
            Self::Uncompressed(_) => CompressionAlgorithm::Uncompressed,
            Self::Zip(_) => CompressionAlgorithm::ZIP,
            Self::Zlib(_) => CompressionAlgorithm::ZLIB,
            #[cfg(feature = "bzip2")]
            Self::Bzip2(_) => CompressionAlgorithm::BZip2,
        }
    }
}

#[allow(clippy::large_enum_variant)]
pub(crate) enum CompressedDataGenerator<R: io::Read> {
    Fixed(CompressedDataFixedGenerator<R>),
    Partial(CompressedDataPartialGenerator<R>),
}

impl<R: io::Read> CompressedDataGenerator<R> {
    pub(crate) fn new(
        alg: CompressionAlgorithm,
        source: R,
        source_len: Option<u32>,
        chunk_size: u32,
    ) -> Result<Self> {
        let source = Compressor::new(alg, source)?;

        match source_len {
            Some(source_len) => {
                let gen = CompressedDataFixedGenerator::new(source, source_len)?;
                Ok(Self::Fixed(gen))
            }
            None => {
                let gen = CompressedDataPartialGenerator::new(source, chunk_size)?;
                Ok(Self::Partial(gen))
            }
        }
    }
}

impl<R: io::Read> io::Read for CompressedDataGenerator<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Fixed(ref mut fixed) => fixed.read(buf),
            Self::Partial(ref mut partial) => partial.read(buf),
        }
    }
}

pub(crate) struct CompressedDataFixedGenerator<R: io::Read> {
    /// The serialized packet header
    header: Vec<u8>,
    /// Data source
    source: Compressor<R>,
    /// how many bytes of the header have we written already
    header_written: usize,
}

impl<R: io::Read> CompressedDataFixedGenerator<R> {
    pub(crate) fn new(source: Compressor<R>, source_len: u32) -> Result<Self> {
        let len = source_len + 1;
        let packet_header = PacketHeader::new_fixed(Tag::CompressedData, len);
        let mut serialized_header = Vec::new();
        packet_header.to_writer(&mut serialized_header)?;
        serialized_header.write_u8(source.algorithm().into())?;

        Ok(Self {
            header: serialized_header,
            source,
            header_written: 0,
        })
    }
}

impl<R: io::Read> io::Read for CompressedDataFixedGenerator<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let header_bytes_left = self.header.len() - self.header_written;
        if header_bytes_left > 0 {
            // write header
            let to_write = header_bytes_left.min(buf.len());
            buf[..to_write]
                .copy_from_slice(&self.header[self.header_written..self.header_written + to_write]);
            self.header_written += to_write;
            Ok(to_write)
        } else {
            // write source
            self.source.read(buf)
        }
    }
}

pub(crate) struct CompressedDataPartialGenerator<R: io::Read> {
    /// Data source
    source: Compressor<R>,
    /// buffer for the individual data
    buffer: Box<[u8]>,
    chunk_size: u32,
    is_done: bool,
    is_first: bool,
    /// Did we emit a (final) fixed packet yet?
    is_fixed_emitted: bool,
    /// Serialized version of the packet being written currently.
    current_packet: BytesMut,
}

impl<R: io::Read> CompressedDataPartialGenerator<R> {
    pub(crate) fn new(source: Compressor<R>, chunk_size: u32) -> Result<Self> {
        ensure!(chunk_size >= 512, "chunk size must be larger than 512");
        ensure!(
            chunk_size.is_power_of_two(),
            "chunk size must be a power of two"
        );
        Ok(Self {
            source,
            buffer: vec![0u8; chunk_size as usize].into_boxed_slice(),
            chunk_size,
            is_done: false,
            is_first: true,
            is_fixed_emitted: false,
            current_packet: BytesMut::with_capacity(chunk_size as usize),
        })
    }
}

impl<R: io::Read> io::Read for CompressedDataPartialGenerator<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.current_packet.has_remaining() {
            if self.is_done && self.is_fixed_emitted {
                return Ok(0);
            }

            let chunk_size = if self.is_first {
                self.chunk_size as usize - 1
            } else {
                self.chunk_size as usize
            };

            let buf_size = match fill_buffer(&mut self.source, &mut self.buffer, Some(chunk_size)) {
                Ok(size) => size,
                Err(err) => {
                    self.is_done = true;
                    return Err(err);
                }
            };

            debug!("read chunk {buf_size} bytes");
            debug_assert!(buf_size <= u32::MAX as usize);

            if buf_size == 0 && self.is_fixed_emitted {
                self.is_done = true;
                return Ok(0);
            }

            let data = &self.buffer[..buf_size];

            let packet_length = if self.is_first && buf_size < chunk_size {
                // all data fits into a single packet
                self.is_done = true;
                self.is_fixed_emitted = true;
                let len = (buf_size + 1)
                    .try_into()
                    .map_err(|_| io::Error::other("too large"))?;
                PacketLength::Fixed(len)
            } else if buf_size == chunk_size {
                // partial
                PacketLength::Partial(self.chunk_size)
            } else {
                // final packet, this can be length 0
                self.is_done = true;
                self.is_fixed_emitted = true;
                let len = data
                    .len()
                    .try_into()
                    .map_err(|_| io::Error::other("too large"))?;
                PacketLength::Fixed(len)
            };

            let mut writer = std::mem::take(&mut self.current_packet).writer();
            if self.is_first {
                // only the first packet needs the literal data header
                let packet_header = PacketHeader::from_parts(
                    PacketHeaderVersion::New,
                    Tag::CompressedData,
                    packet_length,
                )
                .expect("known construction");
                packet_header
                    .to_writer(&mut writer)
                    .map_err(io::Error::other)?;

                writer.write_u8(self.source.algorithm().into())?;

                debug!("first partial packet {packet_header:?}");
                self.is_first = false;
            } else {
                // only length
                packet_length
                    .to_writer_new(&mut writer)
                    .map_err(io::Error::other)?;
                debug!("partial packet {packet_length:?}");
            };

            let mut packet_ser = writer.into_inner();
            packet_ser.extend_from_slice(data);
            self.current_packet = packet_ser;
        }

        let to_write = self.current_packet.remaining().min(buf.len());
        self.current_packet.copy_to_slice(&mut buf[..to_write]);
        Ok(to_write)
    }
}

#[cfg(test)]
mod tests {
    use chacha20::ChaCha8Rng;
    use proptest::prelude::*;
    use rand::{Rng, SeedableRng};

    use super::*;
    use crate::packet::Packet;

    proptest::prop_compose! {
        pub fn compressed_data_gen()(source: Vec<u8>) -> Bytes {
            // TODO: actually compress
            source.into()
        }
    }

    #[test]
    fn test_compressed_data_fixed_generator_uncompressed() {
        compressed_data_generator(CompressionAlgorithm::Uncompressed, true);
    }

    #[test]
    fn test_compressed_data_fixed_generator_zip() {
        compressed_data_generator(CompressionAlgorithm::ZIP, true);
    }

    #[test]
    fn test_compressed_data_fixed_generator_zlib() {
        compressed_data_generator(CompressionAlgorithm::ZLIB, true);
    }

    #[test]
    #[cfg(feature = "bzip2")]
    fn test_compressed_data_fixed_generator_bzip() {
        compressed_data_generator(CompressionAlgorithm::BZip2, true);
    }

    #[test]
    fn test_compressed_data_partial_generator_uncompressed() {
        compressed_data_generator(CompressionAlgorithm::Uncompressed, false);
    }

    #[test]
    fn test_compressed_data_partial_generator_zip() {
        compressed_data_generator(CompressionAlgorithm::ZIP, false);
    }

    #[test]
    fn test_compressed_data_partial_generator_zlib() {
        compressed_data_generator(CompressionAlgorithm::ZLIB, false);
    }

    #[test]
    #[cfg(feature = "bzip2")]
    fn test_compressed_data_partial_generator_bzip() {
        compressed_data_generator(CompressionAlgorithm::BZip2, false);
    }

    fn compressed_data_generator(alg: CompressionAlgorithm, is_fixed: bool) {
        let mut rng = ChaCha8Rng::seed_from_u64(1);

        let chunk_size = 512;
        let max_file_size = chunk_size * 5 + 100;

        for file_size in 1..=max_file_size {
            println!("Size: {file_size}");
            let mut buf = vec![0u8; file_size];
            rng.fill(&mut buf[..]);

            let mut compressed = Vec::new();
            Compressor::new(alg, &buf[..])
                .unwrap()
                .read_to_end(&mut compressed)
                .unwrap();

            let source_len = if is_fixed {
                Some(compressed.len() as _)
            } else {
                None
            };
            let mut generator =
                CompressedDataGenerator::new(alg, &buf[..], source_len, chunk_size as _).unwrap();

            let mut generator_out = Vec::new();
            generator.read_to_end(&mut generator_out).unwrap();

            // roundtrip

            let packets: Vec<_> =
                crate::packet::many::PacketParser::new(&generator_out[..]).collect();
            assert_eq!(packets.len(), 1, "{:?}", packets);
            let packet_back = packets[0].as_ref().unwrap();

            assert_eq!(packet_back.packet_header().tag(), Tag::CompressedData);
            let Packet::CompressedData(data) = packet_back else {
                panic!("invalid packet: {packet_back:?}");
            };

            // only works for packets less than chunk_size - header (1)
            if matches!(
                packet_back.packet_header().packet_length(),
                PacketLength::Fixed(_)
            ) {
                let packet = CompressedData::from_compressed(alg, compressed.clone()).unwrap();
                let mut packet_out = Vec::new();
                packet.to_writer_with_header(&mut packet_out).unwrap();

                assert_eq!(packet_out, generator_out, "different encoding produced");
                assert_eq!(&packet, data);
            }

            // decompress

            let mut decompressed = Vec::new();
            data.decompress()
                .unwrap()
                .read_to_end(&mut decompressed)
                .unwrap();
            assert_eq!(buf, decompressed);
        }
    }

    proptest! {
        #[test]
        fn write_len(packet: CompressedData) {
            let mut buf = Vec::new();
            packet.to_writer(&mut buf).unwrap();
            assert_eq!(buf.len(), packet.write_len());
        }


        #[test]
        fn packet_roundtrip(packet: CompressedData) {
            let mut buf = Vec::new();
            packet.to_writer(&mut buf).unwrap();
            let new_packet = CompressedData::try_from_reader(*packet.packet_header(), &mut &buf[..]).unwrap();
            assert_eq!(packet, new_packet);
        }
    }
}

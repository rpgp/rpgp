use std::io::{self, Read};

use byteorder::WriteBytesExt;
use bytes::{Buf, Bytes};
use bzip2::read::BzDecoder;
use flate2::read::{DeflateDecoder, ZlibDecoder};

use crate::errors::Result;
use crate::packet::PacketTrait;
use crate::ser::Serialize;
use crate::types::{CompressionAlgorithm, Tag, Version};

#[derive(Clone, PartialEq, Eq, derive_more::Debug)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct CompressedData {
    packet_version: Version,
    compression_algorithm: CompressionAlgorithm,
    #[debug("{}", hex::encode(compressed_data))]
    #[cfg_attr(test, proptest(strategy = "compressed_data_gen()"))]
    compressed_data: Bytes,
}

#[cfg(test)]
proptest::prop_compose! {
    fn compressed_data_gen()(source: Vec<u8>) -> Bytes {
        // TODO: actually compress
        source.into()
    }
}

pub enum Decompressor<R> {
    Uncompressed(R),
    Zip(DeflateDecoder<R>),
    Zlib(ZlibDecoder<R>),
    Bzip2(BzDecoder<R>),
}

impl Read for Decompressor<&[u8]> {
    fn read(&mut self, into: &mut [u8]) -> io::Result<usize> {
        match self {
            Decompressor::Uncompressed(ref mut c) => c.read(into),
            Decompressor::Zip(ref mut c) => c.read(into),
            Decompressor::Zlib(ref mut c) => c.read(into),
            Decompressor::Bzip2(ref mut c) => c.read(into),
        }
    }
}

impl CompressedData {
    /// Parses a `CompressedData` packet from the given slice.
    pub fn from_slice(packet_version: Version, input: &[u8]) -> Result<Self> {
        Self::from_buf(packet_version, input)
    }

    /// Parses a `CompressedData` packet from the given `Buf`.
    pub fn from_buf<B: Buf>(packet_version: Version, mut input: B) -> Result<Self> {
        ensure!(input.has_remaining(), "input too short");

        let alg = CompressionAlgorithm::from(input.get_u8());
        Ok(CompressedData {
            packet_version,
            compression_algorithm: alg,
            compressed_data: input.copy_to_bytes(input.remaining()),
        })
    }

    pub fn from_compressed(alg: CompressionAlgorithm, data: Vec<u8>) -> Self {
        CompressedData {
            packet_version: Default::default(),
            compression_algorithm: alg,
            compressed_data: Bytes::from(data),
        }
    }

    pub fn decompress(&self) -> Result<Decompressor<&[u8]>> {
        match self.compression_algorithm {
            CompressionAlgorithm::Uncompressed => {
                Ok(Decompressor::Uncompressed(&self.compressed_data[..]))
            }
            CompressionAlgorithm::ZIP => Ok(Decompressor::Zip(DeflateDecoder::new(
                &self.compressed_data[..],
            ))),
            CompressionAlgorithm::ZLIB => Ok(Decompressor::Zlib(ZlibDecoder::new(
                &self.compressed_data[..],
            ))),
            CompressionAlgorithm::BZip2 => Ok(Decompressor::Bzip2(BzDecoder::new(
                &self.compressed_data[..],
            ))),
            CompressionAlgorithm::Private10 | CompressionAlgorithm::Other(_) => unsupported_err!(
                "CompressionAlgorithm {} is unsupported",
                u8::from(self.compression_algorithm)
            ),
        }
    }

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
    fn packet_version(&self) -> Version {
        self.packet_version
    }

    fn tag(&self) -> Tag {
        Tag::CompressedData
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;

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
            let new_packet = CompressedData::from_slice(packet.packet_version(), &buf).unwrap();
            assert_eq!(packet, new_packet);
        }
    }
}

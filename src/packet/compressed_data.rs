use std::fmt;
use std::io::{self, Cursor, Read};

use flate2::read::{DeflateDecoder, ZlibDecoder};
use num_traits::FromPrimitive;

use crate::errors::Result;
use crate::packet::PacketTrait;
use crate::ser::Serialize;
use crate::types::{CompressionAlgorithm, Tag, Version};

#[derive(Clone, PartialEq, Eq)]
pub struct CompressedData {
    packet_version: Version,
    compression_algorithm: CompressionAlgorithm,
    compressed_data: Vec<u8>,
}

pub enum Decompressor<R> {
    Uncompressed(Cursor<R>),
    Zip(DeflateDecoder<R>),
    Zlib(ZlibDecoder<R>),
    Bzip2,
}

impl<'a> Read for Decompressor<&'a [u8]> {
    fn read(&mut self, into: &mut [u8]) -> io::Result<usize> {
        match self {
            Decompressor::Uncompressed(ref mut c) => c.read(into),
            Decompressor::Zip(ref mut c) => c.read(into),
            Decompressor::Zlib(ref mut c) => c.read(into),
            Decompressor::Bzip2 => unimplemented!("bzip2"),
        }
    }
}

impl CompressedData {
    /// Parses a `CompressedData` packet from the given slice.
    pub fn from_slice(packet_version: Version, input: &[u8]) -> Result<Self> {
        ensure!(input.len() > 1, "input too short");

        let alg = CompressionAlgorithm::from_u8(input[0])
            .ok_or_else(|| format_err!("invalid compression algorithm"))?;
        Ok(CompressedData {
            packet_version,
            compression_algorithm: alg,
            compressed_data: input[1..].to_vec(),
        })
    }

    pub fn from_compressed(alg: CompressionAlgorithm, data: Vec<u8>) -> Self {
        CompressedData {
            packet_version: Default::default(),
            compression_algorithm: alg,
            compressed_data: data,
        }
    }

    pub fn decompress(&self) -> Result<Decompressor<&[u8]>> {
        match self.compression_algorithm {
            CompressionAlgorithm::Uncompressed => Ok(Decompressor::Uncompressed(Cursor::new(
                &self.compressed_data[..],
            ))),
            CompressionAlgorithm::ZIP => Ok(Decompressor::Zip(DeflateDecoder::new(
                &self.compressed_data[..],
            ))),
            CompressionAlgorithm::ZLIB => Ok(Decompressor::Zlib(ZlibDecoder::new(
                &self.compressed_data[..],
            ))),
            CompressionAlgorithm::BZip2 => unimplemented_err!("BZip2"),
            CompressionAlgorithm::Private10 => unsupported_err!("Private10 should not be used"),
        }
    }

    pub fn compressed_data(&self) -> &[u8] {
        &self.compressed_data
    }
}

impl Serialize for CompressedData {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&[self.compression_algorithm as u8])?;
        writer.write_all(&self.compressed_data)?;

        Ok(())
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

impl fmt::Debug for CompressedData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompressedData")
            .field("packet_version", &self.packet_version)
            .field("compression_algorithm", &self.compression_algorithm)
            .field("compressed_data", &hex::encode(&self.compressed_data))
            .finish()
    }
}

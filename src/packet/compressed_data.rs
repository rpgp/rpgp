use std::io::{self, Cursor, Read};

use flate2::read::{DeflateDecoder, ZlibDecoder};
use num_traits::FromPrimitive;

use errors::Result;
use types::CompressionAlgorithm;

#[derive(Debug, Clone)]
pub struct CompressedData {
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
            Decompressor::Bzip2 => unimplemented!(),
        }
    }
}

impl CompressedData {
    /// Parses a `CompressedData` packet from the given slice.
    pub fn from_slice(input: &[u8]) -> Result<Self> {
        ensure!(input.len() > 1, "input too short");

        let alg = CompressionAlgorithm::from_u8(input[0])
            .ok_or_else(|| format_err!("invalid compression algorithm"))?;
        Ok(CompressedData {
            compression_algorithm: alg,
            compressed_data: input[1..].to_vec(),
        })
    }

    pub fn decompress(&self) -> Decompressor<&[u8]> {
        match self.compression_algorithm {
            CompressionAlgorithm::Uncompressed => {
                Decompressor::Uncompressed(Cursor::new(&self.compressed_data[..]))
            }
            CompressionAlgorithm::ZIP => {
                Decompressor::Zip(DeflateDecoder::new(&self.compressed_data[..]))
            }
            CompressionAlgorithm::ZLIB => {
                Decompressor::Zlib(ZlibDecoder::new(&self.compressed_data[..]))
            }
            CompressionAlgorithm::BZip2 => unimplemented!("BZip2"),
        }
    }

    pub fn compressed_data(&self) -> &[u8] {
        &self.compressed_data
    }
}

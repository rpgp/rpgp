use std::io::{self, BufRead, Read};

use bytes::{Buf, BytesMut};
use log::debug;
use zeroize::Zeroizing;

use crate::{
    crypto::{
        aead::{AeadAlgorithm, ChunkSize, Error},
        sym::SymmetricKeyAlgorithm,
    },
    types::Tag,
    util::fill_buffer,
};

/// Currently the tag size for all known aeads is 16.
const AEAD_TAG_SIZE: usize = 16;

#[derive(derive_more::Debug)]
pub struct StreamDecryptor<R: BufRead> {
    sym_alg: SymmetricKeyAlgorithm,
    aead: AeadAlgorithm,
    chunk_size_expanded: usize,
    /// how many bytes have been written
    written: u64,
    chunk_index: u64,
    #[debug("{}", hex::encode(iv))]
    iv: Vec<u8>,
    #[debug("..")]
    message_key: Zeroizing<Vec<u8>>,
    ad: [u8; 5],
    source: R,
    /// finished reading from source?
    is_source_done: bool,
    #[debug("{}", hex::encode(in_buffer))]
    in_buffer: BytesMut,
    #[debug("{}", hex::encode(out_buffer))]
    out_buffer: BytesMut,
}

impl<R: BufRead> StreamDecryptor<R> {
    pub fn new(
        sym_alg: SymmetricKeyAlgorithm,
        aead: AeadAlgorithm,
        chunk_size: ChunkSize,
        key: &[u8],
        iv: &[u8],
        source: R,
    ) -> Result<Self, Error> {
        let chunk_size_expanded: usize = chunk_size
            .as_byte_size()
            .try_into()
            .expect("chunk size is smaller");

        let info = [
            Tag::GnupgAead.encode(), // packet type
            0x01,                    // version
            sym_alg.into(),
            aead.into(),
            chunk_size.into(),
        ];

        let Some(aead_tag_size) = aead.tag_size() else {
            // TODO: error handling
            unimplemented!()

            // return Err(UnsupporedAlgorithmSnafu { alg: aead }.build());
        };

        debug_assert_eq!(
            aead_tag_size, AEAD_TAG_SIZE,
            "unexpected AEAD configuration"
        );

        Ok(Self {
            sym_alg,
            aead,
            iv: iv.to_vec(),
            written: 0,
            chunk_index: 0,
            ad: info,
            message_key: key.to_vec().into(),
            chunk_size_expanded,
            source,
            is_source_done: false,
            in_buffer: BytesMut::with_capacity(2 * (chunk_size_expanded + AEAD_TAG_SIZE)),
            out_buffer: BytesMut::with_capacity(2 * chunk_size_expanded),
        })
    }

    pub fn into_inner(self) -> R {
        self.source
    }

    pub fn get_ref(&self) -> &R {
        &self.source
    }

    pub fn get_mut(&mut self) -> &mut R {
        &mut self.source
    }

    /// The nonce is computed from the initialization vector (as a big endian value),
    /// by XORing its low eight octets with the chunk index (as a big endian value).
    fn nonce(iv: &[u8], chunk_index: &[u8; 8]) -> Vec<u8> {
        let mut nonce = iv.to_vec();

        for (i, value) in chunk_index.iter().enumerate() {
            nonce[iv.len() - 8 + i] ^= value;
        }

        nonce
    }

    fn decrypt(&mut self) -> io::Result<()> {
        let enc_chunk_size = self.chunk_size_expanded + AEAD_TAG_SIZE;

        let end = enc_chunk_size.min(self.in_buffer.len());
        let mut out = self.in_buffer.split_to(end);

        let chunk_index = self.chunk_index.to_be_bytes();

        let nonce = Self::nonce(&self.iv, &chunk_index);

        let mut ad: Vec<u8> = self.ad.to_vec();
        ad.extend_from_slice(&chunk_index);

        self.aead
            .decrypt_in_place(&self.sym_alg, &self.message_key, &nonce, &ad, &mut out)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        self.written += out.len() as u64;

        self.out_buffer.extend(out);

        // Update chunk index
        self.chunk_index += 1;

        Ok(())
    }

    /// Decrypt the final chunk of data
    pub fn decrypt_last(&mut self) -> io::Result<()> {
        debug_assert!(
            self.in_buffer.len() >= AEAD_TAG_SIZE,
            "last chunk size mismatch"
        );

        let mut final_auth_tag = self
            .in_buffer
            .split_off(self.in_buffer.len() - AEAD_TAG_SIZE);

        while !self.in_buffer.is_empty() {
            self.decrypt()?;
        }

        // verify final auth tag
        let chunk_index = self.chunk_index.to_be_bytes();

        let nonce = Self::nonce(&self.iv, &chunk_index);

        // Associated data is extended with number of plaintext octets.
        let size = self.written;
        let mut final_ad = self.ad.to_vec();
        final_ad.extend_from_slice(&chunk_index);
        final_ad.extend_from_slice(&size.to_be_bytes());

        // Update final nonce
        self.aead
            .decrypt_in_place(
                &self.sym_alg,
                &self.message_key,
                &nonce,
                &final_ad,
                &mut final_auth_tag,
            )
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        Ok(())
    }

    fn fill_inner(&mut self) -> io::Result<()> {
        if self.out_buffer.remaining() > 0 || self.is_source_done {
            return Ok(());
        }

        let current_len = self.in_buffer.len();
        let buf_size = 2 * (self.chunk_size_expanded + AEAD_TAG_SIZE);
        let to_read = buf_size - current_len;

        self.in_buffer.resize(buf_size, 0);
        let read = fill_buffer(
            &mut self.source,
            &mut self.in_buffer[current_len..],
            Some(to_read),
        )?;
        self.in_buffer.truncate(current_len + read);

        if read < to_read {
            debug!("source finished reading");
            // make sure we have as much as data as we need
            if self.in_buffer.remaining() < AEAD_TAG_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "not enough data to finalize aead decryption",
                ));
            }

            // done reading the source
            self.is_source_done = true;

            self.decrypt_last()?;
        } else {
            self.decrypt()?;
        }

        Ok(())
    }
}

impl<R: BufRead> BufRead for StreamDecryptor<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.fill_inner()?;
        Ok(&self.out_buffer[..])
    }

    fn consume(&mut self, amt: usize) {
        self.out_buffer.advance(amt);
    }
}

impl<R: BufRead> Read for StreamDecryptor<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.fill_inner()?;
        let to_write = self.out_buffer.remaining().min(buf.len());
        self.out_buffer.copy_to_slice(&mut buf[..to_write]);

        Ok(to_write)
    }
}

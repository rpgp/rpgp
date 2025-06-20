use std::io::{self, BufRead, Read};

use bytes::{Buf, BytesMut};
use log::debug;
use zeroize::Zeroizing;

use crate::{
    crypto::{
        aead::{aead_setup, AeadAlgorithm, ChunkSize, Error, UnsupporedAlgorithmSnafu},
        sym::SymmetricKeyAlgorithm,
    },
    util::fill_buffer_bytes,
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
    #[debug("{}", hex::encode(nonce))]
    nonce: Vec<u8>,
    #[debug("..")]
    message_key: Zeroizing<Vec<u8>>,
    #[debug("{}", hex::encode(info))]
    info: [u8; 5],
    source: R,
    /// finished reading from source?
    is_source_done: bool,
    /// main buffer
    #[debug("{}", hex::encode(buffer))]
    buffer: BytesMut,
    /// end point of encrypted data in `buffer`
    in_buffer_end: usize,
    /// start point of decrypted data in `buffer`
    out_buffer_start: usize,
}

impl<R: BufRead> StreamDecryptor<R> {
    pub fn new(
        sym_alg: SymmetricKeyAlgorithm,
        aead: AeadAlgorithm,
        chunk_size: ChunkSize,
        salt: &[u8; 32],
        key: &[u8],
        source: R,
    ) -> Result<Self, Error> {
        // Initial key material is the session key.
        let ikm = key;
        let chunk_size_expanded: usize = chunk_size
            .as_byte_size()
            .try_into()
            .expect("chunk size is smaller");

        let (info, message_key, nonce) = aead_setup(sym_alg, aead, chunk_size, &salt[..], ikm);

        // There are n chunks, n auth tags + 1 final auth tag
        let Some(aead_tag_size) = aead.tag_size() else {
            return Err(UnsupporedAlgorithmSnafu { alg: aead }.build());
        };

        debug_assert_eq!(
            aead_tag_size, AEAD_TAG_SIZE,
            "unexpected AEAD configuration"
        );

        Ok(Self {
            sym_alg,
            aead,
            nonce,
            written: 0,
            chunk_index: 0,
            info,
            message_key,
            chunk_size_expanded,
            source,
            is_source_done: false,
            buffer: BytesMut::with_capacity(2 * (chunk_size_expanded + AEAD_TAG_SIZE)),
            in_buffer_end: 0,
            out_buffer_start: 0,
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

    fn decrypt(&mut self) -> io::Result<()> {
        let enc_chunk_size = self.chunk_size_expanded + AEAD_TAG_SIZE;

        let end = enc_chunk_size.min(self.buffer.len() - self.out_buffer_remaining());
        let mut out = self.buffer.split_to(end);
        self.in_buffer_end -= out.len();

        self.aead
            .decrypt_in_place(
                &self.sym_alg,
                &self.message_key,
                &self.nonce,
                &self.info,
                &mut out,
            )
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        self.written += out.len() as u64;

        self.buffer.unsplit(out);

        // Update nonce to include the next chunk index
        self.chunk_index += 1;
        let l = self.nonce.len() - 8;
        self.nonce[l..].copy_from_slice(&self.chunk_index.to_be_bytes());

        Ok(())
    }

    /// Decrypt the final chunk of data
    pub fn decrypt_last(&mut self) -> io::Result<()> {
        // all pending data has been read before
        debug_assert_eq!(self.out_buffer_start, 0, "out start: should be 0");

        debug_assert!(
            self.buffer.len() >= AEAD_TAG_SIZE,
            "last chunk size mismatch"
        );

        let mut final_auth_tag = self.buffer.split_off(self.buffer.len() - AEAD_TAG_SIZE);
        self.in_buffer_end -= final_auth_tag.len();

        // decrypt any remaining data, not part of the final auth tag
        while self.in_buffer_end > 0 {
            self.decrypt()?;
        }

        // verify final auth tag

        // Associated data is extended with number of plaintext octets.
        let size = self.written;
        let mut final_info = self.info.to_vec();
        final_info.extend_from_slice(&size.to_be_bytes());

        // Update final nonce
        self.aead
            .decrypt_in_place(
                &self.sym_alg,
                &self.message_key,
                &self.nonce,
                &final_info,
                &mut final_auth_tag,
            )
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        Ok(())
    }

    fn fill_inner(&mut self) -> io::Result<()> {
        if self.out_buffer_remaining() > 0 || self.is_source_done {
            return Ok(());
        }

        let current_len = self.in_buffer_end;
        let buf_size = 2 * (self.chunk_size_expanded + AEAD_TAG_SIZE);
        let to_read = buf_size - current_len;

        self.buffer.truncate(current_len);
        let read = fill_buffer_bytes(&mut self.source, &mut self.buffer, buf_size)?;
        self.in_buffer_end += read;
        // reset out buffer
        self.out_buffer_start = 0;

        if read < to_read {
            debug!("source finished reading");
            // make sure we have as much as data as we need
            if self.buffer.remaining() < AEAD_TAG_SIZE {
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

    fn out_buffer(&self) -> &[u8] {
        let start = self.in_buffer_end + self.out_buffer_start;
        &self.buffer[start..]
    }

    fn out_buffer_remaining(&self) -> usize {
        let start = self.in_buffer_end + self.out_buffer_start;
        self.buffer.len() - start
    }
}

impl<R: BufRead> BufRead for StreamDecryptor<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.fill_inner()?;
        Ok(self.out_buffer())
    }

    fn consume(&mut self, amt: usize) {
        self.out_buffer_start += amt;
    }
}

impl<R: BufRead> Read for StreamDecryptor<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.fill_inner()?;
        let to_write = self.out_buffer_remaining().min(buf.len());
        buf[..to_write].copy_from_slice(&self.out_buffer()[..to_write]);
        self.out_buffer_start += to_write;
        Ok(to_write)
    }
}

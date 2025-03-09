use std::io::{self, BufRead, Read};

use bytes::{Buf, BytesMut};
use log::debug;
use zeroize::Zeroizing;

use crate::crypto::aead::{aead_setup, AeadAlgorithm, ChunkSize};
use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::errors::Result;
use crate::util::fill_buffer;

#[derive(derive_more::Debug)]
pub struct StreamDecryptor<R: BufRead> {
    sym_alg: SymmetricKeyAlgorithm,
    aead: AeadAlgorithm,
    chunk_size_expanded: usize,
    aead_tag_size: usize,
    /// how many bytes have been written
    written: usize,
    chunk_index: usize,
    nonce: Vec<u8>,
    #[debug("..")]
    message_key: Zeroizing<Vec<u8>>,
    info: [u8; 5],
    #[debug("R")]
    source: R,
    /// finished reading from source?
    is_source_done: bool,
    buffer: BytesMut,
}

impl<R: BufRead> StreamDecryptor<R> {
    pub fn new(
        sym_alg: SymmetricKeyAlgorithm,
        aead: AeadAlgorithm,
        chunk_size: ChunkSize,
        salt: &[u8; 32],
        key: &[u8],
        source: R,
    ) -> Result<Self> {
        // Initial key material is the session key.
        let ikm = key;
        let chunk_size_expanded: usize = chunk_size.as_byte_size().try_into()?;

        let (info, message_key, nonce) = aead_setup(sym_alg, aead, chunk_size, &salt[..], ikm)?;

        // There are n chunks, n auth tags + 1 final auth tag
        let Some(aead_tag_size) = aead.tag_size() else {
            unsupported_err!("AEAD mode: {:?}", aead);
        };

        Ok(Self {
            sym_alg,
            aead,
            nonce,
            written: 0,
            chunk_index: 0,
            info,
            message_key,
            aead_tag_size,
            chunk_size_expanded,
            source,
            is_source_done: false,
            buffer: BytesMut::with_capacity(chunk_size_expanded * 2),
        })
    }

    pub fn into_inner(self) -> R {
        self.source
    }

    pub fn get_ref(&self) -> &R {
        &self.source
    }

    fn decrypt(&mut self) -> io::Result<()> {
        self.aead
            .decrypt_in_place(
                &self.sym_alg,
                &self.message_key,
                &self.nonce,
                &self.info,
                &mut self.buffer,
            )
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        self.written += self.buffer.len();

        // Update nonce to include the next chunk index
        self.chunk_index += 1;
        let l = self.nonce.len() - 8;
        self.nonce[l..].copy_from_slice(&self.chunk_index.to_be_bytes());

        Ok(())
    }

    /// Decrypt the final chunk of data
    pub fn decrypt_last(&mut self) -> io::Result<()> {
        debug_assert!(
            self.buffer.len() >= self.aead_tag_size,
            "last chunk size mismatch"
        );

        let mut final_auth_tag = self
            .buffer
            .split_off(self.buffer.len() - self.aead_tag_size);

        self.decrypt()?;

        // verify final auth tag

        // Associated data is extended with number of plaintext octets.
        let size = self.written as u64;
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
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

        Ok(())
    }

    fn full_chunk_size(&self) -> usize {
        self.chunk_size_expanded + self.aead_tag_size
    }

    /// ensure the final tag is not returned
    fn remaining(&self) -> usize {
        let remaining = self.buffer.remaining();
        if self.is_source_done {
            remaining
        } else if remaining > self.aead_tag_size {
            remaining - self.aead_tag_size
        } else {
            0
        }
    }

    fn fill_inner(&mut self) -> io::Result<()> {
        if self.remaining() > 0 || self.is_source_done {
            return Ok(());
        }

        let current_len = self.buffer.remaining();
        let to_read = 2 * self.full_chunk_size();
        let buf_size = current_len + to_read;
        self.buffer.resize(buf_size, 0);
        let read = fill_buffer(
            &mut self.source,
            &mut self.buffer[current_len..],
            Some(to_read),
        )?;
        self.buffer.truncate(current_len + read);

        if read < to_read {
            debug!("source finished reading");
            // make sure we have as much as data as we need
            if self.buffer.remaining() < self.aead_tag_size {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "not enough data to finalize aead decryption",
                ));
            }

            // done reading the source
            self.is_source_done = true;

            self.decrypt_last()?;
        } else {
            let old = self.buffer.split_off(current_len);
            self.decrypt()?;
            self.buffer.unsplit(old);
        }

        Ok(())
    }
}

impl<R: BufRead> BufRead for StreamDecryptor<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.fill_inner()?;
        Ok(&self.buffer[..self.remaining()])
    }

    fn consume(&mut self, amt: usize) {
        self.buffer.advance(amt);
    }
}

impl<R: BufRead> Read for StreamDecryptor<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.fill_inner()?;
        let to_write = self.remaining().min(buf.len());
        self.buffer.copy_to_slice(&mut buf[..to_write]);
        Ok(to_write)
    }
}

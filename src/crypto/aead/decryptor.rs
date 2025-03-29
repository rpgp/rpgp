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
            in_buffer: BytesMut::new(),
            out_buffer: BytesMut::new(),
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
        let enc_chunk_size = self.chunk_size_expanded + self.aead_tag_size;

        let end = enc_chunk_size.min(self.in_buffer.len());
        let mut out = self.in_buffer.split_to(end);

        self.aead
            .decrypt_in_place(
                &self.sym_alg,
                &self.message_key,
                &self.nonce,
                &self.info,
                &mut out,
            )
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        self.written += out.len() as u64;

        self.out_buffer.extend(out);

        // Update nonce to include the next chunk index
        self.chunk_index += 1;
        let l = self.nonce.len() - 8;
        self.nonce[l..].copy_from_slice(&self.chunk_index.to_be_bytes());

        Ok(())
    }

    /// Decrypt the final chunk of data
    pub fn decrypt_last(&mut self) -> io::Result<()> {
        debug_assert!(
            self.in_buffer.len() >= self.aead_tag_size,
            "last chunk size mismatch"
        );

        let mut final_auth_tag = self
            .in_buffer
            .split_off(self.in_buffer.len() - self.aead_tag_size);

        while !self.in_buffer.is_empty() {
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
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

        Ok(())
    }

    fn fill_inner(&mut self) -> io::Result<()> {
        if self.out_buffer.remaining() > 0 || self.is_source_done {
            return Ok(());
        }

        let current_len = self.in_buffer.len();
        let buf_size = 2 * (self.chunk_size_expanded + self.aead_tag_size);
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
            if self.in_buffer.remaining() < self.aead_tag_size {
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

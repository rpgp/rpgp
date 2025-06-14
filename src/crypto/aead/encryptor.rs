use std::io;

use bytes::{Buf, BytesMut};
use zeroize::Zeroizing;

use super::{aead_setup_rfc9580, ChunkSize, InvalidSessionKeySnafu};
use crate::{
    crypto::{
        aead::{AeadAlgorithm, Error},
        sym::SymmetricKeyAlgorithm,
    },
    util::fill_buffer,
};

pub struct StreamEncryptor<R> {
    source: R,
    /// Indicates if we are done reading from the `source`.
    is_source_done: bool,
    /// Total number of bytes read from the source.
    bytes_read: u64,
    chunk_index: u64,
    buffer: BytesMut,
    info: [u8; 5],
    message_key: Zeroizing<Vec<u8>>,
    nonce: Vec<u8>,
    chunk_size_expanded: usize,
    aead: AeadAlgorithm,
    sym_alg: SymmetricKeyAlgorithm,
}

impl<R: io::Read> StreamEncryptor<R> {
    /// Encrypts the data using the given symmetric key.
    pub(crate) fn new(
        sym_alg: SymmetricKeyAlgorithm,
        aead: AeadAlgorithm,
        chunk_size: ChunkSize,
        session_key: &[u8],
        salt: &[u8; 32],
        source: R,
    ) -> Result<Self, Error> {
        if session_key.len() != sym_alg.key_size() {
            return Err(InvalidSessionKeySnafu {
                alg: sym_alg,
                session_key_size: session_key.len(),
            }
            .build());
        }

        let (info, message_key, nonce) =
            aead_setup_rfc9580(sym_alg, aead, chunk_size, &salt[..], session_key);
        let chunk_size_expanded: usize = chunk_size
            .as_byte_size()
            .try_into()
            .expect("invalid chunk size");

        let buffer = BytesMut::with_capacity(chunk_size_expanded);

        Ok(StreamEncryptor {
            source,
            is_source_done: false,
            bytes_read: 0,
            chunk_index: 0,
            info,
            message_key,
            nonce,
            chunk_size_expanded,
            aead,
            sym_alg,
            buffer,
        })
    }

    /// Constructs the final auth tag
    fn create_final_auth_tag(&mut self) -> io::Result<()> {
        // Associated data is extended with number of plaintext octets.
        let mut final_info = self.info.to_vec();
        // length: 8 octets as big endian
        final_info.extend_from_slice(&self.bytes_read.to_be_bytes());

        // encrypts empty string
        self.buffer.clear();
        self.aead
            .encrypt_in_place(
                &self.sym_alg,
                &self.message_key,
                &self.nonce,
                &final_info,
                &mut self.buffer,
            )
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        Ok(())
    }

    fn fill_buffer(&mut self) -> io::Result<()> {
        self.buffer.resize(self.chunk_size_expanded, 0);
        let read = fill_buffer(
            &mut self.source,
            &mut self.buffer,
            Some(self.chunk_size_expanded),
        )?;
        let read_u64 = read.try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "too much data read".to_string(),
            )
        })?;
        self.bytes_read = match self.bytes_read.checked_add(read_u64) {
            Some(read) => read,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "can not read more than u64::MAX data".to_string(),
                ));
            }
        };
        if read == 0 {
            self.is_source_done = true;
            // time to write the final chunk
            self.create_final_auth_tag()?;

            return Ok(());
        }
        self.buffer.truncate(read);

        self.aead
            .encrypt_in_place(
                &self.sym_alg,
                &self.message_key,
                &self.nonce,
                &self.info,
                &mut self.buffer,
            )
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // Update nonce to include the next chunk index
        self.chunk_index += 1;
        let l = self.nonce.len() - 8;
        self.nonce[l..].copy_from_slice(&self.chunk_index.to_be_bytes());

        Ok(())
    }
}

impl<R: io::Read> io::Read for StreamEncryptor<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.buffer.has_remaining() {
            if !self.is_source_done {
                // Still more to read and encrypt from the source.
                self.fill_buffer()?;
            } else {
                // The final chunk was written, we have nothing left to give.
                return Ok(0);
            }
        }

        let to_write = buf.len().min(self.buffer.remaining());
        self.buffer.copy_to_slice(&mut buf[..to_write]);

        Ok(to_write)
    }
}

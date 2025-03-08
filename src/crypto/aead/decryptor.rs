use std::io::{self, BufRead, Read};

use bytes::{Buf, BytesMut};
use zeroize::Zeroizing;

use crate::crypto::aead::{aead_setup, AeadAlgorithm, ChunkSize};
use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::errors::Result;

#[derive(derive_more::Debug)]
pub enum StreamDecryptor<R: BufRead> {
    Init {
        sym_alg: SymmetricKeyAlgorithm,
        aead: AeadAlgorithm,
        chunk_size: ChunkSize,
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
    },
    Data {
        buffer: BytesMut,
        #[debug("R")]
        source: R,
    },
    Done {
        #[debug("R")]
        source: R,
    },
    Error,
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

        Ok(Self::Init {
            sym_alg,
            aead,
            chunk_size,
            nonce,
            written: 0,
            chunk_index: 0,
            info,
            message_key,
            aead_tag_size,
            chunk_size_expanded,
            source,
        })
    }

    pub fn into_inner(self) -> R {
        match self {
            Self::Init { source, .. } => source,
            Self::Data { source, .. } => source,
            Self::Done { source } => source,
            Self::Error => panic!("error state"),
        }
    }

    pub fn get_ref(&self) -> &R {
        match self {
            Self::Init { source, .. } => source,
            Self::Data { source, .. } => source,
            Self::Done { source } => source,
            Self::Error => panic!("error state"),
        }
    }

    // fn decrypt(&mut self, buf: &mut BytesMut) -> Result<()> {
    //     let full_chunk_size = *chunk_size_expanded + *aead_tag_size;
    //     ensure_eq!(buf.len(), full_chunk_size, "buffer has the wrong size");
    //     aead.decrypt_in_place(sym_alg, &message_key, &nonce, &*info, buf)?;
    //     *written += buf.len();

    //     // Update nonce to include the next chunk index
    //     *chunk_index += 1;
    //     let l = nonce.len() - 8;
    //     nonce[l..].copy_from_slice(&chunk_index.to_be_bytes());

    //     Ok(())
    // }

    // /// Decrpyt the final chunk of data
    // pub fn decrypt_last(&mut self, buf: &mut BytesMut) -> Result<()> {
    //     ensure!(buf.len() >= *aead_tag_size, "last chunk size missmatch");

    //     let mut final_auth_tag = buf.split_off(buf.len() - *aead_tag_size);

    //     aead.decrypt_in_place(sym_alg, &message_key, &nonce, &*info, buf)?;
    //     *written += buf.len();

    //     // Update nonce to include the next chunk index
    //     *chunk_index += 1;
    //     let l = nonce.len() - 8;
    //     nonce[l..].copy_from_slice(&chunk_index.to_be_bytes());

    //     // verify final auth tag

    //     // Associated data is extended with number of plaintext octets.
    //     let size = *written as u64;
    //     let mut final_info = info.to_vec();
    //     final_info.extend_from_slice(&size.to_be_bytes());

    //     // Update final nonce
    //     aead.decrypt_in_place(
    //         sym_alg,
    //         &message_key,
    //         &nonce,
    //         &final_info,
    //         &mut final_auth_tag,
    //     )?;

    //     Ok(())
    // }

    fn fill_inner(&mut self) -> io::Result<()> {
        todo!()
    }
}

impl<R: BufRead> BufRead for StreamDecryptor<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.fill_inner()?;
        match self {
            Self::Init { .. } => panic!("invalid state"),
            Self::Data { buffer, .. } => Ok(&buffer[..]),
            Self::Done { .. } => Ok(&[][..]),
            Self::Error => unreachable!("error state "),
        }
    }

    fn consume(&mut self, amt: usize) {
        match self {
            Self::Init { .. } => panic!("invalid state"),
            Self::Data { buffer, .. } => {
                buffer.advance(amt);
            }
            Self::Done { .. } => {}
            Self::Error => unreachable!("error state "),
        }
    }
}

impl<R: BufRead> Read for StreamDecryptor<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.fill_inner()?;
        match self {
            Self::Init { .. } => panic!("invalid state"),
            Self::Data { buffer, .. } => {
                let to_write = buffer.remaining().min(buf.len());
                buffer.copy_to_slice(&mut buf[..to_write]);
                Ok(to_write)
            }
            Self::Done { .. } => Ok(0),
            Self::Error => unreachable!("error state "),
        }
    }
}

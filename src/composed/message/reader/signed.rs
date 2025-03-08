use std::io::{self, BufRead, Read};

use bytes::{Buf, BytesMut};
use digest::DynDigest;
use log::debug;

use crate::errors::Result;
use crate::packet::{Signature, SignatureVersionSpecific};
use crate::{Message, RingResult, TheRing};

use super::PacketBodyReader;

#[derive(derive_more::Debug)]
pub enum SignatureBodyReader<'a> {
    Init {
        /// Running hasher
        #[debug("hasher")]
        hasher: Box<dyn DynDigest>,
        /// Data source
        source: Box<Message<'a>>,
    },
    Body {
        /// Running hasher
        #[debug("hasher")]
        hasher: Box<dyn DynDigest>,
        /// Data source
        source: Box<Message<'a>>,
        buffer: BytesMut,
    },
    Done {
        /// Finalized hash
        hash: Box<[u8]>,
        /// Data source
        source: Box<Message<'a>>,
    },
    Error,
}

impl<'a> SignatureBodyReader<'a> {
    pub(crate) fn new(sig: &Signature, source: Box<Message<'a>>) -> Result<Self> {
        let mut hasher = sig.config.hash_alg.new_hasher()?;
        if let SignatureVersionSpecific::V6 { ref salt, .. } = sig.config.version_specific {
            // Salt size must match the expected length for the hash algorithm that is used
            //
            // See: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3-2.10.2.1.1
            ensure_eq!(
                sig.config.hash_alg.salt_len(),
                Some(salt.len()),
                "Illegal salt length {} for a V6 Signature using {:?}",
                salt.len(),
                sig.config.hash_alg,
            );

            hasher.update(salt.as_ref());
        }

        Ok(Self::Init { hasher, source })
    }

    pub fn hash(&self) -> Option<&[u8]> {
        match self {
            Self::Done { hash, .. } => Some(&hash),
            Self::Error => panic!("error state"),
            _ => None,
        }
    }

    pub fn get_ref(&self) -> &Box<Message<'a>> {
        match self {
            Self::Init { source, .. } => source,
            Self::Body { source, .. } => source,
            Self::Done { source, .. } => source,
            Self::Error => panic!("error state"),
        }
    }

    pub fn into_inner(self) -> PacketBodyReader<Box<dyn BufRead + 'a>> {
        match self {
            Self::Init { source, .. } => source.into_inner(),
            Self::Body { source, .. } => source.into_inner(),
            Self::Done { source, .. } => source.into_inner(),
            Self::Error => panic!("error state"),
        }
    }

    fn fill_inner(&mut self) -> io::Result<()> {
        todo!()
    }

    pub fn is_done(&self) -> bool {
        matches!(self, Self::Done { .. })
    }

    pub(crate) fn decompress(self) -> Result<Self> {
        match self {
            Self::Init { hasher, source } => {
                let source = source.decompress()?;
                Ok(Self::Init {
                    hasher,
                    source: Box::new(source),
                })
            }
            _ => {
                bail!("cannot decompress message that has already been read from");
            }
        }
    }

    pub(crate) fn decrypt_the_ring(
        self,
        ring: TheRing<'_>,
        abort_early: bool,
    ) -> Result<(Self, RingResult)> {
        match self {
            Self::Init { hasher, source } => {
                let (source, fps) = source.decrypt_the_ring(ring, abort_early)?;
                Ok((
                    Self::Init {
                        hasher,
                        source: Box::new(source),
                    },
                    fps,
                ))
            }
            _ => {
                bail!("cannot decrypt message that has already been read from");
            }
        }
    }
}

impl BufRead for SignatureBodyReader<'_> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.fill_inner()?;
        match self {
            Self::Init { .. } => panic!("invalid state"),
            Self::Body { buffer, .. } => Ok(&buffer[..]),
            Self::Done { .. } => Ok(&[][..]),
            Self::Error => panic!("error state"),
        }
    }

    fn consume(&mut self, amt: usize) {
        match self {
            Self::Init { .. } => panic!("invalid state"),
            Self::Body { buffer, .. } => {
                buffer.advance(amt);
            }
            Self::Done { .. } => {}
            Self::Error => panic!("error state"),
        }
    }
}

impl Read for SignatureBodyReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.fill_inner()?;
        match self {
            Self::Init { .. } => panic!("invalid state"),
            Self::Body { buffer, .. } => {
                let to_write = buffer.remaining().min(buf.len());
                buffer.copy_to_slice(&mut buf[..to_write]);
                Ok(to_write)
            }
            Self::Done { .. } => Ok(0),
            Self::Error => panic!("error state"),
        }
    }
}

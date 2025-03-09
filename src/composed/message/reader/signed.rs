use std::io::{self, BufRead, Read};

use bytes::{Buf, BytesMut};
use digest::DynDigest;
use log::debug;

use crate::errors::Result;
use crate::packet::{Signature, SignatureVersionSpecific};
use crate::util::fill_buffer;
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
        signature: Signature,
    },
    Body {
        /// Running hasher
        #[debug("hasher")]
        hasher: Box<dyn DynDigest>,
        /// Data source
        source: Box<Message<'a>>,
        buffer: BytesMut,
        signature: Signature,
    },
    Done {
        /// Finalized hash
        hash: Box<[u8]>,
        /// Data source
        source: Box<Message<'a>>,
        signature: Signature,
    },
    Error,
}

impl<'a> SignatureBodyReader<'a> {
    pub(crate) fn new(sig: Signature, source: Box<Message<'a>>) -> Result<Self> {
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

        Ok(Self::Init {
            hasher,
            source,
            signature: sig,
        })
    }

    pub fn hash(&self) -> Option<&[u8]> {
        match self {
            Self::Done { hash, .. } => Some(hash),
            Self::Error => panic!("error state"),
            _ => None,
        }
    }

    pub fn signature(&self) -> &Signature {
        match self {
            Self::Init { signature, .. } => signature,
            Self::Body { signature, .. } => signature,
            Self::Done { signature, .. } => signature,
            Self::Error => panic!("error state"),
        }
    }

    pub fn get_ref(&self) -> &Message<'a> {
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
        if matches!(self, Self::Done { .. }) {
            return Ok(());
        }

        loop {
            match std::mem::replace(self, Self::Error) {
                Self::Init {
                    mut hasher,
                    mut source,
                    signature,
                } => {
                    debug!("SignatureReader init");
                    let mut buffer = BytesMut::zeroed(1024);
                    let read = fill_buffer(&mut source, &mut buffer, None)?;
                    buffer.truncate(read);

                    if read == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "missing signature",
                        ));
                    }

                    // TODO: normalize line endings..
                    hasher.update(&buffer);

                    *self = Self::Body {
                        source,
                        hasher,
                        buffer,
                        signature,
                    };
                }
                Self::Body {
                    mut hasher,
                    mut source,
                    mut buffer,
                    signature,
                } => {
                    debug!("SignatureReader body");

                    if buffer.has_remaining() {
                        *self = Self::Body {
                            hasher,
                            source,
                            buffer,
                            signature,
                        };
                        return Ok(());
                    }

                    buffer.resize(1024, 0);
                    let read = fill_buffer(&mut source, &mut buffer, None)?;
                    buffer.truncate(read);

                    // TODO: normalize line endings
                    hasher.update(&buffer);

                    if read == 0 {
                        debug!("SignatureReader finish");

                        // calculate final hash
                        let len =
                            signature
                                .config
                                .hash_signature_data(&mut hasher)
                                .map_err(|e| {
                                    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
                                })?;
                        hasher.update(&signature.config.trailer(len).map_err(|e| {
                            io::Error::new(io::ErrorKind::InvalidData, e.to_string())
                        })?);
                        let hash = hasher.finalize();

                        *self = Self::Done {
                            signature,
                            hash,
                            source,
                        };
                    } else {
                        *self = Self::Body {
                            hasher,
                            source,
                            buffer,
                            signature,
                        }
                    }

                    return Ok(());
                }
                Self::Done {
                    hash,
                    source,
                    signature,
                } => {
                    *self = Self::Done {
                        hash,
                        source,
                        signature,
                    };
                    return Ok(());
                }
                Self::Error => panic!("error state"),
            }
        }
    }

    pub fn is_done(&self) -> bool {
        matches!(self, Self::Done { .. })
    }

    pub(crate) fn decompress(self) -> Result<Self> {
        match self {
            Self::Init {
                hasher,
                source,
                signature,
            } => {
                let source = source.decompress()?;
                Ok(Self::Init {
                    hasher,
                    source: Box::new(source),
                    signature,
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
            Self::Init {
                hasher,
                source,
                signature,
            } => {
                let (source, fps) = source.decrypt_the_ring(ring, abort_early)?;
                Ok((
                    Self::Init {
                        hasher,
                        source: Box::new(source),
                        signature,
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

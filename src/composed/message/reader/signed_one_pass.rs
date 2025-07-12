use std::io::{self, BufRead, Read};

use bytes::{Buf, BytesMut};
use log::debug;

use super::PacketBodyReader;
use crate::{
    composed::{Message, MessageReader, RingResult, TheRing},
    errors::{bail, ensure_eq, Result},
    packet::{OnePassSignature, OpsVersionSpecific, Packet, PacketTrait, Signature, SignatureType},
    util::{fill_buffer_bytes, NormalizingHasher},
};

const BUFFER_SIZE: usize = 8 * 1024;

#[derive(derive_more::Debug)]
pub enum SignatureOnePassReader<'a> {
    Init {
        /// Running hasher
        norm_hasher: Option<NormalizingHasher>,
        /// Data source
        source: Box<Message<'a>>,
    },
    Body {
        /// Running hasher
        norm_hasher: Option<NormalizingHasher>,
        /// Data source
        source: Box<Message<'a>>,
        #[debug("{}", hex::encode(buffer))]
        buffer: BytesMut,
    },
    Done {
        /// Finalized hash
        #[debug("{:?}", hash.as_ref().map(hex::encode))]
        hash: Option<Box<[u8]>>,
        /// Data source
        source: Box<Message<'a>>,
        /// Final signature,
        signature: Signature,
    },
    Error,
}

impl<'a> SignatureOnePassReader<'a> {
    pub(crate) fn new(ops: &OnePassSignature, source: Box<Message<'a>>) -> Result<Self> {
        let mut hasher = ops.hash_algorithm().new_hasher().ok();
        if let Some(ref mut hasher) = hasher {
            if let OpsVersionSpecific::V6 { salt, .. } = ops.version_specific() {
                // Salt size must match the expected length for the hash algorithm that is used
                //
                // See: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3-2.10.2.1.1
                ensure_eq!(
                    ops.hash_algorithm().salt_len(),
                    Some(salt.len()),
                    "Illegal salt length {} for a V6 Signature using {:?}",
                    salt.len(),
                    ops.hash_algorithm(),
                );

                hasher.update(salt.as_ref());
            }
        }
        let text_mode = ops.typ() == SignatureType::Text;
        let norm_hasher = hasher.map(|hasher| NormalizingHasher::new(hasher, text_mode));

        Ok(Self::Init {
            norm_hasher,
            source,
        })
    }

    pub fn hash(&self) -> Option<&[u8]> {
        match self {
            Self::Init { .. } => None,
            Self::Body { .. } => None,
            Self::Done { hash, .. } => hash.as_deref(),
            Self::Error => panic!("SignatureOnePassReader errored"),
        }
    }

    pub fn signature(&self) -> Option<&Signature> {
        match self {
            Self::Init { .. } => None,
            Self::Body { .. } => None,
            Self::Done { signature, .. } => Some(signature),
            Self::Error => panic!("SignatureOnePassReader errored"),
        }
    }

    pub fn get_ref(&self) -> &Message<'a> {
        match self {
            Self::Init { source, .. } => source,
            Self::Body { source, .. } => source,
            Self::Done { source, .. } => source,
            Self::Error => panic!("SignatureOnePassReader errored"),
        }
    }

    pub fn get_mut(&mut self) -> &mut Message<'a> {
        match self {
            Self::Init { source, .. } => source,
            Self::Body { source, .. } => source,
            Self::Done { source, .. } => source,
            Self::Error => panic!("SignatureOnePassReader errored"),
        }
    }

    pub fn into_inner(self) -> PacketBodyReader<MessageReader<'a>> {
        match self {
            Self::Init { source, .. } => source.into_inner(),
            Self::Body { source, .. } => source.into_inner(),
            Self::Done { source, .. } => source.into_inner(),
            Self::Error => panic!("SignatureOnePassReader errored"),
        }
    }

    fn fill_inner(&mut self) -> io::Result<()> {
        if matches!(self, Self::Done { .. }) {
            return Ok(());
        }

        loop {
            match std::mem::replace(self, Self::Error) {
                Self::Init {
                    mut norm_hasher,
                    mut source,
                } => {
                    debug!("SignatureOnePassReader init");
                    let mut buffer = BytesMut::with_capacity(BUFFER_SIZE);
                    let read = fill_buffer_bytes(&mut source, &mut buffer, BUFFER_SIZE)?;

                    if read == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "missing signature",
                        ));
                    }

                    if let Some(ref mut hasher) = norm_hasher {
                        hasher.hash_buf(&buffer[..read]);
                    }

                    *self = Self::Body {
                        norm_hasher,
                        source,
                        buffer,
                    };
                }
                Self::Body {
                    mut norm_hasher,
                    mut source,
                    mut buffer,
                } => {
                    debug!("SignatureOnePassReader body");

                    if buffer.has_remaining() {
                        *self = Self::Body {
                            norm_hasher,
                            source,
                            buffer,
                        };
                        return Ok(());
                    }

                    let read = fill_buffer_bytes(&mut source, &mut buffer, BUFFER_SIZE)?;

                    if let Some(ref mut hasher) = norm_hasher {
                        hasher.hash_buf(&buffer[..read]);
                    }

                    if read == 0 {
                        debug!("SignatureOnePassReader finish");

                        let hasher = norm_hasher.map(|h| h.done());

                        let (reader, parts) = source.into_parts();

                        // read the signature
                        let mut packets = crate::packet::PacketParser::new(reader);
                        let Some(packet) = packets.next() else {
                            return Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "missing signature packet",
                            ));
                        };
                        let packet =
                            packet.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

                        let Packet::Signature(signature) = packet else {
                            return Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                format!(
                                    "missing signature packet, found {:?} instead",
                                    packet.tag()
                                ),
                            ));
                        };

                        // calculate final hash
                        let hash = if let Some(mut hasher) = hasher {
                            debug!("calculating final hash");
                            if let Some(config) = signature.config() {
                                let len = config
                                    .hash_signature_data(&mut hasher)
                                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                                hasher.update(
                                    &config.trailer(len).map_err(|e| {
                                        io::Error::new(io::ErrorKind::InvalidData, e)
                                    })?,
                                );
                                Some(hasher.finalize())
                            } else {
                                None
                            }
                        } else {
                            None
                        };

                        // reconstruct message source
                        let reader = packets.into_inner();
                        let source = parts.into_message(reader);

                        *self = Self::Done {
                            signature,
                            hash,
                            source: Box::new(source),
                        };
                    } else {
                        *self = Self::Body {
                            norm_hasher,
                            source,
                            buffer,
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
                Self::Error => return Err(io::Error::other("SignatureOnePassReader errored")),
            }
        }
    }

    pub fn is_done(&self) -> bool {
        matches!(self, Self::Done { .. })
    }

    pub(crate) fn decompress(self) -> Result<Self> {
        match self {
            Self::Init {
                norm_hasher,
                source,
            } => {
                let source = source.decompress()?;
                Ok(Self::Init {
                    norm_hasher,
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
            Self::Init {
                norm_hasher,
                source,
            } => {
                let (source, fps) = source.decrypt_the_ring(ring, abort_early)?;
                Ok((
                    Self::Init {
                        norm_hasher,
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

impl BufRead for SignatureOnePassReader<'_> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.fill_inner()?;
        match self {
            Self::Init { .. } => unreachable!("invalid state"),
            Self::Body { buffer, .. } => Ok(&buffer[..]),
            Self::Done { .. } => Ok(&[][..]),
            Self::Error => Err(io::Error::other("SignatureOnePassReader errored")),
        }
    }

    fn consume(&mut self, amt: usize) {
        match self {
            Self::Init { .. } => panic!("must not be called before fill_buf"),
            Self::Body { buffer, .. } => {
                buffer.advance(amt);
            }
            Self::Done { .. } => {}
            Self::Error => panic!("SignatureOnePassReader errored"),
        }
    }
}

impl Read for SignatureOnePassReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.fill_inner()?;
        match self {
            Self::Init { .. } => unreachable!("invalid state"),
            Self::Body { buffer, .. } => {
                let to_write = buffer.remaining().min(buf.len());
                buffer.copy_to_slice(&mut buf[..to_write]);
                Ok(to_write)
            }
            Self::Done { .. } => Ok(0),
            Self::Error => Err(io::Error::other("SignatureOnePassReader errored")),
        }
    }
}

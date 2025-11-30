use std::io::{self, BufRead, Read};

use bytes::{Buf, BytesMut};
use log::debug;

use super::PacketBodyReader;
use crate::{
    composed::{Message, MessageReader, RingResult, TheRing},
    errors::{bail, ensure_eq, Error, Result},
    packet::{OnePassSignature, OpsVersionSpecific, Packet, PacketTrait, Signature, SignatureType},
    util::{fill_buffer_bytes, NormalizingHasher},
};

const BUFFER_SIZE: usize = 8 * 1024;

#[derive(derive_more::Debug)]
pub enum SignatureOnePassManyReader<'a> {
    Init {
        /// One Pass Signature packet
        ops: Vec<OnePassSignature>,
        /// Running hasher
        hashers: Vec<NormalizingHasher>,
        /// Data source
        source: Box<Message<'a>>,
    },
    Body {
        /// One Pass Signature packet
        ops: Vec<OnePassSignature>,
        /// Running hasher
        hashers: Vec<NormalizingHasher>,
        /// Data source
        source: Box<Message<'a>>,
        #[debug("{}", hex::encode(buffer))]
        buffer: BytesMut,
    },
    Done {
        /// Finalized hashes
        hashes: Vec<Option<Box<[u8]>>>,
        /// Data source
        source: Box<Message<'a>>,
        /// Final signatures
        signatures: Vec<Signature>,
    },
    Error,
}

fn create_hasher(ops: &OnePassSignature) -> Result<NormalizingHasher> {
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
    let hasher = hasher.map(|hasher| NormalizingHasher::new(hasher, text_mode));
    let hasher = hasher.expect("no hasher??");
    Ok(hasher)
}

impl<'a> SignatureOnePassManyReader<'a> {
    pub(crate) fn new(ops: Vec<OnePassSignature>, source: Box<Message<'a>>) -> Result<Self> {
        let hashers = ops
            .iter()
            .map(|ops| create_hasher(ops))
            .collect::<Result<Vec<_>>>()?;

        Ok(Self::Init {
            ops,
            hashers,
            source,
        })
    }

    pub fn num_signatures(&self) -> usize {
        match self {
            Self::Init { ops, .. } => ops.len(),
            Self::Body { ops, .. } => ops.len(),
            Self::Done { hashes, .. } => hashes.len(),
            Self::Error => panic!("SignatureOnePassManyReader errored"),
        }
    }

    pub fn hash(&self, index: usize) -> Option<&[u8]> {
        match self {
            Self::Init { .. } => None,
            Self::Body { .. } => None,
            Self::Done { hashes, .. } => hashes.get(index).and_then(|h| h.as_deref()),
            Self::Error => panic!("SignatureOnePassManyReader errored"),
        }
    }

    pub fn signature(&self, index: usize) -> Option<&Signature> {
        match self {
            Self::Init { .. } => None,
            Self::Body { .. } => None,
            Self::Done { signatures, .. } => signatures.get(index),
            Self::Error => panic!("SignatureOnePassManyReader errored"),
        }
    }

    pub fn get_ref(&self) -> &Message<'a> {
        match self {
            Self::Init { source, .. } => source,
            Self::Body { source, .. } => source,
            Self::Done { source, .. } => source,
            Self::Error => panic!("SignatureOnePassManyReader errored"),
        }
    }

    pub fn get_mut(&mut self) -> &mut Message<'a> {
        match self {
            Self::Init { source, .. } => source,
            Self::Body { source, .. } => source,
            Self::Done { source, .. } => source,
            Self::Error => panic!("SignatureOnePassManyReader errored"),
        }
    }

    pub fn into_inner(self) -> PacketBodyReader<MessageReader<'a>> {
        match self {
            Self::Init { source, .. } => source.into_inner(),
            Self::Body { source, .. } => source.into_inner(),
            Self::Done { source, .. } => source.into_inner(),
            Self::Error => panic!("SignatureOnePassManyReader errored"),
        }
    }

    fn fill_inner(&mut self) -> io::Result<()> {
        if matches!(self, Self::Done { .. }) {
            return Ok(());
        }

        loop {
            match std::mem::replace(self, Self::Error) {
                Self::Init {
                    ops,
                    mut hashers,
                    mut source,
                } => {
                    debug!("SignatureOnePassManyReader init");
                    let mut buffer = BytesMut::with_capacity(BUFFER_SIZE);
                    let read = fill_buffer_bytes(&mut source, &mut buffer, BUFFER_SIZE)?;

                    if read == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "missing signature",
                        ));
                    }

                    for hasher in &mut hashers {
                        hasher.hash_buf(&buffer[..read]);
                    }

                    *self = Self::Body {
                        ops,
                        hashers,
                        source,
                        buffer,
                    };
                }
                Self::Body {
                    ops,
                    mut hashers,
                    mut source,
                    mut buffer,
                } => {
                    debug!("SignatureOnePassManyReader body");

                    if buffer.has_remaining() {
                        *self = Self::Body {
                            ops,
                            hashers,
                            source,
                            buffer,
                        };
                        return Ok(());
                    }

                    let read = fill_buffer_bytes(&mut source, &mut buffer, BUFFER_SIZE)?;

                    for hasher in &mut hashers {
                        hasher.hash_buf(&buffer[..read]);
                    }

                    if read == 0 {
                        debug!("SignatureOnePassManyReader finish");

                        let hashers: Vec<_> = hashers.into_iter().map(|h| h.done()).collect();

                        let (reader, parts) = source.into_parts();

                        let mut packets = crate::packet::PacketParser::new(reader);

                        // Find the signatures (skip padding and non-critical packets along the way)
                        let mut signatures = Vec::with_capacity(ops.len());

                        while signatures.len() < ops.len() {
                            // read next packet from stream, if any
                            let Some(res) = packets.next() else {
                                // no more packets
                                return Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "missing signature packet",
                                ));
                            };

                            // skip marker and padding packets (and read next packet)
                            if matches!(res, Ok(Packet::Marker(_))) {
                                debug!("skipping marker packet");
                                continue;
                            }
                            if matches!(res, Ok(Packet::Padding(_))) {
                                debug!("skipping padding packet");
                                continue;
                            }

                            // skip soft packet parser errors (e.g. unknown non-critical packets)
                            // and read the next packet
                            if let Err(Error::InvalidPacketContent { ref source }) = res {
                                let err: &Error = source; // unbox
                                if let Error::Unsupported { message, .. } = err {
                                    debug!("skipping unsupported packet: {res:?} ({message})");
                                    continue;
                                }
                            }

                            // bubble up any other errors
                            let packet =
                                res.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

                            if let Packet::Signature(signature) = packet {
                                signatures.push(signature);
                            } else {
                                return Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    format!(
                                        "missing signature packet, found {:?} instead",
                                        packet.tag()
                                    ),
                                ));
                            };
                        }

                        // reverse the order of the signatures as we collected them in the opposite order.
                        let signatures: Vec<_> = signatures.into_iter().rev().collect();

                        // calculate final hash
                        let hashes = hashers
                            .into_iter()
                            .enumerate()
                            .map(|(i, mut hasher)| {
                                if !ops[i].matches(&signatures[i]) {
                                    debug!(
                                        "Ops and Signature don't match, rejecting this signature"
                                    );

                                    // If Ops and Signature don't match, we consider the signature invalid.
                                    // Return an empty hash to model this.
                                    Ok(None)
                                } else if let Some(config) = signatures[i].config() {
                                    debug!("calculating final hash");

                                    let len =
                                        config.hash_signature_data(&mut hasher).map_err(|e| {
                                            io::Error::new(io::ErrorKind::InvalidData, e)
                                        })?;
                                    hasher.update(&config.trailer(len).map_err(|e| {
                                        io::Error::new(io::ErrorKind::InvalidData, e)
                                    })?);
                                    Ok(Some(hasher.finalize()))
                                } else {
                                    Ok(None)
                                }
                            })
                            .collect::<io::Result<Vec<_>>>()?;

                        // reconstruct message source
                        let reader = packets.into_inner();
                        let source = parts.into_message(reader);

                        *self = Self::Done {
                            signatures,
                            hashes,
                            source: Box::new(source),
                        };
                    } else {
                        *self = Self::Body {
                            ops,
                            hashers,
                            source,
                            buffer,
                        }
                    }

                    return Ok(());
                }
                Self::Done {
                    hashes,
                    source,
                    signatures,
                } => {
                    *self = Self::Done {
                        hashes,
                        source,
                        signatures,
                    };
                    return Ok(());
                }
                Self::Error => return Err(io::Error::other("SignatureOnePassManyReader errored")),
            }
        }
    }

    pub fn is_done(&self) -> bool {
        matches!(self, Self::Done { .. })
    }

    pub(crate) fn decompress(self) -> Result<Self> {
        match self {
            Self::Init {
                ops,
                hashers,
                source,
            } => {
                let source = source.decompress()?;
                Ok(Self::Init {
                    ops,
                    hashers,
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
                ops,
                hashers,
                source,
            } => {
                let (source, fps) = source.decrypt_the_ring(ring, abort_early)?;
                Ok((
                    Self::Init {
                        ops,
                        hashers,
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

impl BufRead for SignatureOnePassManyReader<'_> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.fill_inner()?;
        match self {
            Self::Init { .. } => unreachable!("invalid state"),
            Self::Body { buffer, .. } => Ok(&buffer[..]),
            Self::Done { .. } => Ok(&[][..]),
            Self::Error => Err(io::Error::other("SignatureOnePassManyReader errored")),
        }
    }

    fn consume(&mut self, amt: usize) {
        match self {
            Self::Init { .. } => panic!("must not be called before fill_buf"),
            Self::Body { buffer, .. } => {
                buffer.advance(amt);
            }
            Self::Done { .. } => {}
            Self::Error => panic!("SignatureOnePassManyReader errored"),
        }
    }
}

impl Read for SignatureOnePassManyReader<'_> {
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
            Self::Error => Err(io::Error::other("SignatureOnePassManyReader errored")),
        }
    }
}

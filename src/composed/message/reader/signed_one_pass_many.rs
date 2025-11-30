use std::io::{self, BufRead, Read};

use bytes::{Buf, BytesMut};
use log::debug;

use super::PacketBodyReader;
use crate::{
    composed::{Message, MessageReader, RingResult, TheRing},
    errors::{bail, ensure_eq, Error, Result},
    packet::{
        OnePassSignature, OpsVersionSpecific, Packet, PacketTrait, Signature, SignatureType,
        SignatureVersionSpecific,
    },
    util::{fill_buffer_bytes, NormalizingHasher},
};

const BUFFER_SIZE: usize = 8 * 1024;

#[derive(Debug)]
pub enum SignaturePacket {
    Ops {
        signature: crate::packet::OnePassSignature,
    },
    Signature {
        signature: crate::packet::Signature,
    },
}

impl SignaturePacket {
    fn new_hasher(&self) -> Result<Option<NormalizingHasher>> {
        let hasher = match self {
            Self::Ops { signature } => {
                let mut hasher = signature.hash_algorithm().new_hasher().ok();

                if let Some(ref mut hasher) = hasher {
                    if let OpsVersionSpecific::V6 { salt, .. } = signature.version_specific() {
                        // Salt size must match the expected length for the hash algorithm that is used
                        //
                        // See: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3-2.10.2.1.1
                        ensure_eq!(
                            signature.hash_algorithm().salt_len(),
                            Some(salt.len()),
                            "Illegal salt length {} for a V6 Signature using {:?}",
                            salt.len(),
                            signature.hash_algorithm(),
                        );

                        hasher.update(salt.as_ref());
                    }
                }
                hasher
            }
            Self::Signature { signature } => {
                if let Some(config) = signature.config() {
                    let mut hasher = config.hash_alg.new_hasher()?;
                    if let SignatureVersionSpecific::V6 { ref salt, .. } = config.version_specific {
                        // Salt size must match the expected length for the hash algorithm that is used
                        //
                        // See: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3-2.10.2.1.1
                        ensure_eq!(
                            config.hash_alg.salt_len(),
                            Some(salt.len()),
                            "Illegal salt length {} for a V6 Signature using {:?}",
                            salt.len(),
                            config.hash_alg,
                        );

                        hasher.update(salt.as_ref());
                    }
                    Some(hasher)
                } else {
                    None
                }
            }
        };

        let text_mode = match self {
            Self::Ops { signature } => signature.typ() == SignatureType::Text,
            Self::Signature { signature } => signature.typ() == Some(SignatureType::Text),
        };
        let hasher = hasher.map(|hasher| NormalizingHasher::new(hasher, text_mode));
        Ok(hasher)
    }
}

#[derive(derive_more::Debug)]
pub enum SignatureOnePassManyReader<'a> {
    Init {
        /// (One Pass) Signature packet
        packets: Vec<SignaturePacket>,
        /// Running hasher
        hashers: Vec<Option<NormalizingHasher>>,
        /// Data source
        source: Box<Message<'a>>,
    },
    Body {
        /// One Pass Signature packet
        packets: Vec<SignaturePacket>,
        /// Running hasher
        hashers: Vec<Option<NormalizingHasher>>,
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

impl<'a> SignatureOnePassManyReader<'a> {
    pub(crate) fn new(packets: Vec<SignaturePacket>, source: Box<Message<'a>>) -> Result<Self> {
        let hashers = packets
            .iter()
            .map(|p| p.new_hasher())
            .collect::<Result<Vec<_>>>()?;

        Ok(Self::Init {
            packets,
            hashers,
            source,
        })
    }

    pub fn num_signatures(&self) -> usize {
        match self {
            Self::Init { packets, .. } => packets.len(),
            Self::Body { packets, .. } => packets.len(),
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
                    packets,
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

                    for hasher in hashers.iter_mut().filter_map(|h| h.as_mut()) {
                        hasher.hash_buf(&buffer[..read]);
                    }

                    *self = Self::Body {
                        packets,
                        hashers,
                        source,
                        buffer,
                    };
                }
                Self::Body {
                    packets,
                    mut hashers,
                    mut source,
                    mut buffer,
                } => {
                    debug!("SignatureOnePassManyReader body");

                    if buffer.has_remaining() {
                        *self = Self::Body {
                            packets,
                            hashers,
                            source,
                            buffer,
                        };
                        return Ok(());
                    }

                    let read = fill_buffer_bytes(&mut source, &mut buffer, BUFFER_SIZE)?;

                    for hasher in hashers.iter_mut().filter_map(|h| h.as_mut()) {
                        hasher.hash_buf(&buffer[..read]);
                    }

                    if read == 0 {
                        debug!("SignatureOnePassManyReader finish");

                        let hashers: Vec<_> =
                            hashers.into_iter().map(|h| h.map(|h| h.done())).collect();

                        let (reader, parts) = source.into_parts();

                        let mut packet_parser = crate::packet::PacketParser::new(reader);

                        // Find the signatures (skip padding and non-critical packets along the way)

                        let num_ops = packets
                            .iter()
                            .filter(|p| matches!(p, SignaturePacket::Ops { .. }))
                            .count();
                        let mut signatures = Vec::with_capacity(num_ops);
                        while signatures.len() < num_ops {
                            // read next packet from stream, if any
                            let Some(res) = packet_parser.next() else {
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

                        // TODO: adjust for indexing into signatures (it only has num_ops elements)

                        // calculate final hash
                        let hashes = hashers
                            .into_iter()
                            .enumerate()
                            .map(|(i, hasher)| {
                                if let Some(mut hasher) = hasher {
                                    match &packets[i] {
                                        SignaturePacket::Ops { signature: packet } => {
                                            if !packet.matches(&signatures[i]) {
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
                                        }
                                        SignaturePacket::Signature { signature: packet } => {
                                            // regular signature
                                            let config = packet.config().ok_or_else(|| {
                                                io::Error::new(
                                                    io::ErrorKind::InvalidData,
                                                    "inconsistent signature state",
                                                )
                                            })?;
                                            // calculate final hash
                                            let len = config
                                                .hash_signature_data(&mut hasher)
                                                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                                            hasher.update(
                                                &config
                                                    .trailer(len)
                                                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
                                            );

                                            Ok(Some(hasher.finalize()))
                                        }
                                    }
                                } else {
                                    Ok(None)
                                }
                            })
                            .collect::<io::Result<Vec<_>>>()?;

                        // reconstruct message source
                        let reader = packet_parser.into_inner();
                        let source = parts.into_message(reader);

                        *self = Self::Done {
                            signatures,
                            hashes,
                            source: Box::new(source),
                        };
                    } else {
                        *self = Self::Body {
                            packets,
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
                packets,
                hashers,
                source,
            } => {
                let source = source.decompress()?;
                Ok(Self::Init {
                    packets,
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
                packets,
                hashers,
                source,
            } => {
                let (source, fps) = source.decrypt_the_ring(ring, abort_early)?;
                Ok((
                    Self::Init {
                        packets,
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

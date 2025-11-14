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
pub enum SignatureOnePassReader<'a> {
    Init {
        /// One Pass Signature packet
        ops: OnePassSignature,
        /// Running hasher
        norm_hasher: Option<NormalizingHasher>,
        /// Data source
        source: Box<Message<'a>>,
    },
    Body {
        /// One Pass Signature packet
        ops: OnePassSignature,
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
    pub(crate) fn new(ops: OnePassSignature, source: Box<Message<'a>>) -> Result<Self> {
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
            ops,
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
                    ops,
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
                        ops,
                        norm_hasher,
                        source,
                        buffer,
                    };
                }
                Self::Body {
                    ops,
                    mut norm_hasher,
                    mut source,
                    mut buffer,
                } => {
                    debug!("SignatureOnePassReader body");

                    if buffer.has_remaining() {
                        *self = Self::Body {
                            ops,
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

                        let mut packets = crate::packet::PacketParser::new(reader);

                        // Find the signature (skip padding and non-critical packets along the way)
                        let signature = loop {
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
                                break signature;
                            } else {
                                return Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    format!(
                                        "missing signature packet, found {:?} instead",
                                        packet.tag()
                                    ),
                                ));
                            };
                        };

                        // calculate final hash
                        let hash = if let Some(mut hasher) = hasher {
                            if !ops.matches(&signature) {
                                debug!("Ops and Signature don't match, rejecting this signature");

                                // If Ops and Signature don't match, we consider the signature invalid.
                                // Return an empty hash to model this.
                                None
                            } else if let Some(config) = signature.config() {
                                debug!("calculating final hash");

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
                            ops,
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
                ops,
                norm_hasher,
                source,
            } => {
                let source = source.decompress()?;
                Ok(Self::Init {
                    ops,
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
                ops,
                norm_hasher,
                source,
            } => {
                let (source, fps) = source.decrypt_the_ring(ring, abort_early)?;
                Ok((
                    Self::Init {
                        ops,
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

#[cfg(test)]
mod tests {

    use chacha20::ChaCha20Rng;
    use rand::SeedableRng;

    use crate::{
        armor,
        armor::{BlockType, Headers},
        composed::{Deserializable, DetachedSignature, Message, SignedSecretKey},
        crypto::hash::HashAlgorithm,
        packet::{LiteralData, OnePassSignature, Packet, SignatureType},
        ser::Serialize,
        types::{KeyDetails, Password},
    };

    const PLAIN: &str = "hello world\r\n";
    const PLAIN_LF: &str = "hello world\n";

    #[test]
    fn message_with_deviating_ops() {
        // Produces a doctored message, which should not validate as ok.
        // It has the deviating signature type "Text" in the one pass signature packet.
        // The message payload would verify as a correct message if the signature were indeed a text mode signature.
        // However, only the OPS shows "Text", while the "main" Signature packets shows signature type "Binary".
        // Therefore, the message should not show successful verification.

        let _ = pretty_env_logger::try_init();

        let rng = ChaCha20Rng::seed_from_u64(1);

        let (bob, _) =
            SignedSecretKey::from_armor_file("./tests/draft-bre-openpgp-samples-00/bob.sec.asc")
                .unwrap();

        // Make a binary signature over "PLAIN"
        let sig = DetachedSignature::sign_binary_data(
            rng,
            &bob.primary_key,
            &Password::empty(),
            HashAlgorithm::Sha256,
            PLAIN.as_bytes(),
        )
        .unwrap();

        let ops = OnePassSignature::v3(
            SignatureType::Text, // Type deviates from the actual Signature!
            HashAlgorithm::Sha256,
            bob.primary_key.algorithm(),
            bob.primary_key.key_id(),
        );

        // Payload uses different line ending!
        let lit = LiteralData::from_bytes(&[][..], PLAIN_LF.as_bytes().into()).unwrap();

        // Construct a binary representation of this hacked message
        let packets: Vec<Packet> = vec![
            Packet::OnePassSignature(ops),
            Packet::LiteralData(lit),
            Packet::Signature(sig.signature),
        ];

        let mut binary_msg = vec![];
        for p in &packets {
            p.to_writer(&mut binary_msg).unwrap();
        }

        // debug print armored version of the message
        let mut armored = vec![];
        armor::write(
            &packets,
            BlockType::Message,
            &mut armored,
            Some(&Headers::default()),
            true,
        )
        .unwrap();
        log::debug!("{}", String::from_utf8(armored).unwrap());

        // Parse message from binary
        let mut msg = Message::from_bytes(&*binary_msg).unwrap();

        let _ = msg.as_data_vec().unwrap();

        msg.verify(bob.primary_key.public_key())
            .expect_err("this doctored message must not validate as ok");
    }
}

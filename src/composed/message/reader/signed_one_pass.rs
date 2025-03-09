use std::io::{self, BufRead, Read};

use bytes::{Buf, BytesMut};
use digest::DynDigest;
use log::debug;
use nom::InputIter;

use super::PacketBodyReader;
use crate::errors::Result;
use crate::packet::{
    OnePassSignature, OpsVersionSpecific, Packet, PacketTrait, Signature, SignatureType,
};
use crate::util::fill_buffer;
use crate::{Message, RingResult, TheRing};

#[derive(derive_more::Debug)]
pub enum SignatureOnePassReader<'a> {
    Init {
        /// Running hasher
        #[debug("hasher")]
        hasher: Box<dyn DynDigest>,
        /// Data source
        source: Box<Message<'a>>,
        /// If Text Mode, then line endings are normalized during hashing
        text_mode: bool,
    },
    Body {
        /// Running hasher
        #[debug("hasher")]
        hasher: Box<dyn DynDigest>,
        /// Data source
        source: Box<Message<'a>>,
        buffer: BytesMut,

        /// If Text Mode, then line endings are normalized during hashing
        text_mode: bool,
        /// true if the last byte that was fed into the hasher was a `\r`
        last_was_cr: bool,
    },
    Done {
        /// Finalized hash
        hash: Box<[u8]>,
        /// Data source
        source: Box<Message<'a>>,
        /// Final signature,
        signature: Signature,
    },
    Error,
}

impl<'a> SignatureOnePassReader<'a> {
    pub(crate) fn new(ops: &OnePassSignature, source: Box<Message<'a>>) -> Result<Self> {
        let mut hasher = ops.hash_algorithm().new_hasher()?;
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

        let text_mode = ops.typ() == SignatureType::Text;

        Ok(Self::Init {
            hasher,
            source,
            text_mode,
        })
    }

    pub fn hash(&self) -> Option<&[u8]> {
        match self {
            Self::Done { hash, .. } => Some(hash),
            Self::Error => panic!("error state"),
            _ => None,
        }
    }

    pub fn signature(&self) -> Option<&Signature> {
        match self {
            Self::Done { signature, .. } => Some(signature),
            Self::Error => panic!("error state"),
            _ => None,
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
                    text_mode,
                } => {
                    debug!("SignatureOnePassReader init");
                    let mut buffer = BytesMut::zeroed(1024);
                    let read = fill_buffer(&mut source, &mut buffer, None)?;
                    buffer.truncate(read);

                    if read == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "missing signature",
                        ));
                    }

                    let mut last_was_cr = false;

                    if !text_mode {
                        hasher.update(&buffer[..read]);
                    } else {
                        if last_was_cr && buffer[0] != b'\n' {
                            hasher.update(b"\n");
                            last_was_cr = false;
                        }

                        let mut buf = &buffer[..read];
                        while !buf.is_empty() {
                            match buf.position(|c| c == b'\r' || c == b'\n') {
                                Some(pos) => {
                                    // consume all bytes before line-break-related position

                                    hasher.update(&buf[..pos]);
                                    buf = &buf[pos..];

                                    // handle this line-break related context
                                    let only_one = buf.len() == 1;
                                    match (buf[0], only_one) {
                                        (b'\n', _) => {
                                            hasher.update(b"\r\n");
                                            buf = &buf[1..];
                                        }
                                        (b'\r', false) => {
                                            hasher.update(b"\r\n");

                                            // we are guaranteed to have at least two bytes
                                            if buf[1] == b'\n' {
                                                buf = &buf[2..];
                                            } else {
                                                buf = &buf[1..];
                                            }
                                        }
                                        (b'\r', true) => {
                                            // we only have this one '\r' byte left
                                            hasher.update(b"\r");
                                            buf = &[];
                                            last_was_cr = true;
                                        }
                                        _ => unreachable!(),
                                    }
                                }
                                None => {
                                    hasher.update(buf);
                                    buf = &[]
                                }
                            }
                        }
                    }

                    *self = Self::Body {
                        source,
                        hasher,
                        buffer,
                        text_mode,
                        last_was_cr,
                    };
                }
                Self::Body {
                    mut hasher,
                    mut source,
                    mut buffer,
                    text_mode,
                    mut last_was_cr,
                } => {
                    debug!("SignatureOnePassReader body");

                    if buffer.has_remaining() {
                        *self = Self::Body {
                            hasher,
                            source,
                            buffer,
                            text_mode,
                            last_was_cr,
                        };
                        return Ok(());
                    }

                    buffer.resize(1024, 0);
                    let read = fill_buffer(&mut source, &mut buffer, None)?;
                    buffer.truncate(read);

                    if !text_mode {
                        hasher.update(&buffer[..read]);
                    } else {
                        if last_was_cr && buffer[0] != b'\n' {
                            hasher.update(b"\n");
                            last_was_cr = false;
                        }

                        let mut buf = &buffer[..read];
                        while !buf.is_empty() {
                            match buf.position(|c| c == b'\r' || c == b'\n') {
                                Some(pos) => {
                                    // consume all bytes before line-break-related position

                                    hasher.update(&buf[..pos]);
                                    buf = &buf[pos..];

                                    // handle this line-break related context
                                    let only_one = buf.len() == 1;
                                    match (buf[0], only_one) {
                                        (b'\n', _) => {
                                            hasher.update(b"\r\n");
                                            buf = &buf[1..];
                                        }
                                        (b'\r', false) => {
                                            hasher.update(b"\r\n");

                                            // we are guaranteed to have at least two bytes
                                            if buf[1] == b'\n' {
                                                buf = &buf[2..];
                                            } else {
                                                buf = &buf[1..];
                                            }
                                        }
                                        (b'\r', true) => {
                                            // we only have this one '\r' byte left
                                            hasher.update(b"\r");
                                            buf = &[];
                                            last_was_cr = true;
                                        }
                                        _ => unreachable!(),
                                    }
                                }
                                None => {
                                    hasher.update(buf);
                                    buf = &[]
                                }
                            }
                        }
                    }

                    if read == 0 {
                        debug!("SignatureOnePassReader finish");

                        let (reader, parts) = source.into_parts();

                        // read the signature
                        let mut packets = crate::packet::PacketParser::new(reader);
                        let Some(packet) = packets.next() else {
                            return Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "missing signature packet",
                            ));
                        };
                        let packet = packet.map_err(|e| {
                            io::Error::new(io::ErrorKind::InvalidData, e.to_string())
                        })?;

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
                            hasher,
                            source,
                            buffer,
                            text_mode,
                            last_was_cr,
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
                text_mode,
            } => {
                let source = source.decompress()?;
                Ok(Self::Init {
                    hasher,
                    source: Box::new(source),
                    text_mode,
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
                text_mode,
            } => {
                let (source, fps) = source.decrypt_the_ring(ring, abort_early)?;
                Ok((
                    Self::Init {
                        hasher,
                        source: Box::new(source),
                        text_mode,
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

impl Read for SignatureOnePassReader<'_> {
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

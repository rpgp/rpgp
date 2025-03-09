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
pub struct NormalizingHasher {
    #[debug("hasher")]
    hasher: Box<dyn DynDigest>,
    text_mode: bool,
    last_was_cr: bool,
}

impl NormalizingHasher {
    fn new(hasher: Box<dyn DynDigest>, text_mode: bool) -> Self {
        Self {
            hasher,
            text_mode,
            last_was_cr: false,
        }
    }

    fn done(mut self) -> Box<dyn DynDigest> {
        if self.text_mode && self.last_was_cr {
            self.hasher.update(b"\n")
        }

        self.hasher
    }

    fn hash_buf(&mut self, buffer: &[u8]) {
        if buffer.is_empty() {
            return;
        }

        if !self.text_mode {
            self.hasher.update(buffer);
        } else {
            let mut buf = buffer;

            if self.last_was_cr {
                self.hasher.update(b"\n");

                if buf[0] == b'\n' {
                    buf = &buf[1..];
                }

                self.last_was_cr = false;
            }

            while !buf.is_empty() {
                match buf.position(|c| c == b'\r' || c == b'\n') {
                    None => {
                        // no line endings in sight, just hash the data
                        self.hasher.update(buf);
                        buf = &[]
                    }

                    Some(pos) => {
                        // consume all bytes before line-break-related position

                        self.hasher.update(&buf[..pos]);
                        buf = &buf[pos..];

                        // handle this line-break related context
                        let only_one = buf.len() == 1;
                        match (buf[0], only_one) {
                            (b'\n', _) => {
                                self.hasher.update(b"\r\n");
                                buf = &buf[1..];
                            }
                            (b'\r', false) => {
                                self.hasher.update(b"\r\n");

                                // we are guaranteed to have at least two bytes
                                if buf[1] == b'\n' {
                                    // there was a '\n' in the stream, we consume it as well
                                    buf = &buf[2..];
                                } else {
                                    // this was a lone '\r', we have normalized it
                                    buf = &buf[1..];
                                }
                            }
                            (b'\r', true) => {
                                // this one '\r' was the last thing in the buffer
                                self.hasher.update(b"\r");
                                buf = &[];

                                self.last_was_cr = true;
                            }
                            _ => unreachable!("buf.position gave us either a '\n or a '\r'"),
                        }
                    }
                }
            }
        }
    }
}

#[derive(derive_more::Debug)]
pub enum SignatureOnePassReader<'a> {
    Init {
        // /// Running hasher
        // #[debug("hasher")]
        // hasher: Box<dyn DynDigest>,
        /// Running hasher
        #[debug("hasher")]
        norm_hasher: NormalizingHasher,

        /// Data source
        source: Box<Message<'a>>,
    },
    Body {
        // /// Running hasher
        // #[debug("hasher")]
        // hasher: Box<dyn DynDigest>,
        /// Running hasher
        #[debug("hasher")]
        norm_hasher: NormalizingHasher,
        /// Data source
        source: Box<Message<'a>>,
        buffer: BytesMut,
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

        let hasher = NormalizingHasher::new(hasher, text_mode);

        Ok(Self::Init {
            norm_hasher: hasher,
            source,
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
                    mut norm_hasher,
                    mut source,
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

                    norm_hasher.hash_buf(&buffer[..read]);

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

                    buffer.resize(1024, 0);
                    let read = fill_buffer(&mut source, &mut buffer, None)?;
                    buffer.truncate(read);

                    norm_hasher.hash_buf(&buffer[..read]);

                    if read == 0 {
                        debug!("SignatureOnePassReader finish");

                        let mut hasher = norm_hasher.done();

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
                norm_hasher: hasher,
                source,
            } => {
                let source = source.decompress()?;
                Ok(Self::Init {
                    norm_hasher: hasher,
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
                norm_hasher: hasher,
                source,
            } => {
                let (source, fps) = source.decrypt_the_ring(ring, abort_early)?;
                Ok((
                    Self::Init {
                        norm_hasher: hasher,
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

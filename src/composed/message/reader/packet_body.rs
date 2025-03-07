use std::io::{self, BufRead, Read};

use bytes::{Buf, BytesMut};
use log::debug;

use crate::packet::PacketHeader;
use crate::types::{PacketLength, Tag};

use super::{fill_buffer, LimitedReader};

#[derive(derive_more::Debug)]
pub struct PacketBodyReader<R: BufRead> {
    packet_header: PacketHeader,
    state: State<R>,
}

#[derive(derive_more::Debug)]
enum State<R: BufRead> {
    Header {
        #[debug("source")]
        source: R,
    },
    Body {
        buffer: BytesMut,
        source: LimitedReader<R>,
    },
    Done {
        #[debug("source")]
        source: R,
    },
    Error,
}

impl<R: BufRead> BufRead for PacketBodyReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.fill_inner()?;
        match self.state {
            State::Body { ref mut buffer, .. } => Ok(&buffer[..]),
            State::Done { .. } => Ok(&[][..]),
            State::Header { .. } => unreachable!("invalid state: header"),
            State::Error => panic!("PacketBodyReader errored"),
        }
    }

    fn consume(&mut self, amt: usize) {
        match self.state {
            State::Body { ref mut buffer, .. } => {
                buffer.advance(amt);
            }
            State::Error => panic!("PacketBodyreader errored"),
            State::Header { .. } => unreachable!("invalid state: header"),
            State::Done { .. } => {}
        }
    }
}

impl<R: BufRead> Read for PacketBodyReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.fill_inner()?;
        match self.state {
            State::Body { ref mut buffer, .. } => {
                let to_write = buffer.remaining().min(buf.len());
                buffer.copy_to_slice(&mut buf[..to_write]);
                Ok(to_write)
            }
            State::Done { .. } => Ok(0),
            _ => unreachable!("invalid state"),
        }
    }
}

impl<R: BufRead> PacketBodyReader<R> {
    pub fn new(packet_header: PacketHeader, source: R) -> Self {
        Self {
            packet_header,
            state: State::Header { source },
        }
    }

    pub fn new_done(packet_header: PacketHeader, source: R) -> Self {
        Self {
            packet_header,
            state: State::Done { source },
        }
    }

    pub fn is_done(&self) -> bool {
        matches!(self.state, State::Done { .. })
    }

    pub fn into_inner(self) -> R {
        match self.state {
            State::Header { source } => source,
            State::Body { source, .. } => source.into_inner(),
            State::Done { source } => source,
            State::Error => panic!("PacketBodyReader errored"),
        }
    }

    pub fn packet_header(&self) -> PacketHeader {
        self.packet_header
    }

    fn fill_inner(&mut self) -> io::Result<()> {
        if matches!(self.state, State::Done { .. }) {
            return Ok(());
        }

        loop {
            match std::mem::replace(&mut self.state, State::Error) {
                State::Header { source } => {
                    let source = match self.packet_header.packet_length() {
                        PacketLength::Fixed(len) => LimitedReader::Fixed(source.take(len as u64)),
                        PacketLength::Indeterminate => LimitedReader::Indeterminate(source),
                        PacketLength::Partial(len) => {
                            // https://www.rfc-editor.org/rfc/rfc9580.html#name-partial-body-lengths
                            // "An implementation MAY use Partial Body Lengths for data packets, be
                            // they literal, compressed, or encrypted [...]
                            // Partial Body Lengths MUST NOT be used for any other packet types"
                            if !matches!(
                                self.packet_header.tag(),
                                Tag::LiteralData
                                    | Tag::CompressedData
                                    | Tag::SymEncryptedData
                                    | Tag::SymEncryptedProtectedData
                            ) {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidInput,
                                    format!(
                                        "Partial body length is not allowed for packet type {:?}",
                                        self.packet_header.tag()
                                    ),
                                ));
                            }

                            // https://www.rfc-editor.org/rfc/rfc9580.html#section-4.2.1.4-5
                            // "The first partial length MUST be at least 512 octets long."
                            if len < 512 {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidInput,
                                    format!("Illegal first partial body length {} (shorter than 512 bytes)", len)
                                ));
                            }

                            LimitedReader::Partial(source.take(len as u64))
                        }
                    };

                    self.state = State::Body {
                        source,
                        buffer: BytesMut::with_capacity(1024),
                    };
                }
                State::Body {
                    mut buffer,
                    mut source,
                } => {
                    if buffer.has_remaining() {
                        self.state = State::Body { source, buffer };
                        return Ok(());
                    }

                    buffer.resize(1024, 0);
                    let read = fill_buffer(&mut source, &mut buffer, None)?;
                    buffer.truncate(read);

                    if read == 0 {
                        match source {
                            LimitedReader::Fixed(r) => {
                                self.state = State::Done {
                                    source: r.into_inner(),
                                };
                            }
                            LimitedReader::Indeterminate(source) => {
                                self.state = State::Done { source };
                            }
                            LimitedReader::Partial(r) => {
                                // new round
                                let mut source = r.into_inner();
                                let packet_length = PacketLength::try_from_reader(&mut source)?;

                                let source = match packet_length {
                                    PacketLength::Fixed(len) => {
                                        // the last one
                                        debug!("fixed partial packet {}", len);
                                        LimitedReader::Fixed(source.take(len as u64))
                                    }
                                    PacketLength::Partial(len) => {
                                        // another one
                                        debug!("intermediary partial packet {}", len);
                                        LimitedReader::Partial(source.take(len as u64))
                                    }
                                    PacketLength::Indeterminate => {
                                        return Err(io::Error::new(
                                            io::ErrorKind::InvalidInput,
                                            "invalid indeterminate packet length",
                                        ));
                                    }
                                };

                                self.state = State::Body { source, buffer };
                                continue;
                            }
                        };
                    } else {
                        self.state = State::Body { source, buffer };
                    }
                    return Ok(());
                }
                State::Done { source } => {
                    self.state = State::Done { source };
                    return Ok(());
                }
                State::Error => {
                    panic!("PacketBodyReader errored");
                }
            }
        }
    }
}

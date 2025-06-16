use std::io::{self, BufRead, Read};

use super::PacketBodyReader;
use crate::{
    composed::{DebugBufRead, PlainSessionKey},
    errors::{bail, ensure_eq, unsupported_err, Result},
    packet::{PacketHeader, StreamDecryptor, SymEncryptedProtectedDataConfig},
    types::Tag,
};

#[derive(Debug)]
pub struct SymEncryptedProtectedDataReader<R: DebugBufRead> {
    config: SymEncryptedProtectedDataConfig,
    source: Source<R>,
}

#[derive(Debug)]
enum Source<R: DebugBufRead> {
    Init(PacketBodyReader<R>),
    BodyRaw(PacketBodyReader<R>),
    BodyDecryptor(StreamDecryptor<PacketBodyReader<R>>),
    Done(PacketBodyReader<R>),
}

impl<R: DebugBufRead> SymEncryptedProtectedDataReader<R> {
    pub fn new(mut source: PacketBodyReader<R>) -> Result<Self> {
        debug_assert_eq!(source.packet_header().tag(), Tag::SymEncryptedProtectedData);
        let config = SymEncryptedProtectedDataConfig::try_from_reader(&mut source)?;

        Ok(Self {
            config,
            source: Source::Init(source),
        })
    }

    pub fn decrypt(&mut self, session_key: &PlainSessionKey) -> Result<()> {
        match self.source {
            Source::BodyDecryptor(_) => {
                bail!("cannot decrypt after starting to read")
            }
            Source::BodyRaw(_) => {
                bail!("cannot decrypt after starting to read")
            }
            Source::Done(_) => {
                bail!("cannot decrypt after finishing to read")
            }
            Source::Init(_) => {}
        }

        match self.config {
            SymEncryptedProtectedDataConfig::V1 => {
                let (sym_alg, session_key) = match session_key {
                    PlainSessionKey::V3_4 { sym_alg, key } => (sym_alg, key),
                    PlainSessionKey::V5 { .. } => {
                        unsupported_err!("v5 is not supported");
                    }
                    PlainSessionKey::V6 { .. } => {
                        bail!("mismatch between session key and edata config");
                    }
                    PlainSessionKey::Unknown { sym_alg, key } => (sym_alg, key),
                };

                replace_with::replace_with(
                    &mut self.source,
                    || todo!(),
                    |source| {
                        let Source::Init(source) = source else {
                            unreachable!("checked");
                        };
                        Source::BodyDecryptor(
                            StreamDecryptor::v1(*sym_alg, session_key, source).unwrap(),
                        )
                    },
                );
            }
            SymEncryptedProtectedDataConfig::V2 {
                sym_alg,
                aead,
                chunk_size,
                salt,
            } => {
                let (sym_alg_session_key, session_key) = match session_key {
                    PlainSessionKey::V3_4 { .. } => {
                        bail!("mismatch between session key and edata config");
                    }
                    PlainSessionKey::V5 { .. } => {
                        unsupported_err!("v5 is not supported");
                    }
                    PlainSessionKey::V6 { key } => (None, key),
                    PlainSessionKey::Unknown { sym_alg, key } => (Some(sym_alg), key),
                };
                if let Some(sym_alg_session_key) = sym_alg_session_key {
                    ensure_eq!(
                        sym_alg,
                        *sym_alg_session_key,
                        "mismatching symmetric key algorithm"
                    );
                }

                ensure_eq!(
                    session_key.len(),
                    sym_alg.key_size(),
                    "Unexpected session key length for {:?}",
                    sym_alg
                );
                replace_with::replace_with(
                    &mut self.source,
                    || todo!(),
                    |source| {
                        let Source::Init(source) = source else {
                            unreachable!("checked");
                        };
                        Source::BodyDecryptor(
                            StreamDecryptor::v2(
                                sym_alg,
                                aead,
                                chunk_size,
                                &salt,
                                session_key,
                                source,
                            )
                            .unwrap(),
                        )
                    },
                );
            }
        }
        Ok(())
    }

    pub(crate) fn new_done(
        config: SymEncryptedProtectedDataConfig,
        source: PacketBodyReader<R>,
    ) -> Self {
        Self {
            source: Source::Done(source),
            config,
        }
    }

    pub fn config(&self) -> &SymEncryptedProtectedDataConfig {
        &self.config
    }

    pub fn is_done(&self) -> bool {
        matches!(self.source, Source::Done { .. })
    }

    pub fn into_inner(self) -> PacketBodyReader<R> {
        match self.source {
            Source::Init(source) => source,
            Source::BodyDecryptor(source) => source.into_inner(),
            Source::BodyRaw(source) => source,
            Source::Done(source) => source,
        }
    }

    pub fn get_mut(&mut self) -> &mut PacketBodyReader<R> {
        match &mut self.source {
            Source::Init(source) => source,
            Source::BodyDecryptor(source) => source.get_mut(),
            Source::BodyRaw(source) => source,
            Source::Done(source) => source,
        }
    }

    pub fn packet_header(&self) -> PacketHeader {
        match &self.source {
            Source::Init(source) => source.packet_header(),
            Source::BodyDecryptor(source) => source.get_ref().packet_header(),
            Source::BodyRaw(source) => source.packet_header(),
            Source::Done(source) => source.packet_header(),
        }
    }

    fn fill_inner(&mut self) -> io::Result<()> {
        if matches!(self.source, Source::Done(_)) {
            return Ok(());
        }

        loop {
            let (needs_replacing, should_return) = match &mut self.source {
                Source::Init(_) => (true, false),
                Source::BodyRaw(source) => {
                    let buf = source.fill_buf()?;
                    (buf.is_empty(), true)
                }
                Source::BodyDecryptor(decryptor) => {
                    let buf = decryptor.fill_buf()?;
                    (buf.is_empty(), true)
                }
                Source::Done(_) => (false, true),
            };

            if needs_replacing {
                replace_with::replace_with(
                    &mut self.source,
                    || todo!(),
                    |source| match source {
                        Source::Init(source) => Source::BodyRaw(source),
                        Source::BodyRaw(source) => Source::Done(source),
                        Source::BodyDecryptor(source) => Source::Done(source.into_inner()),
                        Source::Done(source) => Source::Done(source),
                    },
                )
            }
            if should_return {
                return Ok(());
            }
        }
    }
}

impl<R: DebugBufRead> BufRead for SymEncryptedProtectedDataReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.fill_inner()?;
        match &mut self.source {
            Source::Init(..) => unreachable!("invalid state"),
            Source::BodyDecryptor(decryptor) => decryptor.fill_buf(),
            Source::BodyRaw(source) => source.fill_buf(),
            Source::Done(_) => Ok(&[][..]),
        }
    }

    fn consume(&mut self, amt: usize) {
        match &mut self.source {
            Source::Init(..) => unreachable!("invalid state"),
            Source::BodyDecryptor(decryptor) => decryptor.consume(amt),
            Source::BodyRaw(source) => source.consume(amt),
            Source::Done(_) => {
                if amt > 0 {
                    panic!("consume after done: {}", amt)
                }
            }
        }
    }
}

impl<R: DebugBufRead> Read for SymEncryptedProtectedDataReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.fill_inner()?;
        match &mut self.source {
            Source::Init(..) => unreachable!("invalid state"),
            Source::BodyDecryptor(decryptor) => decryptor.read(buf),
            Source::BodyRaw(source) => source.read(buf),
            Source::Done(_) => Ok(0),
        }
    }
}

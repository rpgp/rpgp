//! Parsing functions to parse data using [Buf].

use bytes::{Buf, Bytes};

/// Parsing errors
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{}: reading {:?}: {:?}", context, typ, error)]
    TooShort {
        typ: Typ,
        context: &'static str,
        error: RemainingError,
    },
    #[error("expected {}, found {}", debug_bytes(expected), debug_bytes(&found[..]))]
    TagMissmatch {
        expected: Vec<u8>,
        found: Bytes,
        context: &'static str,
    },
}

impl Error {
    /// Returns true if the error indictates that the input was too short.
    pub fn is_incomplete(&self) -> bool {
        match self {
            Self::TooShort { .. } => true,
            Self::TagMissmatch { .. } => false,
        }
    }
}

fn debug_bytes(b: &[u8]) -> String {
    if let Ok(s) = std::str::from_utf8(b) {
        return s.to_string();
    }
    hex::encode(b)
}

#[derive(Debug, thiserror::Error)]
#[error("needed {}, remaining {}", needed, remaining)]
pub struct RemainingError {
    pub needed: usize,
    pub remaining: usize,
}

#[derive(Debug)]
pub enum Typ {
    U8,
    U16Be,
    U16Le,
    U32Be,
    Array(usize),
    Take(usize),
    Tag(Vec<u8>),
}

pub trait BufParsing: Buf + Sized {
    fn read_u8(&mut self) -> Result<u8, Error> {
        self.ensure_remaining(1).map_err(|e| Error::TooShort {
            typ: Typ::U8,
            error: e,
            context: "todo",
        })?;
        Ok(self.get_u8())
    }

    fn read_be_u16(&mut self) -> Result<u16, Error> {
        self.ensure_remaining(2).map_err(|e| Error::TooShort {
            typ: Typ::U16Be,
            error: e,
            context: "todo",
        })?;
        Ok(self.get_u16())
    }

    fn read_le_u16(&mut self) -> Result<u16, Error> {
        self.ensure_remaining(2).map_err(|e| Error::TooShort {
            typ: Typ::U16Le,
            error: e,
            context: "todo",
        })?;
        Ok(self.get_u16_le())
    }

    fn read_be_u32(&mut self) -> Result<u32, Error> {
        self.ensure_remaining(4).map_err(|e| Error::TooShort {
            typ: Typ::U32Be,
            error: e,
            context: "todo",
        })?;
        Ok(self.get_u32())
    }

    fn read_array<const C: usize>(&mut self) -> Result<[u8; C], Error> {
        self.ensure_remaining(C).map_err(|e| Error::TooShort {
            typ: Typ::Array(C),
            error: e,
            context: "todo",
        })?;
        let mut arr = [0u8; C];
        self.copy_to_slice(&mut arr);
        Ok(arr)
    }

    fn read_take(&mut self, size: usize) -> Result<Bytes, Error> {
        self.ensure_remaining(size).map_err(|e| Error::TooShort {
            typ: Typ::Take(size),
            error: e,
            context: "todo",
        })?;
        Ok(self.copy_to_bytes(size))
    }

    fn rest(&mut self) -> Bytes {
        let len = self.remaining();
        self.copy_to_bytes(len)
    }

    fn ensure_remaining(&self, size: usize) -> Result<(), RemainingError> {
        if self.remaining() < size {
            return Err(RemainingError {
                needed: size,
                remaining: self.remaining(),
            });
        }

        Ok(())
    }

    fn read_tag(&mut self, tag: &[u8]) -> Result<(), Error> {
        self.ensure_remaining(tag.len())
            .map_err(|e| Error::TooShort {
                typ: Typ::Tag(tag.to_vec()),
                error: e,
                context: "todo",
            })?;
        let read = self.copy_to_bytes(tag.len());
        if tag != read {
            return Err(Error::TagMissmatch {
                context: "todo",
                expected: tag.to_vec(),
                found: read,
            });
        }
        Ok(())
    }
}

impl<B: Buf> BufParsing for B {}

//! Parsing functions to parse data using [Buf].

use bytes::{Buf, Bytes};
use snafu::{Backtrace, Snafu};

/// Parsing errors
#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("{}: reading {:?}", context, typ))]
    TooShort {
        typ: Typ,
        context: &'static str,
        #[snafu(backtrace)]
        source: RemainingError,
    },
    #[snafu(display("expected {}, found {}", debug_bytes(expected), debug_bytes(&found[..])))]
    TagMismatch {
        expected: Vec<u8>,
        found: Bytes,
        context: &'static str,
        backtrace: Option<Backtrace>,
    },
    #[snafu(transparent)]
    UnexpectedEof {
        source: std::io::Error,
        #[snafu(backtrace)]
        backtrace: Option<Backtrace>,
    },
}

impl Error {
    /// Returns true if the error indictates that the input was too short.
    pub fn is_incomplete(&self) -> bool {
        match self {
            Self::TooShort { .. } => true,
            Self::TagMismatch { .. } => false,
            Self::UnexpectedEof { .. } => true,
        }
    }
}

fn debug_bytes(b: &[u8]) -> String {
    if let Ok(s) = std::str::from_utf8(b) {
        return s.to_string();
    }
    hex::encode(b)
}

#[derive(Debug, Snafu)]
#[snafu(display("needed {}, remaining {}", needed, remaining))]
pub struct RemainingError {
    pub needed: usize,
    pub remaining: usize,
    backtrace: Option<Backtrace>,
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
            source: e,
            context: "todo",
        })?;
        Ok(self.get_u8())
    }

    fn read_le_u16(&mut self) -> Result<u16, Error> {
        self.ensure_remaining(2).map_err(|e| Error::TooShort {
            typ: Typ::U16Le,
            source: e,
            context: "todo",
        })?;
        Ok(self.get_u16_le())
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
                backtrace: snafu::GenerateImplicitData::generate(),
            });
        }

        Ok(())
    }
}

impl<B: Buf> BufParsing for B {}

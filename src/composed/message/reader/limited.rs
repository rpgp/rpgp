use std::io::{self, BufRead, Read};

use crate::util::FinalizingBufRead;

#[derive(Debug)]
pub enum LimitedReader<R: BufRead> {
    Fixed { reader: io::Take<R> },
    Indeterminate(R),
    Partial(io::Take<R>),
}

impl<R: FinalizingBufRead> FinalizingBufRead for LimitedReader<R> {
    fn is_done(&self) -> bool {
        match self {
            Self::Fixed { reader } => reader.limit() == 0,
            Self::Indeterminate(reader) => reader.is_done(),
            Self::Partial(reader) => reader.limit() == 0,
        }
    }
}

impl<R: BufRead> BufRead for LimitedReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        match self {
            Self::Fixed { ref mut reader, .. } => reader.fill_buf(),
            Self::Indeterminate(ref mut r) => r.fill_buf(),
            Self::Partial(ref mut r) => r.fill_buf(),
        }
    }

    fn consume(&mut self, amt: usize) {
        match self {
            Self::Fixed { reader } => {
                reader.consume(amt);
            }
            Self::Indeterminate(ref mut r) => r.consume(amt),
            Self::Partial(ref mut r) => r.consume(amt),
        }
    }
}

impl<R: BufRead> Read for LimitedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Fixed { reader } => reader.read(buf),
            Self::Indeterminate(ref mut r) => r.read(buf),
            Self::Partial(ref mut r) => r.read(buf),
        }
    }
}

impl<R: BufRead> LimitedReader<R> {
    pub fn fixed(limit: u64, reader: R) -> Self {
        let reader = reader.take(limit);
        Self::Fixed { reader }
    }

    pub fn into_inner(self) -> R {
        match self {
            Self::Fixed { reader, .. } => reader.into_inner(),
            Self::Indeterminate(source) => source,
            Self::Partial(source) => source.into_inner(),
        }
    }
    pub fn get_mut(&mut self) -> &mut R {
        match self {
            Self::Fixed { reader, .. } => reader.get_mut(),
            Self::Indeterminate(source) => source,
            Self::Partial(source) => source.get_mut(),
        }
    }
}

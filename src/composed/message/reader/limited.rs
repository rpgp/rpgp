use std::io::{self, BufRead, Read};

#[derive(derive_more::Debug)]
pub enum LimitedReader<R: BufRead> {
    Fixed(#[debug("Take<R>")] io::Take<R>),
    Indeterminate(#[debug("R")] R),
    Partial(#[debug("Take<R>")] io::Take<R>),
}

impl<R: BufRead> BufRead for LimitedReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        match self {
            Self::Fixed(ref mut r) => r.fill_buf(),
            Self::Indeterminate(ref mut r) => r.fill_buf(),
            Self::Partial(ref mut r) => r.fill_buf(),
        }
    }

    fn consume(&mut self, amt: usize) {
        match self {
            Self::Fixed(ref mut r) => r.consume(amt),
            Self::Indeterminate(ref mut r) => r.consume(amt),
            Self::Partial(ref mut r) => r.consume(amt),
        }
    }
}

impl<R: BufRead> Read for LimitedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Fixed(ref mut r) => r.read(buf),
            Self::Indeterminate(ref mut r) => r.read(buf),
            Self::Partial(ref mut r) => r.read(buf),
        }
    }
}

impl<R: BufRead> LimitedReader<R> {
    pub fn into_inner(self) -> R {
        match self {
            Self::Fixed(source) => source.into_inner(),
            Self::Indeterminate(source) => source,
            Self::Partial(source) => source.into_inner(),
        }
    }
}

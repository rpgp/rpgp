use std::io::{self, BufRead, Read};

#[derive(Debug)]
pub enum LimitedReader<R: BufRead> {
    Fixed {
        // Number of bytes we (still) expect to read from this Fixed
        expect_data: u32,
        reader: io::Take<R>,
    },
    Indeterminate(R),
    Partial(io::Take<R>),
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
            Self::Fixed { reader, .. } => {
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
            Self::Fixed {
                reader,
                expect_data,
            } => {
                let got = reader.read(buf)?;
                if got > *expect_data as usize {
                    // This should never happen: LimitedReader should never read more than expect_data
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "Got more data than expected",
                    ));
                }
                *expect_data -= u32::try_from(got).expect("checked, cannot be too large");
                Ok(got)
            }
            Self::Indeterminate(ref mut r) => r.read(buf),
            Self::Partial(ref mut r) => r.read(buf),
        }
    }
}

impl<R: BufRead> LimitedReader<R> {
    pub fn fixed(limit: u32, reader: R) -> Self {
        let reader = reader.take(limit as u64);
        Self::Fixed {
            reader,
            expect_data: limit,
        }
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

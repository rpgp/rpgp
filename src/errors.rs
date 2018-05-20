use std::{fmt, error};
use nom::{self, IResult};

pub type Result<T> = ::std::result::Result<T, Error>;


/// Error types
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Error {
    ParsingError(nom::ErrorKind),
    InvalidInput,
    Incomplete,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(error::Error::description(self))
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::ParsingError(_) => "failed to parse",
            Error::InvalidInput => "invalid input",
            Error::Incomplete => "incomplete input",
        }
    }

    #[inline]
    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::ParsingError(ref err) => Some(err),
            _ => None,
        }
    }
}

pub fn unwrap_iresult<I, O>(res: IResult<I, O>) -> Result<O> {
    match res {
        IResult::Done(_, res) => Ok(res),
        IResult::Error(err) => Err(Error::ParsingError(err)),
        IResult::Incomplete(_) => Err(Error::Incomplete),
    }
}

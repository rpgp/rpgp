use base64;
use nom;
use openssl::error::ErrorStack;

pub type Result<T> = ::std::result::Result<T, Error>;

// custom nom error types
pub const MPI_TOO_LONG: u32 = 1000;

/// Error types
#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "failed to parse {:?}", _0)]
    ParsingError(nom::ErrorKind),
    #[fail(display = "invalid input")]
    InvalidInput,
    #[fail(display = "incomplete input")]
    Incomplete,
    #[fail(display = "invalid armor wrappers")]
    InvalidArmorWrappers,
    #[fail(display = "invalid crc24 checksum")]
    InvalidChecksum,
    #[fail(display = "failed to decode base64 {:?}", _0)]
    Base64DecodeError(base64::DecodeError),
    #[fail(display = "requested data size is larger than the packet body")]
    RequestedSizeTooLarge,
    #[fail(display = "no valid key found")]
    NoKey,
    #[fail(display = "more than one key found")]
    MultipleKeys,
    #[fail(display = "openssl error: {:?}", _0)]
    OpenSSLError(ErrorStack),
    #[fail(display = "io error: {:?}", _0)]
    IOError(::std::io::Error),
    #[fail(display = "missing packets")]
    MissingPackets,
}

impl Error {
    pub fn as_code(&self) -> u32 {
        match self {
            Error::ParsingError(_) => 0,
            Error::InvalidInput => 1,
            Error::Incomplete => 2,
            Error::InvalidArmorWrappers => 3,
            Error::InvalidChecksum => 4,
            Error::Base64DecodeError(_) => 5,
            Error::RequestedSizeTooLarge => 6,
            Error::NoKey => 7,
            Error::MultipleKeys => 8,
            Error::OpenSSLError(_) => 9,
            Error::IOError(_) => 10,
            Error::MissingPackets => 11,
        }
    }
}

impl<'a> From<nom::Err<&'a [u8]>> for Error {
    fn from(err: nom::Err<&'a [u8]>) -> Error {
        Error::ParsingError(err.into_error_kind())
    }
}

impl<'a> From<Error> for nom::Err<&'a [u8]> {
    fn from(err: Error) -> nom::Err<&'a [u8]> {
        nom::Err::Error(nom::Context::Code(
            &b""[..],
            nom::ErrorKind::Custom(err.as_code()),
        ))
    }
}

impl<'a> From<nom::Err<&'a str>> for Error {
    fn from(err: nom::Err<&'a str>) -> Error {
        Error::ParsingError(err.into_error_kind())
    }
}

impl From<base64::DecodeError> for Error {
    fn from(err: base64::DecodeError) -> Error {
        Error::Base64DecodeError(err)
    }
}

impl From<ErrorStack> for Error {
    fn from(err: ErrorStack) -> Error {
        Error::OpenSSLError(err)
    }
}

impl From<::std::io::Error> for Error {
    fn from(err: ::std::io::Error) -> Error {
        Error::IOError(err)
    }
}

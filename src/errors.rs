use base64;
use nom;

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
}

impl<'a> From<nom::Err<&'a [u8]>> for Error {
    fn from(err: nom::Err<&'a [u8]>) -> Error {
        Error::ParsingError(err.into_error_kind())
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

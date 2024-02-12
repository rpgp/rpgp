use std::num::TryFromIntError;

use ed25519_dalek::SignatureError;
use nom::{
    error::{FromExternalError, ParseError},
    ErrorConvert,
};

pub type Result<T> = ::std::result::Result<T, Error>;

// custom nom error types
pub const MPI_TOO_LONG: u32 = 1000;

/// Error types
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to parse {0:?}")]
    ParsingError(nom::error::ErrorKind),
    #[error("invalid input")]
    InvalidInput,
    #[error("incomplete input: {0:?}")]
    Incomplete(nom::Needed),
    #[error("invalid armor wrappers")]
    InvalidArmorWrappers,
    #[error("invalid crc24 checksum")]
    InvalidChecksum,
    #[error("failed to decode base64 {0:?}")]
    Base64DecodeError(#[from] base64::DecodeError),
    #[error("requested data size is larger than the packet body")]
    RequestedSizeTooLarge,
    #[error("no matching packet found")]
    NoMatchingPacket,
    #[error("more than one matching packet was found")]
    TooManyPackets,
    #[error("rsa error: {0:?}")]
    RSAError(rsa::errors::Error),
    #[error("elliptic error: {0:?}")]
    EllipticCurve(#[from] elliptic_curve::Error),
    #[error("io error: {0:?}")]
    IOError(#[from] std::io::Error),
    #[error("missing packets")]
    MissingPackets,
    #[error("invalid key length")]
    InvalidKeyLength,
    #[error("block mode error")]
    BlockMode,
    #[error("missing key")]
    MissingKey,
    #[error("cfb: invalid key iv length")]
    CfbInvalidKeyIvLength,
    #[error("Not yet implemented: {0:?}")]
    Unimplemented(String),
    #[error("Unsupported: {0:?}")]
    Unsupported(String), // Signals packet versions and parameters we don't support, but can safely ignore
    #[error("{0:?}")]
    Message(String),
    #[error("Invalid Packet {0:?}")]
    PacketError(nom::error::ErrorKind),
    #[error("Incomplete Packet")]
    PacketIncomplete,
    #[error("Unpadding failed")]
    UnpadError,
    #[error("Padding failed")]
    PadError,
    #[error("Utf8 {0:?}")]
    Utf8Error(#[from] std::str::Utf8Error),
    #[error("ParseInt {0:?}")]
    ParseIntError(#[from] std::num::ParseIntError),
    #[error("Invalid Packet Content {0:?}")]
    InvalidPacketContent(Box<Error>),
    #[error("Signature {0:?}")]
    SignatureError(#[from] SignatureError),
    #[error("Modification Detection Code error")]
    MdcError,
    #[error("Invalid size conversion {0}")]
    TryFromInt(#[from] TryFromIntError),
}

impl Error {
    pub fn as_code(&self) -> u32 {
        match self {
            Error::ParsingError(_) => 0,
            Error::InvalidInput => 1,
            Error::Incomplete(_) => 2,
            Error::InvalidArmorWrappers => 3,
            Error::InvalidChecksum => 4,
            Error::Base64DecodeError(_) => 5,
            Error::RequestedSizeTooLarge => 6,
            Error::NoMatchingPacket => 7,
            Error::TooManyPackets => 8,
            Error::RSAError(_) => 9,
            Error::IOError(_) => 10,
            Error::MissingPackets => 11,
            Error::InvalidKeyLength => 12,
            Error::BlockMode => 13,
            Error::MissingKey => 14,
            Error::CfbInvalidKeyIvLength => 15,
            Error::Unimplemented(_) => 16,
            Error::Unsupported(_) => 17,
            Error::Message(_) => 18,
            Error::PacketError(_) => 19,
            Error::PacketIncomplete => 20,
            Error::UnpadError => 21,
            Error::PadError => 22,
            Error::Utf8Error(_) => 23,
            Error::ParseIntError(_) => 24,
            Error::InvalidPacketContent(_) => 25,
            Error::SignatureError(_) => 26,
            Error::MdcError => 27,
            Error::TryFromInt(_) => 28,
            Error::EllipticCurve(_) => 29,
        }
    }
}

pub(crate) type IResult<I, O, E = Error> = nom::IResult<I, O, E>;

impl<T> From<nom::error::Error<T>> for Error {
    fn from(err: nom::error::Error<T>) -> Self {
        Self::PacketError(err.code)
    }
}

impl<I> ParseError<I> for Error {
    fn from_error_kind(_input: I, kind: nom::error::ErrorKind) -> Self {
        Self::ParsingError(kind)
    }

    fn append(_input: I, _kind: nom::error::ErrorKind, other: Self) -> Self {
        other
    }
}

impl<I, E> FromExternalError<I, E> for Error {
    fn from_external_error(input: I, kind: nom::error::ErrorKind, e: E) -> Self {
        nom::error::Error::from_external_error(input, kind, e).into()
    }
}

impl From<Error> for nom::Err<Error> {
    fn from(err: Error) -> Self {
        Self::Error(err)
    }
}

impl ErrorConvert<Self> for Error {
    fn convert(self) -> Self {
        self
    }
}

impl From<nom::Err<Error>> for Error {
    fn from(err: nom::Err<Error>) -> Self {
        match err {
            nom::Err::Incomplete(err) => Self::Incomplete(err),
            nom::Err::Error(err) | nom::Err::Failure(err) => err,
        }
    }
}

impl<T> From<nom::Err<nom::error::Error<T>>> for Error {
    fn from(err: nom::Err<nom::error::Error<T>>) -> Error {
        match err {
            nom::Err::Incomplete(err) => Self::Incomplete(err),
            nom::Err::Error(err) | nom::Err::Failure(err) => Self::ParsingError(err.code),
        }
    }
}

impl From<rsa::errors::Error> for Error {
    fn from(err: rsa::errors::Error) -> Error {
        Error::RSAError(err)
    }
}

impl From<cipher::InvalidLength> for Error {
    fn from(_: cipher::InvalidLength) -> Error {
        Error::CfbInvalidKeyIvLength
    }
}

impl From<block_padding::UnpadError> for Error {
    fn from(_: block_padding::UnpadError) -> Error {
        Error::UnpadError
    }
}

impl From<String> for Error {
    fn from(err: String) -> Error {
        Error::Message(err)
    }
}

impl From<derive_builder::UninitializedFieldError> for Error {
    fn from(err: derive_builder::UninitializedFieldError) -> Error {
        Error::Message(err.to_string())
    }
}

#[macro_export]
macro_rules! unimplemented_err {
    ($e:expr) => {
        return Err($crate::errors::Error::Unimplemented($e.to_string()))
    };
    ($fmt:expr, $($arg:tt)+) => {
        return Err($crate::errors::Error::Unimplemented(format!($fmt, $($arg)+)))
    };
}

#[macro_export]
macro_rules! unsupported_err {
    ($e:expr) => {
        return Err($crate::errors::Error::Unsupported($e.to_string()))
    };
    ($fmt:expr, $($arg:tt)+) => {
        return Err($crate::errors::Error::Unsupported(format!($fmt, $($arg)+)))
    };
}

#[macro_export]
macro_rules! bail {
    ($e:expr) => {
        return Err($crate::errors::Error::Message($e.to_string()))
    };
    ($fmt:expr, $($arg:tt)+) => {
        return Err($crate::errors::Error::Message(format!($fmt, $($arg)+)))
    };
}

#[macro_export]
macro_rules! format_err {
    ($e:expr) => {
        $crate::errors::Error::Message($e.to_string())
    };
    ($fmt:expr, $($arg:tt)+) => {
        $crate::errors::Error::Message(format!($fmt, $($arg)+))
    };
}

#[macro_export(local_inner_macros)]
macro_rules! ensure {
    ($cond:expr, $e:expr) => {
        if !($cond) {
            bail!($e);
        }
    };
    ($cond:expr, $fmt:expr, $($arg:tt)+) => {
        if !($cond) {
            bail!($fmt, $($arg)+);
        }
    };
}

#[macro_export]
macro_rules! ensure_eq {
    ($left:expr, $right:expr) => ({
        match (&$left, &$right) {
            (left_val, right_val) => {
                if !(*left_val == *right_val) {
                    bail!(r#"assertion failed: `(left == right)`
  left: `{:?}`,
 right: `{:?}`"#, left_val, right_val)
                }
            }
        }
    });
    ($left:expr, $right:expr,) => ({
        ensure_eq!($left, $right)
    });
    ($left:expr, $right:expr, $($arg:tt)+) => ({
        match (&($left), &($right)) {
            (left_val, right_val) => {
                if !(*left_val == *right_val) {
                    bail!(r#"assertion failed: `(left == right)`
  left: `{:?}`,
 right: `{:?}`: {}"#, left_val, right_val,
                           format_args!($($arg)+))
                }
            }
        }
    });
}

#[macro_export]
macro_rules! err_opt {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(err) => return Some(Err(err)),
        }
    };
}

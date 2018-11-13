use aes::block_cipher_trait;
use base64;
use block_modes;
use block_padding;
use cfb_mode;
use nom;
use rsa;

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
    #[fail(display = "rsa error: {:?}", _0)]
    RSAError(rsa::errors::Error),
    #[fail(display = "io error: {:?}", _0)]
    IOError(::std::io::Error),
    #[fail(display = "missing packets")]
    MissingPackets,
    #[fail(display = "invalid key length")]
    InvalidKeyLength,
    #[fail(display = "block mode error")]
    BlockMode,
    #[fail(display = "missing key")]
    MissingKey,
    #[fail(display = "cfb: invalid key iv length")]
    CfbInvalidKeyIvLength,
    #[fail(display = "Not yet implemented: {:?}", _0)]
    Unimplemented(String),
    #[fail(display = "Unsupported: {:?}", _0)]
    Unsupported(String),
    #[fail(display = "{:?}", _0)]
    Message(String),
    #[fail(display = "Invalid Packet {:?}", _0)]
    PacketError(nom::ErrorKind),
    #[fail(display = "Incomplete Packet")]
    PacketIncomplete,
    #[fail(display = "Unpadding failed")]
    UnpadError,
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

impl From<rsa::errors::Error> for Error {
    fn from(err: rsa::errors::Error) -> Error {
        Error::RSAError(err)
    }
}

impl From<::std::io::Error> for Error {
    fn from(err: ::std::io::Error) -> Error {
        Error::IOError(err)
    }
}

impl From<block_cipher_trait::InvalidKeyLength> for Error {
    fn from(_: block_cipher_trait::InvalidKeyLength) -> Error {
        Error::InvalidKeyLength
    }
}

impl From<block_modes::BlockModeError> for Error {
    fn from(_: block_modes::BlockModeError) -> Error {
        Error::BlockMode
    }
}

impl From<cfb_mode::stream_cipher::InvalidKeyNonceLength> for Error {
    fn from(_: cfb_mode::stream_cipher::InvalidKeyNonceLength) -> Error {
        Error::CfbInvalidKeyIvLength
    }
}

impl From<block_padding::UnpadError> for Error {
    fn from(_: block_padding::UnpadError) -> Error {
        Error::UnpadError
    }
}

#[macro_export]
macro_rules! unimplemented_err {
    ($e:expr) => {
        return Err($crate::errors::Error::Unimplemented($e.to_string()));
    };
    ($fmt:expr, $($arg:tt)+) => {
        return Err($crate::errors::Error::Unimplemented(format!($fmt, $($arg)+)));
    };
}

#[macro_export]
macro_rules! unsupported_err {
    ($e:expr) => {
        return Err($crate::errors::Error::Unsupported($e.to_string()));
    };
    ($fmt:expr, $($arg:tt)+) => {
        return Err($crate::errors::Error::Unsupported(format!($fmt, $($arg)+)));
    };
}

#[macro_export]
macro_rules! bail {
    ($e:expr) => {
        return Err($crate::errors::Error::Message($e.to_string()));
    };
    ($fmt:expr, $($arg:tt)+) => {
        return Err($crate::errors::Error::Message(format!($fmt, $($arg)+)));
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

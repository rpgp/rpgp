use ed25519_dalek::SignatureError;

pub type Result<T> = ::std::result::Result<T, Error>;

// custom nom error types
pub const MPI_TOO_LONG: u32 = 1000;

/// Error types
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to parse {0:?}")]
    ParsingError(nom::ErrorKind),
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
    Unsupported(String),
    #[error("{0:?}")]
    Message(String),
    #[error("Invalid Packet {0:?}")]
    PacketError(nom::ErrorKind),
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
    #[error("Ed25519 {0:?}")]
    Ed25519SignatureError(#[from] SignatureError),
    #[error("Modification Detection Code error")]
    MdcError,
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
            Error::Ed25519SignatureError(_) => 26,
            Error::MdcError => 27,
        }
    }
}

impl<'a> From<nom::Err<&'a [u8]>> for Error {
    fn from(err: nom::Err<&'a [u8]>) -> Error {
        match err {
            nom::Err::Incomplete(n) => Error::Incomplete(n),
            _ => Error::ParsingError(err.into_error_kind()),
        }
    }
}

impl<'a> From<nom::Err<nom::types::CompleteStr<'a>>> for Error {
    fn from(err: nom::Err<nom::types::CompleteStr<'a>>) -> Error {
        match err {
            nom::Err::Incomplete(n) => Error::Incomplete(n),
            _ => Error::ParsingError(err.into_error_kind()),
        }
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

impl From<rsa::errors::Error> for Error {
    fn from(err: rsa::errors::Error) -> Error {
        Error::RSAError(err)
    }
}

impl From<block_modes::BlockModeError> for Error {
    fn from(_: block_modes::BlockModeError) -> Error {
        Error::BlockMode
    }
}

impl From<cipher::stream::InvalidKeyNonceLength> for Error {
    fn from(_: cipher::stream::InvalidKeyNonceLength) -> Error {
        Error::CfbInvalidKeyIvLength
    }
}

impl From<block_padding::UnpadError> for Error {
    fn from(_: block_padding::UnpadError) -> Error {
        Error::UnpadError
    }
}
impl From<block_padding::PadError> for Error {
    fn from(_: block_padding::PadError) -> Error {
        Error::PadError
    }
}

impl From<String> for Error {
    fn from(err: String) -> Error {
        Error::Message(err)
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

#[macro_export]
macro_rules! format_err {
    ($e:expr) => {
        $crate::errors::Error::Message($e.to_string());
    };
    ($fmt:expr, $($arg:tt)+) => {
        $crate::errors::Error::Message(format!($fmt, $($arg)+));
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

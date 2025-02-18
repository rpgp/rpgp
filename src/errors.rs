use std::num::TryFromIntError;

use ed25519_dalek::SignatureError;
use snafu::{Backtrace, Snafu};

pub type Result<T, E = Error> = ::std::result::Result<T, E>;

// custom nom error types
pub const MPI_TOO_LONG: u32 = 1000;

pub use crate::parsing::{Error as ParsingError, RemainingError};

/// Error types
#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("invalid input"))]
    InvalidInput,
    #[snafu(display("invalid armor wrappers"))]
    InvalidArmorWrappers,
    #[snafu(display("invalid crc24 checksum"))]
    InvalidChecksum,
    #[snafu(transparent)]
    Base64Decode { source: base64::DecodeError },
    #[snafu(display("requested data size is larger than the packet body"))]
    RequestedSizeTooLarge,
    #[snafu(display("no matching packet found"))]
    NoMatchingPacket,
    #[snafu(display("more than one matching packet was found"))]
    TooManyPackets,
    #[snafu(transparent)]
    RSAError { source: rsa::errors::Error },
    #[snafu(transparent)]
    EllipticCurve { source: elliptic_curve::Error },
    #[snafu(transparent)]
    IO {
        source: std::io::Error,
        backtrace: Backtrace,
    },
    #[snafu(display("invalid key length"))]
    InvalidKeyLength,
    #[snafu(display("block mode error"))]
    BlockMode,
    #[snafu(display("missing key"))]
    MissingKey,
    #[snafu(display("cfb: invalid key iv length"))]
    CfbInvalidKeyIvLength,
    #[snafu(display("Not yet implemented: {message}"))]
    Unimplemented { message: String },
    /// Signals packet versions and parameters we don't support, but can safely ignore
    #[snafu(display("Unsupported: {message}"))]
    Unsupported { message: String },
    #[snafu(display("{message}"))]
    Message { message: String },
    #[snafu(display("Invalid Packet {kind:?}"))]
    PacketError { kind: nom::error::ErrorKind },
    #[snafu(display("Unpadding failed"))]
    UnpadError,
    #[snafu(display("Padding failed"))]
    PadError,
    #[snafu(transparent)]
    Utf8Error { source: std::str::Utf8Error },
    #[snafu(transparent)]
    ParseIntError { source: std::num::ParseIntError },
    #[snafu(display("Invalid Packet Content {source:?}"))]
    InvalidPacketContent { source: Box<Error> },
    #[snafu(transparent)]
    SignatureError { source: SignatureError },
    #[snafu(display("Modification Detection Code error"))]
    MdcError,
    #[snafu(transparent)]
    TryFromInt { source: TryFromIntError },
    #[snafu(display("GCM"))]
    Gcm,
    #[snafu(display("EAX"))]
    Eax,
    #[snafu(display("OCB"))]
    Ocb,
    #[snafu(display("SHA1 hash collision detected"))]
    Sha1HashCollision,
    #[snafu(transparent)]
    AesKek { source: aes_kw::Error },
    #[snafu(transparent)]
    PacketParsing { source: ParsingError },
    #[snafu(display("packet is incomplete"))]
    PacketIncomplete { source: ParsingError },
    #[snafu(transparent)]
    Argon2 { source: argon2::Error },
}

impl<T> From<nom::error::Error<T>> for Error {
    fn from(err: nom::error::Error<T>) -> Self {
        Self::PacketError { kind: err.code }
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
        Error::Message { message: err }
    }
}

impl From<derive_builder::UninitializedFieldError> for Error {
    fn from(err: derive_builder::UninitializedFieldError) -> Error {
        Error::Message {
            message: err.to_string(),
        }
    }
}

#[macro_export]
macro_rules! unimplemented_err {
    ($e:expr) => {
        return Err($crate::errors::Error::Unimplemented { message: $e.to_string() })
    };
    ($fmt:expr, $($arg:tt)+) => {
        return Err($crate::errors::Error::Unimplemented { message: format!($fmt, $($arg)+)})
    };
}

#[macro_export]
macro_rules! unsupported_err {
    ($e:expr) => {
        return Err($crate::errors::Error::Unsupported { message: $e.to_string()})
    };
    ($fmt:expr, $($arg:tt)+) => {
        return Err($crate::errors::Error::Unsupported { message: format!($fmt, $($arg)+) })
    };
}

#[macro_export]
macro_rules! bail {
    ($e:expr) => {
        return Err($crate::errors::Error::Message { message: $e.to_string() })
    };
    ($fmt:expr, $($arg:tt)+) => {
        return Err($crate::errors::Error::Message { message: format!($fmt, $($arg)+) })
    };
}

#[macro_export]
macro_rules! format_err {
    ($e:expr) => {
        $crate::errors::Error::Message { message: $e.to_string() }
    };
    ($fmt:expr, $($arg:tt)+) => {
        $crate::errors::Error::Message { message: format!($fmt, $($arg)+) }
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

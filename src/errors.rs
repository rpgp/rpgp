use std::num::TryFromIntError;

use ed25519_dalek::SignatureError;

pub type Result<T, E = Error> = ::std::result::Result<T, E>;

// custom nom error types
pub const MPI_TOO_LONG: u32 = 1000;

pub use crate::parsing::{Error as ParsingError, RemainingError};

/// Error types
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid input")]
    InvalidInput,
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
    RSAError(#[from] rsa::errors::Error),
    #[error("elliptic error: {0:?}")]
    EllipticCurve(#[from] elliptic_curve::Error),
    #[error("io error: {0:?}")]
    IOError(#[from] std::io::Error),
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
    /// Signals packet versions and parameters we don't support, but can safely ignore
    #[error("Unsupported: {0:?}")]
    Unsupported(String),
    #[error("{0:?}")]
    Message(String),
    #[error("Invalid Packet {0:?}")]
    PacketError(nom::error::ErrorKind),
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
    #[error("GCM")]
    Gcm,
    #[error("EAX")]
    Eax,
    #[error("OCB")]
    Ocb,
    #[error("SHA1 hash collision detected")]
    Sha1HashCollision,
    #[error("AES Key Wrap error {0}")]
    AesKek(#[from] aes_kw::Error),
    #[error("failed to parse packet {0:?}")]
    PacketParsing(#[from] ParsingError),
    #[error("packet is incomplete: {0:?}")]
    PacketIncomplete(ParsingError),
}

impl<T> From<nom::error::Error<T>> for Error {
    fn from(err: nom::error::Error<T>) -> Self {
        Self::PacketError(err.code)
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

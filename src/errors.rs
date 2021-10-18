use ed25519_dalek::SignatureError;

pub type Result<T> = ::std::result::Result<T, Error>;

/// Error types
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to parse {0:?}")]
    ParsingErrorNom(nom::error::ErrorKind),
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
    #[error("Ed25519 {0:?}")]
    Ed25519SignatureError(#[from] SignatureError),
    #[error("Modification Detection Code error")]
    MdcError,
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

impl From<cipher::errors::InvalidLength> for Error {
    fn from(_: cipher::errors::InvalidLength) -> Error {
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

impl From<(&[u8], nom::error::ErrorKind)> for Error {
    fn from(err: (&[u8], nom::error::ErrorKind)) -> Error {
        Error::ParsingErrorNom(err.1)
    }
}

impl From<nom::Err<nom::error::Error<&[u8]>>> for Error {
    fn from(err: nom::Err<nom::error::Error<&[u8]>>) -> Error {
        match err {
            nom::Err::Incomplete(n) => Error::Incomplete(n),
            nom::Err::Error(e) => Error::ParsingErrorNom(e.code),
            nom::Err::Failure(e) => Error::ParsingErrorNom(e.code),
        }
    }
}

impl From<nom::Err<(&[u8], nom::error::ErrorKind)>> for Error {
    fn from(err: nom::Err<(&[u8], nom::error::ErrorKind)>) -> Error {
        match err {
            nom::Err::Incomplete(n) => Error::Incomplete(n),
            nom::Err::Error((_, e)) => Error::ParsingErrorNom(e),
            nom::Err::Failure((_, e)) => Error::ParsingErrorNom(e),
        }
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

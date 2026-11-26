use std::{fmt, num::NonZero};

use byteorder::BigEndian;

use crate::ser::Serialize;

/// Expiration duration in seconds
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Default)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum ExpirationDuration {
    /// No expiration, represented as 0.
    #[default]
    NoExpiration,

    /// Non-zero expiration duration
    Expiring {
        /// Duration in seconds.
        duration: NonZero<u32>,
    },
}

impl fmt::Debug for ExpirationDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoExpiration => write!(f, "ExpirationDuration::NoExpiration"),
            Self::Expiring { duration } => {
                let time = std::time::Duration::from_secs(duration.get().into());
                write!(f, "ExpirationDuration({time:?})")
            }
        }
    }
}

impl TryFrom<std::time::Duration> for ExpirationDuration {
    type Error = ExpirationDurationError;

    fn try_from(duration: std::time::Duration) -> Result<Self, Self::Error> {
        let val: u32 = duration
            .as_secs()
            .try_into()
            .map_err(|_| TooFarIntoTheFutureSnafu.build())?;

        match NonZero::<u32>::new(val) {
            None => Err(ExpirationDurationError::Zero),
            Some(duration) => Ok(Self::Expiring { duration }),
        }
    }
}

/// Error when trying to convert a [`std::time::Duration`] into a [`ExpirationDuration`].
#[derive(Debug, snafu::Snafu)]
pub enum ExpirationDurationError {
    #[snafu(display("duration is more than u32::MAX seconds into the future"))]
    TooFarIntoTheFuture,
    #[snafu(display("Expiration duration cannot be zero"))]
    Zero,
}

impl ExpirationDuration {
    /// Returns the number of seconds.
    pub const fn as_secs(self) -> Option<u32> {
        match self {
            Self::NoExpiration => None,
            Self::Expiring { duration } => Some(duration.get()),
        }
    }

    /// Creates a new [`ExpirationDuration`] from seconds.
    pub const fn from_secs(duration: NonZero<u32>) -> Self {
        Self::Expiring { duration }
    }
}

impl Serialize for ExpirationDuration {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> crate::errors::Result<()> {
        use byteorder::WriteBytesExt;
        match self {
            Self::NoExpiration => writer.write_u32::<BigEndian>(0)?,
            Self::Expiring { duration } => writer.write_u32::<BigEndian>(duration.get())?,
        };
        Ok(())
    }

    fn write_len(&self) -> usize {
        4
    }
}

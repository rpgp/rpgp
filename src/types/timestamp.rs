use std::{
    fmt,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use byteorder::BigEndian;

use crate::ser::Serialize;

/// Timestamp that refers to a moment in time after the [`UNIX_EPOCH`].
///
/// Stored in seconds precision.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Default)]
pub struct Timestamp(u32);

impl fmt::Debug for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let time: SystemTime = (*self).into();
        write!(f, "Timestamp({:?})", time)
    }
}

impl From<Timestamp> for SystemTime {
    fn from(value: Timestamp) -> Self {
        UNIX_EPOCH + Duration::from_secs(u64::from(value.0))
    }
}

impl TryFrom<SystemTime> for Timestamp {
    type Error = TimestampError;

    fn try_from(value: SystemTime) -> Result<Self, Self::Error> {
        let duration = value
            .duration_since(UNIX_EPOCH)
            .map_err(|_| TooFarBackSnafu.build())?;
        let val: u32 = duration
            .as_secs()
            .try_into()
            .map_err(|_| TooFarIntoTheFutureSnafu.build())?;
        Ok(Self(val))
    }
}

/// Error when trying to convert a [`SystemTime`] into a [`Timestamp`].
#[derive(Debug, snafu::Snafu)]
pub enum TimestampError {
    #[snafu(display("time was before 1970-01-01 00:00:00"))]
    TooFarBack,
    #[snafu(display("time is more than u32::MAX seconds into the future"))]
    TooFarIntoTheFuture,
}

impl Timestamp {
    /// Returns the current timestamp.
    pub fn now() -> Self {
        SystemTime::now()
            .try_into()
            .expect("now is too far into the future")
    }

    /// Returns the number of seconds (ignoring leaps) since the [`UNIX_EPOCH`].
    pub fn as_secs(self) -> u32 {
        self.0
    }

    /// Creates a new [`Timestamp`] from seconds since the [`UNIX_EPOCH`].
    pub fn from_secs(secs: u32) -> Self {
        Self(secs)
    }
}

impl Serialize for Timestamp {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> crate::errors::Result<()> {
        use byteorder::WriteBytesExt;
        writer.write_u32::<BigEndian>(self.0)?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        4
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    impl Arbitrary for Timestamp {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            any::<u32>().prop_map(Timestamp::from_secs).boxed()
        }
    }
}

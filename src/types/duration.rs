use std::fmt;

use byteorder::BigEndian;

use crate::ser::Serialize;

/// Duration in seconds
///
/// This type is related to an OpenPGP [`Timestamp`](crate::types::Timestamp)
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Default)]
pub struct Duration(u32);

impl fmt::Debug for Duration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let time: std::time::Duration = (*self).into();
        write!(f, "Duration({:?})", time)
    }
}

impl From<Duration> for std::time::Duration {
    fn from(value: Duration) -> Self {
        std::time::Duration::from_secs(u64::from(value.0))
    }
}

impl TryFrom<std::time::Duration> for Duration {
    type Error = DurationError;

    fn try_from(duration: std::time::Duration) -> Result<Self, Self::Error> {
        let val: u32 = duration
            .as_secs()
            .try_into()
            .map_err(|_| TooFarIntoTheFutureSnafu.build())?;
        Ok(Self(val))
    }
}

/// Error when trying to convert a [`std::time::Duration`] into a [`Duration`].
#[derive(Debug, snafu::Snafu)]
pub enum DurationError {
    #[snafu(display("duration is more than u32::MAX seconds into the future"))]
    TooFarIntoTheFuture,
}

impl Duration {
    /// Returns the number of seconds.
    pub fn as_secs(self) -> u32 {
        self.0
    }

    /// Creates a new [`Duration`] from seconds.
    pub fn from_secs(secs: u32) -> Self {
        Self(secs)
    }
}

impl Serialize for Duration {
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

    impl Arbitrary for Duration {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            any::<u32>().prop_map(Duration::from_secs).boxed()
        }
    }
}

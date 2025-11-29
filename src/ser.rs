//! # Serialize trait module

use std::{
    io,
    time::{Duration, SystemTime},
};

use crate::errors::Result;

pub trait Serialize {
    fn to_writer<W: io::Write>(&self, _: &mut W) -> Result<()>;
    fn write_len(&self) -> usize;

    fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(self.write_len());
        self.to_writer(&mut buf)?;

        Ok(buf)
    }
}

impl<T: Serialize> Serialize for &T {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        (*self).to_writer(writer)
    }
    fn write_len(&self) -> usize {
        (*self).write_len()
    }
}

impl<T: Serialize> Serialize for &[T] {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        for x in self.iter() {
            (*x).to_writer(writer)?;
        }
        Ok(())
    }

    fn write_len(&self) -> usize {
        self.iter().map(|w| w.write_len()).sum()
    }
}

impl<T: Serialize> Serialize for Vec<T> {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        for x in self.iter() {
            (*x).to_writer(writer)?;
        }
        Ok(())
    }

    fn write_len(&self) -> usize {
        self.iter().map(|w| w.write_len()).sum()
    }
}

/// Convert expiration time "Duration" data to OpenPGP u32 format.
/// Use u32:MAX on overflow.
pub(crate) fn duration_to_u32(d: &Duration) -> u32 {
    u32::try_from(d.as_secs()).unwrap_or(u32::MAX)
}

pub(crate) fn time_to_u32(t: &SystemTime) -> u32 {
    let d = t.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
    duration_to_u32(&d)
}

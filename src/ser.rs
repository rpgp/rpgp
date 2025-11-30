//! # Serialize trait module

use std::io;

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

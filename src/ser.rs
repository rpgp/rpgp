use std::io;

use crate::errors::Result;

pub trait Serialize {
    fn to_writer<W: io::Write>(&self, _: &mut W) -> Result<()>;

    fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        self.to_writer(&mut buf)?;

        Ok(buf)
    }
}

impl<'a, T: Serialize> Serialize for &'a T {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        (*self).to_writer(writer)
    }
}

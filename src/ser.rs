use std::io;

use errors::Result;

pub trait Serialize {
    fn to_writer<W: io::Write>(&self, &mut W) -> Result<()>;
}

impl<'a, T: Serialize> Serialize for &'a T {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        (*self).to_writer(writer)
    }
}

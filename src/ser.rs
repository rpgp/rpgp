use std::io;

use errors::Result;

pub trait Serialize {
    fn to_writer<W: io::Write>(&self, &mut W) -> Result<()>;
}

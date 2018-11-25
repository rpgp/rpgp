use std::io;

use errors::Result;
use packet::signature::types::Signature;
use ser::Serialize;

impl Serialize for Signature {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        unimplemented!();
    }
}

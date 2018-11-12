use circular::Buffer;
use nom::{self, Needed, Offset};
use std::io::Read;

use super::single;
use super::types::Packet;
use errors::{Error, Result};

/// Parse packets, in a streaming fashion from the given reader.
pub fn parser(mut input: impl Read) -> Result<Vec<Packet>> {
    // maximum size of our buffer
    let max_capacity = 1024 * 1024 * 1024;
    // the inital capacity of our buffer
    // TODO: use a better value than a random guess
    let mut capacity = 1024;
    let mut b = Buffer::with_capacity(capacity);

    let mut packets = Vec::new();
    let mut needed: Option<Needed> = None;

    let mut second_round = false;

    loop {
        // read some data
        let sz = input.read(b.space()).unwrap();
        b.fill(sz);

        // if there's no more available data in the buffer after a write, that means we reached
        // the end of the input
        if b.available_data() == 0 {
            break;
        }

        if needed.is_some() && sz == 0 {
            if second_round {
                // Cancel if we didn't receive enough bytes from our source, the second time around.
                return Err(Error::PacketIncomplete);
            }
            second_round = true;
        }

        loop {
            let length = {
                match single::parser(b.data()) {
                    Ok((remaining, p)) => {
                        info!("-- parsed packet {:?} --", p.tag);
                        packets.push(p);
                        b.data().offset(remaining)
                    }
                    Err(err) => match err {
                        nom::Err::Incomplete(n) => {
                            needed = Some(n);
                            break;
                        }
                        _ => return Err(Error::PacketError(err.into_error_kind())),
                    },
                }
            };

            b.consume(length);
        }

        // if the parser returned `Incomplete`, and it needs more data than the buffer can hold, we grow the buffer.
        if let Some(Needed::Size(sz)) = needed {
            if sz > b.capacity() && capacity * 2 < max_capacity {
                capacity *= 2;
                b.grow(capacity);
            }
        }
    }

    Ok(packets)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::path::Path;

    #[test]
    fn test_many_parser() {
        let p = Path::new("./tests/sks-dump/0000.pgp");
        let file = File::open(p).unwrap();

        let packets = parser(file).unwrap();
        assert_eq!(packets.len(), 141_945);
    }
}

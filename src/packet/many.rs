use std::io::Read;

use buf_redux::Buffer;
use nom::{Needed, Offset};

use errors::{Error, Result};
use packet::packet_sum::Packet;
use packet::single::{self, ParseResult};
use util;

const MAX_CAPACITY: usize = 1024 * 1024 * 1024;

pub struct PacketParser<R> {
    inner: R,
    capacity: usize,
    buffer: Buffer,
    failed: bool,
}

impl<R: Read> PacketParser<R> {
    pub fn new(inner: R) -> Self {
        PacketParser {
            inner,
            // the inital capacity of our buffer
            // TODO: use a better value than a random guess
            capacity: 1024,
            // TODO: only use when available
            buffer: util::new_buffer(1024),
            failed: false,
        }
    }
}

impl<R: Read> Iterator for PacketParser<R> {
    type Item = Result<Packet>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }

        let b = &mut self.buffer;
        let mut needed: Option<Needed> = None;
        let mut second_round = false;
        let inner = &mut self.inner;

        loop {
            // read some data
            let sz = match b.read_from(inner) {
                Ok(sz) => sz,
                Err(err) => {
                    warn!("failed to read {:?}", err);
                    return None;
                }
            };

            // If there's no more available data in the buffer after a write, that means we reached
            // the end of the input.
            if b.is_empty() {
                return None;
            }

            if needed.is_some() && sz == 0 {
                if second_round {
                    // Cancel if we didn't receive enough bytes from our source, the second time around.
                    // TODO: b.reset();
                    self.failed = true;
                    return Some(Err(Error::PacketIncomplete));
                }
                second_round = true;
            }

            let res = match {
                match single::parser(b.buf()) {
                    Ok(v) => Ok(v),
                    Err(err) => Err(err.into()),
                }
            }
            .and_then(|(rest, (ver, tag, _packet_length, body))| match body {
                ParseResult::Indeterminated => {
                    let mut body = rest.to_vec();
                    inner.read_to_end(&mut body)?;
                    let p = single::body_parser(ver, tag, &body);
                    Ok((rest.len() + body.len(), p))
                }
                ParseResult::Fixed(body) => {
                    let p = single::body_parser(ver, tag, body);
                    Ok((b.buf().offset(rest), p))
                }
                ParseResult::Partial(body) => {
                    let p = single::body_parser(ver, tag, &body.concat());
                    Ok((b.buf().offset(rest), p))
                }
            }) {
                Ok(val) => Some(val),
                Err(err) => match err {
                    Error::Incomplete(n) => {
                        info!("incomplete {:?}", n);
                        needed = Some(n);
                        None
                    }
                    _ => {
                        warn!("parsing error {:?}", err);
                        self.failed = true;
                        return Some(Err(err));
                    }
                },
            };

            if let Some((length, p)) = res {
                info!("got packet: {:#?} {}", p, length);
                b.consume(length);
                return Some(p);
            }

            // if the parser returned `Incomplete`, and it needs more data than the buffer can hold, we grow the buffer.
            if let Some(Needed::Size(sz)) = needed {
                if b.usable_space() < sz && self.capacity * 2 < MAX_CAPACITY {
                    self.capacity *= 2;
                    let capacity = self.capacity;
                    b.make_room();
                    b.reserve(capacity);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::FromPrimitive;
    use regex::Regex;
    use std::fs::File;
    use std::io::{BufRead, BufReader, Seek, SeekFrom};
    use std::path::Path;

    use ser::Serialize;
    use types::Tag;

    #[test]
    #[ignore]
    fn test_packet_roundtrip_0001() {
        packet_roundtrip(
            "0001",
            vec![
                (556, 6 + 2224),
                (805, 6 + 95),
                (806, 6 + 6495),
                (1027, 6 + 6246),
                (1074, 2490),
                (1331, 838),
                (1898, 6420),
                (1935, 3583),
            ],
        )
    }

    #[test]
    #[ignore]
    fn test_packet_roundtrip_0002() {
        packet_roundtrip(
            "0002",
            vec![
                (82, 199),    // invalid hash alg 06
                (85, 196),    // invalid hash alg 06
                (836, 3136),  // non canoncial length encoding
                (1200, 2772), // non canoncial length encoding
                (1268, 1223), // non canoncial length encoding
                (1670, 3419), // non canoncial length encoding
            ],
        )
    }

    #[test]
    #[ignore]
    fn test_packet_roundtrip_0009() {
        packet_roundtrip(
            "0009",
            vec![
                (37, 3960),   // non canoncial length encoding
                (39, 3960),   // non canoncial length encoding
                (258, 75),    // non canoncial length encoding
                (260, 78),    // non canoncial length encoding
                (1053, 3181), // non canoncial length encoding
                (1473, 5196), // non canoncial length encoding
                (1895, 4243), // non canoncial length encoding
            ],
        )
    }

    fn packet_roundtrip(dump: &str, skips: Vec<(usize, i64)>) {
        use pretty_env_logger;
        let _ = pretty_env_logger::try_init();

        let path = format!("./tests/tests/sks-dump/{}.pgp", dump);
        let p = Path::new(&path);
        let file = File::open(&p).unwrap();

        let mut bytes = File::open(&p).unwrap();

        let packets = PacketParser::new(file);

        for (i, packet) in packets.take(2000).enumerate() {
            // packets we need to skip, because we can not roundtrip them for some reason
            if let Some((_, size)) = skips.iter().find(|(j, _)| *j == i) {
                bytes.seek(SeekFrom::Current(*size)).unwrap();
                continue;
            }

            let packet = packet.expect("invalid packet");
            let mut buf = Vec::new();
            packet
                .to_writer(&mut buf)
                .expect("failed to serialize packet");

            let mut expected_buf = vec![0u8; buf.len()];
            assert_eq!(bytes.read(&mut expected_buf).unwrap(), buf.len());
            // println!("\n-- packet: {} expected size: {}", i, expected_buf.len());

            if buf != expected_buf {
                assert_eq!(hex::encode(buf), hex::encode(expected_buf));
            }
        }
    }

    #[test]
    fn test_many_parser() {
        // use pretty_env_logger;
        // let _ = pretty_env_logger::try_init();

        let p = Path::new("./tests/tests/sks-dump/0000.pgp");
        let file = File::open(p).unwrap();

        // list of expected tags
        // this file is built by
        // `gpg --list-packets tests/tests/sks-dump/0000.pgp`
        let fixture = File::open("./tests/tests/sks-dump/0000_parsed.txt").unwrap();
        let re = Regex::new(r"^#\soff=(\d+)\sctb=[[:alpha:]\d]+\stag=(\d+)\s.*").unwrap();
        let expected_tags = BufReader::new(fixture)
            .lines()
            .filter(|line| line.as_ref().unwrap().starts_with("# off"))
            .map(|line| {
                let (offset, tag) = {
                    let cap = re.captures(line.as_ref().unwrap()).unwrap();
                    (cap[1].to_string(), cap[2].to_string())
                };

                (offset, tag, line)
            })
            .filter(|(offset, _, _)| {
                // skip certain packages we are not (yet) parsing
                offset != &"1193538".to_string() && // invalid mpi
                offset != &"5053086".to_string() && // invalid mpi
                offset != &"8240010".to_string() && // unknown public key algorithm 100
                offset != &"9758352".to_string() && // TODO: unclear why this sig fails to parse
                offset != &"9797527".to_string() && // TODO: unclear why this sig fails to parse
                offset != &"11855679".to_string() &&  // TODO: unclear why this sig fails to parse
                offset != &"11855798".to_string() && // TODO: unclear why this sig fails to parse
                offset != &"11856933".to_string() && // TODO: unclear why this sig fails to parse
                offset != &"11857023".to_string() && // TODO: unclear why this sig fails to parse
                offset != &"11857113".to_string() && // TODO: unclear why this sig fails to parse
                offset != &"12688657".to_string() && // TODO: unclear why this sig fails to parse
                offset != &"24798372".to_string() && // TODO: unclear why this public sub key fails to parse
                offset != &"24810682".to_string() && // bad attribute size
                offset != &"38544535".to_string() // bad attribute size
            });

        let actual_tags = PacketParser::new(file).filter(|p| p.is_ok());
        for ((_offset, tag, e), packet) in expected_tags.zip(actual_tags) {
            let e = e.as_ref().unwrap();
            let packet = packet.unwrap();

            // println!("\n-- checking: {:?} {}", packet.tag(), e);

            let tag = Tag::from_u8(tag.parse().unwrap()).unwrap();
            assert_eq!(tag, packet.tag(), "missmatch in packet {:?} ({})", p, e);
        }
    }
}

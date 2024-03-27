use std::io::Read;

use buffer_redux::Buffer;
use nom::{Needed, Offset};

use crate::errors::{Error, Result};
use crate::packet::packet_sum::Packet;
use crate::packet::single::{self, ParseResult};
use crate::types::Tag;

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
            buffer: Buffer::with_capacity(1024),
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

            let res_header = match single::parser(b.buf()) {
                Ok(v) => Ok(v),
                Err(err) => Err(err.into()),
            }
            .and_then(|(rest, (ver, tag, _packet_length, body))| match body {
                ParseResult::Indeterminate => {
                    let mut body = rest.to_vec();
                    inner.read_to_end(&mut body)?;
                    match single::body_parser(ver, tag, &body) {
                        Err(Error::Incomplete(n)) => Err(Error::Incomplete(n)),
                        p => Ok((rest.len() + body.len(), p)),
                    }
                }
                ParseResult::Fixed(body) => {
                    let p = single::body_parser(ver, tag, body);
                    Ok((b.buf().offset(rest), p))
                }
                ParseResult::Partial(body) => {
                    ensure!(
                        // https://datatracker.ietf.org/doc/html/rfc4880#section-4.2.2.4
                        // "An implementation MAY use Partial Body Lengths for data packets, be
                        // they literal, compressed, or encrypted [...]
                        // Partial Body Lengths MUST NOT be used for any other packet types"
                        matches!(
                            tag,
                            Tag::LiteralData
                                | Tag::CompressedData
                                | Tag::SymEncryptedData
                                | Tag::SymEncryptedProtectedData
                        ),
                        "Partial body length is not allowed for packet type {:?}",
                        tag
                    );

                    if let Some(first) = body.first() {
                        // https://datatracker.ietf.org/doc/html/rfc4880#section-4.2.2.4
                        // "The first partial length MUST be at least 512 octets long."
                        ensure!(
                            first.len() >= 512,
                            "Illegal first partial body length {} (shorter than 512 bytes)",
                            first.len()
                        );
                    }

                    let p = single::body_parser(ver, tag, &body.concat());
                    Ok((b.buf().offset(rest), p))
                }
            });

            let res_body = match res_header {
                Ok(val) => Some(val),
                Err(err) => match err {
                    Error::Incomplete(n) => {
                        debug!("incomplete {:?}", n);
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

            if let Some((length, p)) = res_body {
                debug!("got packet: {:#?} {}", p, length);
                assert!(length > 0);
                b.consume(length);
                return Some(p);
            }

            // if the parser returned `Incomplete`, and it needs more data than the buffer can hold, we grow the buffer.
            if let Some(needed) = needed {
                let requested_size: usize = match needed {
                    Needed::Size(sz) => sz.into(),
                    Needed::Unknown => 1024,
                };

                if b.usable_space() < requested_size {
                    self.capacity = std::cmp::min(self.capacity * 2, MAX_CAPACITY);
                    b.make_room();
                    b.reserve(self.capacity);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use regex::Regex;
    use std::fs::File;
    use std::io::{BufRead, BufReader, Seek, SeekFrom};
    use std::path::Path;

    use crate::ser::Serialize;

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
        let _ = pretty_env_logger::try_init();

        let path = format!("./tests/tests/sks-dump/{dump}.pgp");
        let p = Path::new(&path);
        let file = File::open(p).unwrap();

        let mut bytes = File::open(p).unwrap();

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
                offset != "1193538" && // invalid mpi
                offset != "5053086" && // invalid mpi
                offset != "9758352" && // TODO: unclear why this sig fails to parse
                offset != "9797527" && // TODO: unclear why this sig fails to parse
                offset != "24798372" && // TODO: unclear why this public sub key fails to parse
                offset != "24810682" && // bad attribute size
                offset != "38544535" // bad attribute size
            });

        let actual_tags = PacketParser::new(file).filter(|p| p.is_ok());
        for ((_offset, tag, e), packet) in expected_tags.zip(actual_tags) {
            let e = e.as_ref().unwrap();
            let packet = packet.unwrap();

            // println!("\n-- checking: {:?} {}", packet.tag(), e);

            let tag: Tag = u8::into(tag.parse().unwrap());
            assert_eq!(tag, packet.tag(), "missmatch in packet {:?} ({})", p, e);
        }
    }

    #[test]
    fn incomplete_packet_parser() {
        let _ = pretty_env_logger::try_init();
        use std::io::Cursor;

        let bytes: [u8; 1] = [0x97];
        let parser = PacketParser::new(Cursor::new(bytes));
        let mut packets = parser.filter_map(|p| {
            // for now we are skipping any packets that we failed to parse
            match p {
                Ok(pp) => Some(pp),
                Err(err) => {
                    warn!("skipping packet: {:?}", err);
                    None
                }
            }
        });
        assert!(packets.next().is_none());
    }

    #[test]
    fn test_partial_length_encoding() {
        use crate::{Deserializable, Message};

        const TEXT: &str = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum. Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.\n";

        for msg_file in [
            // Literal Data Packet with two octet length encoding
            "./tests/unit-tests/partial-body-length/literal.packet-two-octet-length.asc",
            // Literal Data Packet with first partial length of 512 bytes, followed by a part with five octet length encoding
            "./tests/unit-tests/partial-body-length/literal.packet-partial.512.asc",
        ] {
            let (message, _headers) = Message::from_armor_single(File::open(msg_file).unwrap())
                .expect("failed to parse message");

            let Message::Literal(data) = &message else {
                panic!("expected Literal")
            };

            assert_eq!(data.data(), TEXT.as_bytes());
        }

        // Literal Data Packet with illegal first partial length of 256 bytes
        let res = Message::from_armor_single(
            File::open("./tests/unit-tests/partial-body-length/literal.packet-partial.256.asc")
                .unwrap(),
        );
        assert!(res.is_err());
    }
}

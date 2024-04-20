use std::io::{BufRead, Read};

use buffer_redux::policy::MinBuffered;
use buffer_redux::BufReader;

use crate::errors::{Error, Result};
use crate::packet::packet_sum::Packet;
use crate::packet::single;
use crate::types::{PacketLength, Tag};

use super::Span;

const MAX_CAPACITY: usize = 1024 * 1024 * 1024;

const DEFAULT_CAPACITY: usize = 1024 * 16;
const READER_POLICY: MinBuffered = MinBuffered(1024);

pub struct PacketParser<R> {
    reader: BufReader<R, MinBuffered>,
    /// Remember if we are done.
    done: bool,
}

impl<R: Read> PacketParser<R> {
    pub fn new(inner: R) -> Self {
        PacketParser {
            reader: BufReader::with_capacity(DEFAULT_CAPACITY, inner).set_policy(READER_POLICY),
            done: false,
        }
    }
}

impl<R: Read> Iterator for PacketParser<R> {
    type Item = Result<Packet>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        let buf = match self.reader.fill_buf() {
            Ok(buf) => buf,
            Err(err) => {
                warn!("failed to read {:?}", err);
                self.done = true;
                return None;
            }
        };

        // No more data to read
        if buf.is_empty() {
            self.done = true;
            return None;
        }

        let buf_len = buf.len();

        let (version, tag, packet_length) = match single::parser(Span::new(buf)) {
            Ok((rest, v)) => {
                let rest_len = rest.len();
                let read = buf_len - rest_len;
                self.reader.consume(read);
                v
            }
            Err(nom::Err::Incomplete(_)) => {
                // If incomplete, we are not getting a full header,
                // minimum input size is checked above.
                self.done = true;
                return Some(Err(Error::PacketIncomplete));
            }
            Err(err) => {
                self.done = true;
                return Some(Err(err.into()));
            }
        };

        match packet_length {
            PacketLength::Indeterminate => {
                let mut body = Vec::new();
                let mut buf = [0u8; 1024];

                loop {
                    // limited read_to_end
                    match self.reader.read(&mut buf) {
                        Ok(0) => {
                            break;
                        }
                        Ok(r) => {
                            body.extend_from_slice(&buf[..r]);
                            if body.len() >= MAX_CAPACITY {
                                self.done = true;
                                return Some(Err(format_err!("Indeterminate packet too large")));
                            }
                        }
                        Err(err) => {
                            self.done = true;
                            return Some(Err(err.into()));
                        }
                    }
                }

                let body_span = Span::new(&body); // TODO: add offset from header
                match single::body_parser(version, tag, body_span) {
                    Ok(packet) => Some(Ok(packet)),
                    Err(err) => {
                        self.done = true;
                        Some(Err(err))
                    }
                }
            }
            PacketLength::Fixed(len) => {
                let res = if len <= self.reader.policy().0 {
                    // small enough to reuse our internal buffer
                    self.reader.make_room();
                    let body = match self.reader.fill_buf() {
                        Ok(body) => body,
                        Err(err) => {
                            self.done = true;
                            return Some(Err(err.into()));
                        }
                    };
                    let res = single::body_parser(version, tag, Span::new(&body[..len]));
                    self.reader.consume(len);
                    res
                } else {
                    let mut buffer = vec![0u8; len];
                    if let Err(err) = self.reader.read_exact(&mut buffer) {
                        self.done = true;
                        return Some(Err(err.into()));
                    };
                    single::body_parser(version, tag, Span::new(&buffer))
                };

                match res {
                    Ok(p) => Some(Ok(p)),
                    Err(Error::Incomplete(_)) => {
                        // not bailing, we are just skipping incomplete bodies
                        Some(Err(Error::PacketIncomplete))
                    }
                    Err(err) => Some(Err(err)),
                }
            }
            PacketLength::Partial(len) => {
                // https://datatracker.ietf.org/doc/html/rfc4880#section-4.2.2.4
                // "An implementation MAY use Partial Body Lengths for data packets, be
                // they literal, compressed, or encrypted [...]
                // Partial Body Lengths MUST NOT be used for any other packet types"
                if !matches!(
                    tag,
                    Tag::LiteralData
                        | Tag::CompressedData
                        | Tag::SymEncryptedData
                        | Tag::SymEncryptedProtectedData
                ) {
                    self.done = true;
                    return Some(Err(format_err!(
                        "Partial body length is not allowed for packet type {:?}",
                        tag
                    )));
                }

                // https://datatracker.ietf.org/doc/html/rfc4880#section-4.2.2.4
                // "The first partial length MUST be at least 512 octets long."
                if len < 512 {
                    self.done = true;
                    return Some(Err(format_err!(
                        "Illegal first partial body length {} (shorter than 512 bytes)",
                        len,
                    )));
                }

                let mut body = vec![0u8; len];
                if let Err(err) = self.reader.read_exact(&mut body) {
                    self.done = true;
                    return Some(Err(err.into()));
                };

                // Read n partials + 1 final fixed
                loop {
                    self.reader.make_room();
                    let buf = match self.reader.fill_buf() {
                        Ok(buf) => buf,
                        Err(err) => {
                            self.done = true;
                            return Some(Err(err.into()));
                        }
                    };
                    match single::read_packet_len(Span::new(buf)) {
                        Ok((rest, PacketLength::Partial(len))) => {
                            let read = buf.len() - rest.len();
                            self.reader.consume(read);

                            if let Err(err) = read_fixed(&mut self.reader, len, &mut body) {
                                self.done = true;
                                return Some(Err(err));
                            }
                        }
                        Ok((rest, PacketLength::Fixed(len))) => {
                            let read = buf.len() - rest.len();
                            self.reader.consume(read);

                            if let Err(err) = read_fixed(&mut self.reader, len, &mut body) {
                                self.done = true;
                                return Some(Err(err));
                            }
                            break;
                        }
                        Ok((_, PacketLength::Indeterminate)) => {
                            self.done = true;
                            return Some(Err(Error::InvalidInput));
                        }
                        Err(err) => {
                            self.done = true;
                            return Some(Err(err.into()));
                        }
                    }
                }

                match single::body_parser(version, tag, Span::new(&body)) {
                    Ok(res) => Some(Ok(res)),
                    Err(Error::Incomplete(_)) => {
                        // not bailing, we are just skipping incomplete bodies
                        Some(Err(Error::PacketIncomplete))
                    }
                    Err(err) => {
                        self.done = true;
                        Some(Err(err))
                    }
                }
            }
        }
    }
}

fn read_fixed<R: Read>(
    reader: &mut BufReader<R, MinBuffered>,
    len: usize,
    out: &mut Vec<u8>,
) -> Result<()> {
    let out_len = out.len();
    out.resize(out_len + len, 0u8);
    reader.read_exact(&mut out[out_len..])?;

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use regex::Regex;
    use std::fs::File;
    use std::io::{BufReader, Seek, SeekFrom};
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
        let _ = pretty_env_logger::try_init();

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

        let bytes: [u8; 1] = [0x97];
        let parser = PacketParser::new(&bytes[..]);
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
        let _ = pretty_env_logger::try_init();

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

use log::debug;
use std::io::BufRead;

use crate::errors::{Error, Result};
use crate::packet::{Packet, PacketHeader};
use crate::parsing_reader::BufReadParsing;
use crate::reader::PacketBodyReader;

pub struct PacketParser<R: BufRead> {
    /// The reader that gets advanced through the original source
    reader: R,
    /// Are we done?
    is_done: bool,
}

impl<R: BufRead> PacketParser<R> {
    pub fn new(source: R) -> Self {
        PacketParser {
            reader: source,
            is_done: false,
        }
    }

    pub fn into_inner(self) -> R {
        self.reader
    }
}

impl<R: BufRead> Iterator for PacketParser<R> {
    type Item = Result<Packet>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.is_done {
            return None;
        }

        let header = match PacketHeader::try_from_reader(&mut self.reader) {
            Ok(header) => header,
            Err(err) => {
                self.is_done = true;
                if err.kind() == std::io::ErrorKind::UnexpectedEof {
                    return None;
                }

                return Some(Err(err.into()));
            }
        };

        log::warn!("found header: {header:?}");
        let mut body = PacketBodyReader::new(header, &mut self.reader);
        match Packet::from_reader(header, &mut body) {
            Ok(packet) => Some(Ok(packet)),
            Err(Error::PacketParsing { source }) if source.is_incomplete() => {
                debug!("incomplete packet for: {:?}", source);
                // not bailing, we are just skipping incomplete bodies

                if let Err(err) = body.drain() {
                    self.is_done = true;
                    return Some(Err(err.into()));
                }

                Some(Err(Error::PacketIncomplete { source }))
            }
            Err(err) => {
                if let Err(err) = body.drain() {
                    self.is_done = true;
                    return Some(Err(err.into()));
                }
                Some(Err(err.into()))
            }
        }
    }
}

impl<R: BufRead> PacketParser<R> {
    pub fn next_ref(&mut self) -> Option<Result<PacketBodyReader<&'_ mut R>>> {
        if self.is_done {
            return None;
        }

        let header = match PacketHeader::try_from_reader(&mut self.reader) {
            Ok(header) => header,
            Err(err) => {
                if err.kind() == std::io::ErrorKind::UnexpectedEof {
                    return None;
                }

                self.is_done = true;
                return Some(Err(err.into()));
            }
        };

        debug!("found header: {header:?}");
        let body = PacketBodyReader::new(header, &mut self.reader);
        Some(Ok(body))
    }

    pub fn next_owned(mut self) -> Option<Result<PacketBodyReader<R>>> {
        if self.is_done {
            return None;
        }

        let header = match PacketHeader::try_from_reader(&mut self.reader) {
            Ok(header) => header,
            Err(err) => {
                self.is_done = true;
                return Some(Err(err.into()));
            }
        };

        debug!("found header: {header:?}");
        let body = PacketBodyReader::new(header, self.reader);
        Some(Ok(body))
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
    use std::path::Path;

    use regex::Regex;

    use super::*;
    use crate::packet::PacketTrait;
    use crate::ser::Serialize;
    use crate::types::Tag;

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
                (836, 3136),  // non canonical length encoding
                (1200, 2772), // non canonical length encoding
                (1268, 1223), // non canonical length encoding
                (1670, 3419), // non canonical length encoding
            ],
        )
    }

    #[test]
    #[ignore]
    fn test_packet_roundtrip_0009() {
        packet_roundtrip(
            "0009",
            vec![
                (37, 3960),   // non canonical length encoding
                (39, 3960),   // non canonical length encoding
                (258, 75),    // non canonical length encoding
                (260, 78),    // non canonical length encoding
                (1053, 3181), // non canonical length encoding
                (1473, 5196), // non canonical length encoding
                (1895, 4243), // non canonical length encoding
            ],
        )
    }

    fn packet_roundtrip(dump: &str, skips: Vec<(usize, i64)>) {
        let _ = pretty_env_logger::try_init();

        let path = format!("./tests/tests/sks-dump/{dump}.pgp");
        let p = Path::new(&path);
        let mut file = BufReader::new(std::fs::File::open(p).unwrap());
        let mut bytes = File::open(p).unwrap();

        let packets = PacketParser::new(&mut file);

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
    #[ignore]
    fn test_many_parser() {
        let _ = pretty_env_logger::try_init();

        let p = Path::new("./tests/tests/sks-dump/0000.pgp");
        let file = BufReader::new(std::fs::File::open(p).unwrap());

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
                offset != "6844449" && // RSA public exponent too large
                offset != "9758352" && // TODO: unclear why this sig fails to parse
                offset != "9797527" && // TODO: unclear why this sig fails to parse
                offset != "24798372" && // TODO: unclear why this public sub key fails to parse
                offset != "24810682" && // bad attribute size
                offset != "38544535" && // bad attribute size
                offset != "38521947" && // RSA public exponent too large
                offset != "32162244" && // Invalid DSA key
                offset != "43825283" // Invalid DSA key
            });

        let actual_tags = PacketParser::new(file).filter(|p| p.is_ok());
        for ((_offset, tag, e), packet) in expected_tags.zip(actual_tags) {
            let e = e.as_ref().unwrap();
            let packet = packet.unwrap();

            println!("-- checking: {:?} {}", packet.tag(), e);

            let tag: Tag = u8::into(tag.parse().unwrap());
            assert_eq!(tag, packet.tag(), "mismatch in packet {:?} ({})", p, e);
        }
    }

    #[test]
    fn incomplete_packet_parser() {
        let _ = pretty_env_logger::try_init();

        let bytes = [0x97];
        let parser = PacketParser::new(&bytes[..]);
        let mut packets = parser.filter_map(|p| {
            // for now we are skipping any packets that we failed to parse
            match p {
                Ok(pp) => Some(pp),
                Err(err) => {
                    log::warn!("skipping packet: {:?}", err);
                    None
                }
            }
        });
        assert!(packets.next().is_none());
    }

    #[test]
    fn test_partial_length_encoding() {
        let _ = pretty_env_logger::try_init();

        use crate::Message;

        const TEXT: &str = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum. Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.\n";

        for msg_file in [
            // Literal Data Packet with two octet length encoding
            "./tests/unit-tests/partial-body-length/literal.packet-two-octet-length.asc",
            // Literal Data Packet with first partial length of 512 bytes, followed by a part with five octet length encoding
            "./tests/unit-tests/partial-body-length/literal.packet-partial.512.asc",
        ] {
            let (mut message, _headers) =
                Message::from_armor_file(msg_file).expect("failed to parse message");

            assert!(message.is_literal());
            assert_eq!(message.as_data_vec().unwrap(), TEXT.as_bytes());
        }

        // Literal Data Packet with illegal first partial length of 256 bytes
        let res = Message::from_armor_file(
            "./tests/unit-tests/partial-body-length/literal.packet-partial.256.asc",
        );
        assert!(res.is_err());
    }
}

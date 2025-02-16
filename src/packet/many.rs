use bytes::{Buf, Bytes};
use bytes_utils::SegmentedBuf;
use log::debug;

use crate::errors::{Error, Result};
use crate::packet::{Packet, PacketHeader};
use crate::parsing::BufParsing;
use crate::types::{PacketLength, Tag};

pub struct PacketParser {
    /// The reader that gets advanced through the original source
    reader: Bytes,
    /// Are we done?
    is_done: bool,
}

impl PacketParser {
    pub fn new(source: Bytes) -> Self {
        PacketParser {
            reader: source,
            is_done: false,
        }
    }
}

impl Iterator for PacketParser {
    type Item = Result<Packet>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.is_done {
            return None;
        }

        if !self.reader.has_remaining() {
            self.is_done = true;
            return None;
        }

        let header = match PacketHeader::from_buf(&mut self.reader) {
            Ok(header) => header,
            Err(err) => {
                self.is_done = true;
                return Some(Err(err));
            }
        };

        debug!("found header: {header:?}");

        match header.packet_length() {
            PacketLength::Indeterminate => {
                let body = self.reader.rest();
                match Packet::from_bytes(header, body) {
                    Ok(packet) => Some(Ok(packet)),
                    Err(err) => {
                        self.is_done = true;
                        Some(Err(err))
                    }
                }
            }
            PacketLength::Fixed(len) => {
                let packet_bytes = match self.reader.read_take(len) {
                    Ok(b) => b,
                    Err(err) => return Some(Err(err)),
                };
                let res = Packet::from_bytes(header, packet_bytes);
                match res {
                    Ok(packet) => Some(Ok(packet)),
                    Err(Error::Incomplete(e)) => {
                        debug!("incomplete packet for: {:?}", e);
                        // not bailing, we are just skipping incomplete bodies
                        Some(Err(Error::PacketIncomplete))
                    }
                    Err(err) => Some(Err(err)),
                }
            }
            PacketLength::Partial(len) => {
                // https://www.rfc-editor.org/rfc/rfc9580.html#name-partial-body-lengths
                // "An implementation MAY use Partial Body Lengths for data packets, be
                // they literal, compressed, or encrypted [...]
                // Partial Body Lengths MUST NOT be used for any other packet types"
                if !matches!(
                    header.tag(),
                    Tag::LiteralData
                        | Tag::CompressedData
                        | Tag::SymEncryptedData
                        | Tag::SymEncryptedProtectedData
                ) {
                    self.is_done = true;
                    return Some(Err(format_err!(
                        "Partial body length is not allowed for packet type {:?}",
                        header.tag()
                    )));
                }

                // https://www.rfc-editor.org/rfc/rfc9580.html#section-4.2.1.4-5
                // "The first partial length MUST be at least 512 octets long."
                if len < 512 {
                    self.is_done = true;
                    return Some(Err(format_err!(
                        "Illegal first partial body length {} (shorter than 512 bytes)",
                        len,
                    )));
                }

                let mut body = SegmentedBuf::new();
                let first = match self.reader.read_take(len as usize) {
                    Ok(bytes) => bytes,
                    Err(err) => {
                        self.is_done = true;
                        return Some(Err(err));
                    }
                };
                body.push(first);

                // Read n partials + 1 final fixed
                loop {
                    let len = PacketLength::from_buf(&mut self.reader);
                    debug!("partials: found packet_length: {:?}", len);
                    match len {
                        Ok(PacketLength::Partial(len)) => {
                            let len = len as usize;
                            if self.reader.remaining() < len {
                                self.is_done = true;
                                return Some(Err(format_err!("invalid packet length detected: need {} bytes, only have {} bytes", len, self.reader.remaining())));
                            }

                            body.push(self.reader.copy_to_bytes(len));
                        }
                        Ok(PacketLength::Fixed(len)) => {
                            if self.reader.remaining() < len {
                                self.is_done = true;
                                return Some(Err(format_err!("invalid packet length detected: need {} bytes, only have {} bytes", len, self.reader.remaining())));
                            }
                            body.push(self.reader.copy_to_bytes(len));
                            break;
                        }
                        Ok(PacketLength::Indeterminate) => {
                            self.is_done = true;
                            return Some(Err(Error::InvalidInput));
                        }
                        Err(err) => {
                            self.is_done = true;
                            return Some(Err(err));
                        }
                    }
                }

                match Packet::from_bytes(header, body) {
                    Ok(packet) => Some(Ok(packet)),
                    Err(Error::Incomplete(_)) => {
                        // not bailing, we are just skipping incomplete bodies
                        Some(Err(Error::PacketIncomplete))
                    }
                    Err(err) => {
                        self.is_done = true;
                        Some(Err(err))
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::fs::File;
    use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
    use std::path::Path;

    use regex::Regex;

    use super::*;
    use crate::packet::PacketTrait;
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
        let file: Bytes = std::fs::read(p).unwrap().into();

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
    #[ignore]
    fn test_many_parser() {
        let _ = pretty_env_logger::try_init();

        let p = Path::new("./tests/tests/sks-dump/0000.pgp");
        let file: Bytes = std::fs::read(p).unwrap().into();

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

        let bytes = Bytes::from_static(&[0x97]);
        let parser = PacketParser::new(bytes);
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

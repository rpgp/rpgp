use armor;
use packet::{Packet, packets_parser};
use packet::types::{User, UserAttribute, PrimaryKey, pubkey};
use errors::{Result, unwrap_iresult};
use nom::IResult;

/// Represents a PGP key.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Key {
    pub primary_key: PrimaryKey,
    // pub revocation_signature:
    // pub direct_signatures: Vec<>
    pub users: Vec<User>,
    pub user_attributes: Vec<UserAttribute>,
    // pub subkeys: Vec<>
}

impl Key {
    /// Parse a raw byte encoded publickey.
    /// This is usually a file with the eding `.pgp`.
    pub fn from_raw_bytes(bytes: &[u8]) -> Result<Vec<Self>> {
        let packets = unwrap_iresult(packets_parser(bytes))?;

        // TODO: handle both public key and private keys.
        // They use different packets.
        unwrap_iresult(pubkey::parse(packets))
    }

    /// Parse an armor encoded publickey.
    /// This is usually a file with the endig `.asc`.
    pub fn from_armor_bytes(bytes: &[u8]) -> Result<Vec<Self>> {
        let (_typ, _headers, body) = unwrap_iresult(armor::parse(bytes))?;
        Key::from_raw_bytes(body.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet::types::{Signature, SignatureVersion, SignatureType, User, PublicKey, PrimaryKey,
                        KeyVersion, PublicKeyAlgorithm, HashAlgorithm, Subpacket,
                        SymmetricKeyAlgorithm, CompressionAlgorithm, UserAttributeType};
    use chrono::{DateTime, Utc};
    use std::fs::File;
    use std::io::Read;
    use std::path::{Path, PathBuf};
    use std::io::prelude::*;

    fn read_file(path: PathBuf) -> Vec<u8> {
        // Open the path in read-only mode, returns `io::Result<File>`
        let mut file = match File::open(&path) {
            // The `description` method of `io::Error` returns a string that
            // describes the error
            Err(why) => panic!("couldn't open {}: {}", path.display(), why),
            Ok(file) => file,
        };
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).unwrap();

        buf
    }

    fn get_test_key(name: &str) -> Vec<u8> {
        return read_file(Path::new("./tests/opengpg-interop/testcases/keys").join(
            name,
        ));
    }

    #[test]
    fn test_parse_dump() {
        for i in 0..10 {
            let buf = read_file(Path::new("./tests/sks-dump/").join(format!("000{}.pgp", i)));

            let key = Key::from_raw_bytes(buf.as_slice());
            key.expect("failed to parse key");
        }
    }

    #[test]
    fn test_parse_gnupg_v1() {
        for i in 1..5 {
            let name = format!("gnupg-v1-00{}.asc", i);
            let buf = get_test_key(&name);

            let key = Key::from_armor_bytes(buf.as_slice());
            key.expect("failed to parse key");
        }
    }
}

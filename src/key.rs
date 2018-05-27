use armor;
use packet::packets_parser;
use packet::types::{User, UserAttribute, PrimaryKey, pubkey};
use errors::Result;

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
    /// This is usually a file with the extension `.pgp`.
    pub fn from_raw_bytes(bytes: &[u8]) -> Result<Vec<Self>> {
        let (_, packets) = packets_parser(bytes)?;

        // TODO: handle both public key and private keys.
        // tip: They use different packet types.
        let (_, res) = pubkey::parse(packets)?;
        Ok(res)
    }

    /// Parse an armor encoded publickey.
    /// This is usually a file with the extension `.asc`.
    pub fn from_armor(input: &str) -> Result<Vec<Self>> {
        let (_, res) = armor::parse(input)?;
        let (_typ, _headers, body) = res;
        Key::from_raw_bytes(body.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Read;
    use std::path::{Path, PathBuf};

    fn read_file(path: PathBuf) -> Vec<u8> {
        // Open the path in read-only mode, returns `io::Result<File>`
        let mut file = match File::open(&path) {
            // The `description` method of `io::Error` returns a string that
            // describes the error
            Err(why) => panic!("couldn't open {}: {}", path.display(), why),
            Ok(file) => file,
        };
        let mut res = Vec::new();
        file.read_to_end(&mut res).expect("failed to read file");

        res
    }

    fn get_test_key(name: &str) -> Vec<u8> {
        return read_file(Path::new("./tests/opengpg-interop/testcases/keys").join(
            name,
        ));
    }

    #[test]
    fn test_parse_dump() {
        let i = 0;
        // for i in 0..10 {
        let buf = read_file(Path::new("./tests/sks-dump/").join(format!("000{}.pgp", i)));

        let key = Key::from_raw_bytes(buf.as_slice());
        key.expect("failed to parse key");
        // }
    }

    #[test]
    fn test_parse_gnupg_v1() {
        for i in 1..5 {
            let name = format!("gnupg-v1-00{}.asc", i);
            let buf = get_test_key(&name);

            let key = Key::from_armor(::std::str::from_utf8(buf.as_slice()).unwrap())
                .expect("failed to parse key");
            assert_eq!(1, key.len());
        }
    }
}

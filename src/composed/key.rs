use super::parser::{self, ParseKey};
use armor;
use errors::{Error, Result};
use packet::{self, types};
use std::io::Read;

// TODO: can detect armored vs binary using a check if the first bit in the data is set. If it is cleared it is not a binary message, so can try to parse as armor ascii. (from gnupg source)

/// Represents a PGP key.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Key<T>
where
    T: ::std::fmt::Debug + Clone,
{
    pub primary_key: types::key::Key<T>,
    pub revocation_signatures: Vec<types::Signature>,
    pub direct_signatures: Vec<types::Signature>,
    pub users: Vec<types::User>,
    pub user_attributes: Vec<types::UserAttribute>,
    pub subkeys: Vec<SubKey<T>>,
}

/// Represents a PGP SubKey
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SubKey<T>
where
    T: ::std::fmt::Debug + Clone,
{
    pub key: types::key::Key<T>,
    pub signatures: Vec<types::Signature>,
}

impl<T> Key<T>
where
    T: ::std::fmt::Debug + Clone,
    parser::KeyParser: parser::ParseKey<T>,
{
    /// Parse a single byte encoded key.
    /// This is usually a file with the extension `.pgp`.
    pub fn from_bytes(bytes: impl Read) -> Result<Key<T>> {
        let keys = Key::from_bytes_many(bytes)?;

        if keys.len() > 1 {
            return Err(Error::MultipleKeys);
        }

        keys.into_iter().nth(0).ok_or_else(|| Error::NoKey)
    }

    /// Parse a single armor encoded key string.
    /// This is usually a file with the extension `.asc`.
    pub fn from_string(input: &str) -> Result<Key<T>> {
        let keys = Key::from_string_many(input)?;

        if keys.len() > 1 {
            return Err(Error::MultipleKeys);
        }

        keys.into_iter().nth(0).ok_or_else(|| Error::NoKey)
    }

    /// Parse byte encoded keys.
    pub fn from_bytes_many(bytes: impl Read) -> Result<Vec<Key<T>>> {
        let packets = packet::parser(bytes)?;
        println!("got packets {:?}", packets);
        // TODO: handle both public key and private keys.
        // tip: They use different packet types.
        parser::KeyParser::many(&packets)
    }

    /// Parse an armor encoded list of keys.
    pub fn from_string_many(input: &str) -> Result<Vec<Key<T>>> {
        let (_typ, _headers, body) = armor::parse(input)?;
        println!("got key: {:?} {:?} {}", _typ, _headers, body.len());
        // TODO: add typ and headers information to the key possibly?
        Key::from_bytes_many(body.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};
    use packet::types::key;
    use packet::types::{
        CompressionAlgorithm, HashAlgorithm, KeyVersion, PublicKeyAlgorithm, Signature,
        SignatureType, SignatureVersion, Subpacket, SymmetricKeyAlgorithm, User, UserAttributeType,
    };
    use std::fs::File;
    use std::io::Read;
    use std::path::{Path, PathBuf};

    fn read_file(path: PathBuf) -> File {
        // Open the path in read-only mode, returns `io::Result<File>`
        match File::open(&path) {
            // The `description` method of `io::Error` returns a string that
            // describes the error
            Err(why) => panic!("couldn't open {}: {}", path.display(), why),
            Ok(file) => file,
        }
    }

    fn get_test_key(name: &str) -> File {
        return read_file(Path::new("./tests/opengpg-interop/testcases/keys").join(name));
    }

    fn test_parse_dump(i: usize) {
        let f = read_file(Path::new("./tests/sks-dump/").join(format!("000{}.pgp", i)));
        Key::<key::Public>::from_bytes_many(f).unwrap();
    }

    #[test]
    fn test_parse_dumps_0() {
        test_parse_dump(0);
    }

    #[test]
    fn test_parse_dumps_1() {
        test_parse_dump(1);
    }

    #[test]
    fn test_parse_dumps_2() {
        test_parse_dump(2);
    }

    #[test]
    fn test_parse_dumps_3() {
        test_parse_dump(3);
    }
    #[test]
    fn test_parse_dumps_4() {
        test_parse_dump(4);
    }

    #[test]
    fn test_parse_dumps_5() {
        test_parse_dump(5);
    }

    #[test]
    fn test_parse_dumps_6() {
        test_parse_dump(6);
    }

    #[test]
    fn test_parse_dumps_7() {
        test_parse_dump(7);
    }

    #[test]
    fn test_parse_dumps_8() {
        test_parse_dump(8);
    }

    #[test]
    fn test_parse_dumps_9() {
        test_parse_dump(9);
    }

    #[test]
    fn test_parse_gnupg_v1() {
        for i in 1..5 {
            let name = format!("gnupg-v1-00{}.asc", i);
            let mut file = get_test_key(&name);
            let mut buf = vec![];
            file.read_to_end(&mut buf).unwrap();

            let input = ::std::str::from_utf8(buf.as_slice()).expect("failed to convert to string");
            Key::<key::Public>::from_string(input).expect("failed to parse key");
        }
    }

    #[test]
    fn test_parse_openpgp_sample_rsa_private() {
        let p = Path::new("./tests/openpgp/samplekeys/rsa-primary-auth-only.sec.asc");
        let mut file = read_file(p.to_path_buf());

        let mut buf = vec![];
        file.read_to_end(&mut buf).unwrap();

        let input = ::std::str::from_utf8(buf.as_slice()).expect("failed to convert to string");
        let key = Key::<key::Private>::from_string(input).expect("failed to parse key");

        assert_eq!(key.primary_key.version(), &KeyVersion::V4);
        assert_eq!(key.primary_key.algorithm(), &PublicKeyAlgorithm::RSA);
    }

    #[test]
    fn test_parse_details() {
        let raw = include_bytes!("../../tests/opengpg-interop/testcases/keys/gnupg-v1-003.asc");
        let input = ::std::str::from_utf8(raw).unwrap();
        let key = Key::from_string(input).expect("failed to parse key");

        // assert_eq!(key.primary_key.fingerprint(), "56c65c513a0d1b9cff532d784c073ae0c8445c0c");

        let primary_n = hex!("a5 4c fa 91 42 fb 75 26 53 22 05 5b 11 f7 50 f4 9a f3 7b 64 c6 7a d8 30 ed 74 43 d6 c2 04 77 b0 49 2e e9 09 0e 4c b8 b0 c2 c5 d4 9e 87 df f5 ac 80 1b 1a aa db 31 9e ee 9d 3d 29 b2 5b d9 aa 63 4b 12 6c 0e 5d a4 e6 6b 41 4e 9d bd de 5d ea 0e 38 c5 bf e7 e5 f7 fd b9 f4 c1 b1 f3 9e d8 92 dd 4e 08 73 a0 df 66 ff 46 fd 92 36 d2 91 c2 76 ce 69 fb 97 2f 5e f2 47 46 b6 79 4a 0f 70 e0 69 46 67 b9 de 57 35 33 30 c7 32 73 3c c6 d5 f2 4c d7 72 c5 c7 d5 bd b7 7d c0 a5 b6 e9 d3 ee 03 72 14 67 78 cd a6 14 49 76 e3 30 66 fc 57 bf b5 15 ef 39 7b 3a a8 82 c0 bd e0 2d 19 f7 a3 2d f7 b1 19 5c b0 f3 2e 6e 74 55 ac 19 9f a4 34 35 5f 0f a4 32 30 e5 23 7e 9a 6e 0f f6 ad 5b 21 b4 d8 92 c6 fc 38 42 78 8b a4 8b 02 0e e8 5e dd 13 5c ff 28 08 78 0e 83 4b 5d 94 cc 2c 2b 5f a7 47 16 7a 20 81 45 89 d7 f0 30 ee 9f 8a 66 97 37 bd b0 63 e6 b0 b8 8a b0 fd 74 54 c0 3f 69 67 8a 1d d9 94 42 cf d0 bf 62 0b c5 b6 89 6c d6 e2 b5 1f de cf 54 c7 e6 36 8c 11 c7 0f 30 24 44 ec 9d 5a 17 ce aa cb 4a 9a c3 c3 7d b3 47 8f 8f b0 4a 67 9f 09 57 a3 69 7e 8d 90 15 20 08 92 7c 75 1b 34 16 0c 72 e7 57 ef c8 50 53 dd 86 73 89 31 fd 35 1c f1 34 26 6e 43 6e fd 64 a1 4b 35 86 90 40 10 80 82 84 7f 7f 52 15 62 8e 7f 66 51 38 09 ae 0f 66 ea 73 d0 1f 5f d9 65 14 2c db 78 60 27 6d 4c 20 fa f7 16 c4 0a e0 63 2d 3b 18 01 37 43 8c b9 52 57 32 76 07 03 8f b3 b8 2f 76 55 6e 8d d1 86 b7 7c 2f 51 b0 bf dd 75 52 f1 68 f2 c4 eb 90 84 4f dc 05 cf 23 9a 57 69 02 25 90 33 99 78 3a d3 73 68 91 ed b8 77 45 a1 18 0e 04 74 15 26 38 40 45 c2 de 03 c4 63 c4 3b 27 d5 ab 7f fd 6d 0e cc cc 24 9f").to_vec();

        assert_eq!(
            key.primary_key,
            key::RSA::<key::Public>::new(
                KeyVersion::V4,
                PublicKeyAlgorithm::RSA,
                key::RSAPublicParams {
                    n: primary_n,
                    e: vec![1u8, 0u8, 1u8],
                }
            ).into()
        );

        // TODO: examine subkey details
        assert_eq!(key.subkeys.len(), 1, "missing subkey");

        let mut sig1 = Signature::new(
            SignatureVersion::V4,
            SignatureType::CertPositive,
            PublicKeyAlgorithm::RSA,
            HashAlgorithm::SHA1,
            vec![0x7c, 0x63],
            vec![
                0x15, 0xb5, 0x4f, 0xca, 0x11, 0x7f, 0x1b, 0x1d, 0xc0, 0x7a, 0x05, 0x97, 0x25, 0x10,
                0x4b, 0x6a, 0x76, 0x12, 0xf8, 0x89, 0x48, 0x76, 0x74, 0xeb, 0x8b, 0x22, 0xcf, 0xeb,
                0x95, 0x80, 0x70, 0x97, 0x1b, 0x92, 0x7e, 0x35, 0x8f, 0x5d, 0xc8, 0xae, 0x22, 0x0d,
                0x19, 0xdd, 0xd3, 0x38, 0x6c, 0xbb, 0x2f, 0x25, 0xa7, 0xcb, 0x8d, 0x2d, 0x11, 0x6b,
                0x05, 0xc5, 0x77, 0xce, 0xa8, 0x86, 0xa0, 0xfc, 0xb5, 0x43, 0x26, 0x70, 0xec, 0x26,
                0xdf, 0x56, 0x1c, 0xff, 0xe1, 0xe9, 0x13, 0x72, 0x18, 0xae, 0x7f, 0xf8, 0x1c, 0x0f,
                0x5f, 0x2e, 0x37, 0xb5, 0xdf, 0xd9, 0x6b, 0x17, 0x8c, 0x87, 0xc7, 0x30, 0x75, 0x7f,
                0x25, 0xb3, 0xbf, 0xfa, 0xcd, 0x93, 0xe6, 0x93, 0x31, 0xba, 0x06, 0x14, 0x91, 0xbf,
                0x8a, 0xf2, 0x15, 0x80, 0xac, 0xdd, 0xc9, 0xaf, 0x8e, 0xf7, 0xbd, 0x95, 0x77, 0x3b,
                0xb8, 0x02, 0x1a, 0x29, 0x9b, 0x96, 0x01, 0xd9, 0x28, 0x76, 0xa4, 0xb4, 0xf0, 0x2a,
                0x18, 0x1b, 0x76, 0x70, 0xa0, 0x5f, 0x39, 0x54, 0xc1, 0x9e, 0x5d, 0x77, 0x1f, 0x43,
                0x61, 0x84, 0x0e, 0xed, 0x4e, 0x86, 0x9f, 0x99, 0x57, 0xe1, 0x69, 0x27, 0xd6, 0xfc,
                0x0b, 0x46, 0x98, 0x31, 0x89, 0xe5, 0xc8, 0xc6, 0xc9, 0x89, 0x08, 0x49, 0x3a, 0xd2,
                0xff, 0x56, 0x2c, 0xe0, 0xf6, 0x7f, 0xb0, 0x72, 0x23, 0xf1, 0x52, 0x3c, 0x5f, 0x8d,
                0x81, 0xc4, 0xd0, 0xba, 0xd5, 0x6d, 0x57, 0x71, 0x46, 0xc6, 0x85, 0xe6, 0x35, 0xfa,
                0x12, 0x09, 0x8f, 0x30, 0x0d, 0x7e, 0x78, 0xc0, 0x0c, 0xc2, 0xd5, 0x20, 0x3e, 0xd0,
                0x03, 0x28, 0x01, 0x06, 0xf2, 0xef, 0x93, 0xf8, 0x09, 0x1d, 0xf8, 0x4f, 0x61, 0xe0,
                0xdc, 0x03, 0x4b, 0x70, 0xbd, 0x15, 0x6f, 0xf0, 0x72, 0xeb, 0x93, 0xb2, 0x65, 0x5a,
                0x65, 0xea, 0xf5, 0x05, 0xcb, 0x97, 0x89, 0xa3, 0xf7, 0x95, 0xdf, 0x26, 0xae, 0xae,
                0x1c, 0x71, 0xfe, 0x8c, 0x83, 0xda, 0x30, 0x69, 0xfd, 0x10, 0x28, 0x22, 0xd7, 0x9d,
                0x02, 0xe2, 0x2d, 0xb3, 0x31, 0x34, 0x9c, 0x0f, 0x4a, 0xf6, 0xff, 0x77, 0xeb, 0x64,
                0xa1, 0x6e, 0x97, 0x07, 0xbf, 0x66, 0x92, 0xec, 0xce, 0x65, 0xe3, 0x55, 0x73, 0x33,
                0x6a, 0xb9, 0xed, 0x5d, 0xdd, 0x36, 0x41, 0x2e, 0xc9, 0xea, 0x1c, 0x3f, 0x9d, 0x0c,
                0x95, 0x22, 0xa8, 0x46, 0xcd, 0x25, 0xf1, 0xd4, 0x5d, 0x70, 0x48, 0xca, 0x85, 0x53,
                0xe2, 0xcd, 0x2e, 0x45, 0x7f, 0xeb, 0x98, 0x21, 0x95, 0xfa, 0xa9, 0x8a, 0x6b, 0x3e,
                0x56, 0x82, 0x4e, 0x16, 0xf6, 0xab, 0x6e, 0xfd, 0x7c, 0x96, 0xf1, 0x15, 0xab, 0x50,
                0x80, 0x19, 0xbb, 0x46, 0x98, 0x18, 0x58, 0x4e, 0x98, 0xc5, 0x58, 0x23, 0x41, 0x89,
                0xeb, 0xb9, 0x21, 0x74, 0x56, 0xeb, 0xfe, 0x68, 0x5e, 0x79, 0xde, 0x12, 0x07, 0xfb,
                0xfa, 0x13, 0xe3, 0x44, 0x33, 0xfb, 0x22, 0xa7, 0x83, 0x37, 0xf0, 0x9f, 0xf8, 0xd7,
                0xc2, 0xab, 0x6e, 0x2b, 0x51, 0xda, 0x47, 0xe0, 0x3b, 0x3f, 0xdb, 0x2a, 0x4a, 0x22,
                0xb4, 0xfb, 0xa0, 0x32, 0xb6, 0x9d, 0x37, 0xeb, 0x82, 0x3d, 0xbb, 0x2d, 0x8f, 0x13,
                0xbf, 0x28, 0xe1, 0x0e, 0x01, 0x6f, 0x7c, 0x6e, 0x52, 0x78, 0x88, 0xb5, 0xf3, 0x28,
                0x51, 0x9c, 0x07, 0x1b, 0x29, 0x60, 0xda, 0x27, 0x56, 0xe1, 0x88, 0x97, 0x1c, 0xf3,
                0x1d, 0x64, 0x28, 0x14, 0xf6, 0xf7, 0x29, 0x53, 0x95, 0x9a, 0x1e, 0x51, 0x75, 0x03,
                0xbd, 0x1f, 0x26, 0x92, 0xda, 0x85, 0x52, 0x71, 0x15, 0x9d, 0x7e, 0xa4, 0x7e, 0xc2,
                0xd1, 0xcd, 0xb4, 0x56, 0xb3, 0x9a, 0x92, 0x0c, 0x4c, 0x0e, 0x40, 0x8d, 0xf3, 0x4d,
                0xb9, 0x49, 0x6f, 0x55, 0xc6, 0xb9, 0xf5, 0x1a,
            ],
        );

        let key_flags = vec![3];
        let p_sym_algs = vec![
            SymmetricKeyAlgorithm::AES256,
            SymmetricKeyAlgorithm::AES192,
            SymmetricKeyAlgorithm::AES128,
            SymmetricKeyAlgorithm::CAST5,
            SymmetricKeyAlgorithm::TripleDES,
        ];
        let p_com_algs = vec![
            CompressionAlgorithm::ZLIB,
            CompressionAlgorithm::BZip2,
            CompressionAlgorithm::ZIP,
        ];
        let p_hash_algs = vec![
            HashAlgorithm::SHA256,
            HashAlgorithm::SHA1,
            HashAlgorithm::SHA384,
            HashAlgorithm::SHA512,
            HashAlgorithm::SHA224,
        ];
        let issuer = Subpacket::Issuer([0x4C, 0x07, 0x3A, 0xE0, 0xC8, 0x44, 0x5C, 0x0C]);

        sig1.created = Some(
            DateTime::parse_from_rfc3339("2014-06-06T15:57:41Z")
                .expect("failed to parse static time")
                .with_timezone(&Utc),
        );

        sig1.key_flags = key_flags.clone();
        sig1.preferred_symmetric_algs = p_sym_algs.clone();
        sig1.preferred_compression_algs = p_com_algs.clone();
        sig1.preferred_hash_algs = p_hash_algs.clone();

        sig1.key_server_prefs = vec![128];
        sig1.features = vec![1];

        sig1.unhashed_subpackets.push(issuer.clone());

        let u1 = User::new("john doe (test) <johndoe@example.com>", vec![sig1]);

        let mut sig2 = Signature::new(
            SignatureVersion::V4,
            SignatureType::CertPositive,
            PublicKeyAlgorithm::RSA,
            HashAlgorithm::SHA1,
            vec![0xca, 0x6c],
            vec![
                0x49, 0xa0, 0xb5, 0x41, 0xbd, 0x33, 0xa8, 0xda, 0xda, 0x6e, 0xb1, 0xe5, 0x28, 0x74,
                0x18, 0xee, 0x39, 0xc8, 0x8d, 0xfd, 0x39, 0xe8, 0x3b, 0x09, 0xdc, 0x9d, 0x04, 0x91,
                0x5d, 0x66, 0xb8, 0x1d, 0x04, 0x0a, 0x90, 0xe7, 0xa6, 0x84, 0x9b, 0xb1, 0x06, 0x4f,
                0x3f, 0xaa, 0xc5, 0x64, 0x53, 0xf8, 0xaf, 0xe1, 0xaa, 0x6f, 0xba, 0x9d, 0xd4, 0xa0,
                0x58, 0xc4, 0x39, 0x39, 0xee, 0xb6, 0xcd, 0x7d, 0xd4, 0x04, 0xab, 0xa2, 0x30, 0x3d,
                0xab, 0xf5, 0xb1, 0x2c, 0x28, 0xa7, 0xd7, 0xba, 0x59, 0x0c, 0xe9, 0xa2, 0xe9, 0x40,
                0x76, 0xcd, 0xce, 0xf5, 0x77, 0x7d, 0xf5, 0x0c, 0x90, 0x8b, 0x13, 0x44, 0xb4, 0xe1,
                0x1d, 0xf2, 0x41, 0x71, 0xd6, 0xb0, 0x90, 0xed, 0x97, 0x5c, 0x6b, 0x60, 0x4b, 0xb6,
                0xda, 0xb4, 0x19, 0xb5, 0x26, 0x35, 0xbe, 0xed, 0xda, 0x6e, 0x14, 0x91, 0x77, 0x76,
                0x52, 0x78, 0xbb, 0xe1, 0xfa, 0x25, 0x34, 0xcb, 0x55, 0x0a, 0x25, 0x61, 0x43, 0x3a,
                0x45, 0xae, 0x6b, 0xe9, 0x26, 0xa8, 0x56, 0x62, 0xd4, 0x27, 0x1f, 0xb7, 0x6c, 0xdc,
                0xd6, 0x3c, 0x2c, 0x52, 0x6c, 0xae, 0x84, 0x9b, 0xc1, 0x30, 0x15, 0xe8, 0xa1, 0x69,
                0x33, 0x9d, 0xe1, 0x3d, 0xba, 0x6f, 0x34, 0xa7, 0x65, 0x98, 0x86, 0x81, 0x7c, 0x08,
                0x9c, 0x6a, 0xb7, 0x39, 0x93, 0xe7, 0x93, 0x43, 0x08, 0x83, 0xea, 0x43, 0x95, 0xf2,
                0x6c, 0x16, 0x02, 0x1b, 0xb9, 0xbb, 0xe5, 0x69, 0xf1, 0x6a, 0xd0, 0xc5, 0xa6, 0x77,
                0x33, 0x42, 0xe1, 0x40, 0x01, 0x2a, 0x92, 0x9d, 0x27, 0xb3, 0x75, 0x2d, 0x67, 0xd4,
                0xec, 0x77, 0xc5, 0xaa, 0x49, 0xe3, 0x62, 0x9d, 0x92, 0xaa, 0x74, 0x38, 0xec, 0x72,
                0x3c, 0x54, 0x3d, 0xa9, 0x9e, 0x52, 0x6e, 0x58, 0xd5, 0x22, 0x3c, 0x40, 0xaf, 0xc8,
                0x25, 0xda, 0x5f, 0x6b, 0xb8, 0x63, 0x43, 0x1d, 0x2d, 0x6c, 0x14, 0x9a, 0xe4, 0x7c,
                0xce, 0xc7, 0x27, 0x1f, 0xc2, 0x77, 0xc0, 0x6e, 0x10, 0xfb, 0x79, 0x8b, 0x2e, 0x5a,
                0x25, 0x4e, 0x60, 0x41, 0xbb, 0xcf, 0x08, 0x92, 0x24, 0x98, 0x58, 0xec, 0xc5, 0xcc,
                0xd5, 0x61, 0xe0, 0x86, 0x3b, 0x9d, 0xad, 0x00, 0x58, 0x81, 0x33, 0x10, 0x17, 0x35,
                0x5c, 0x10, 0x66, 0x2b, 0x0d, 0x36, 0x18, 0x76, 0x92, 0x7b, 0xd4, 0xe9, 0x40, 0x22,
                0x92, 0x69, 0xea, 0xc3, 0x8f, 0xf2, 0x45, 0x36, 0xa3, 0xa5, 0x70, 0xcd, 0xb9, 0xc2,
                0x09, 0x02, 0x4b, 0x3f, 0xa1, 0x78, 0x54, 0xc1, 0xc3, 0xfd, 0xec, 0x97, 0x80, 0xac,
                0x4a, 0x83, 0x45, 0x35, 0x0d, 0x6d, 0x73, 0xb8, 0xe9, 0xa0, 0xf0, 0x44, 0x47, 0xa9,
                0xd2, 0xb9, 0x25, 0xd1, 0xb2, 0xda, 0xcb, 0x7a, 0x63, 0x2f, 0x46, 0xaf, 0x3e, 0x61,
                0x11, 0xfc, 0xe1, 0xfd, 0x88, 0xb4, 0xdb, 0x69, 0xd1, 0x19, 0x3f, 0x48, 0x67, 0x2a,
                0xe6, 0xf2, 0x4d, 0x1a, 0xdd, 0x8d, 0xab, 0xd1, 0x79, 0x12, 0xee, 0xb3, 0x21, 0xe8,
                0x91, 0xdb, 0x91, 0x47, 0xab, 0x0c, 0x5b, 0x68, 0x60, 0x1a, 0x05, 0x4d, 0xe0, 0xe8,
                0x66, 0x63, 0x3d, 0xe9, 0x35, 0xb0, 0x94, 0x66, 0x01, 0x5f, 0x21, 0x1a, 0x74, 0xc6,
                0x43, 0xce, 0xc1, 0xf8, 0x96, 0x51, 0x76, 0x20, 0xaa, 0x7b, 0x6e, 0xf0, 0x86, 0x47,
                0x41, 0x3c, 0x8a, 0xb1, 0x27, 0x07, 0x20, 0x34, 0xa7, 0xe7, 0x4a, 0x50, 0xed, 0x25,
                0xf2, 0xaf, 0xa6, 0x94, 0x72, 0xde, 0x0f, 0x43, 0x74, 0x22, 0x6d, 0x02, 0x7b, 0x6f,
                0x5a, 0xe8, 0x4a, 0x93, 0x98, 0xf3, 0xe2, 0xdb, 0xbc, 0x9f, 0xb1, 0x83, 0x92, 0x8b,
                0xba, 0x8b, 0xe0, 0xe4, 0x6b, 0x77, 0x0f, 0x35, 0xcb, 0x3f, 0x3e, 0xf5, 0x98, 0x37,
                0x99, 0xed, 0x79, 0xd8, 0x76, 0xdf, 0x13, 0x9e,
            ],
        );

        sig2.created = Some(
            DateTime::parse_from_rfc3339("2014-06-06T16:21:46Z")
                .expect("failed to parse static time")
                .with_timezone(&Utc),
        );

        sig2.key_flags = key_flags.clone();
        sig2.preferred_symmetric_algs = p_sym_algs.clone();
        sig2.preferred_compression_algs = p_com_algs.clone();
        sig2.preferred_hash_algs = p_hash_algs.clone();

        sig2.key_server_prefs = vec![128];
        sig2.features = vec![1];

        sig2.unhashed_subpackets.push(issuer.clone());

        let u2 = User::new("john doe <johndoe@seconddomain.com>", vec![sig2]);

        assert_eq!(key.users.len(), 2);
        assert_eq!(key.users[0], u1);
        assert_eq!(key.users[1], u2);
        assert_eq!(key.user_attributes.len(), 1);
        let ua = &key.user_attributes[0];
        match &ua.attr {
            &UserAttributeType::Image(ref v) => {
                assert_eq!(v.len(), 1156);
            }
            _ => panic!("not here"),
        }

        let mut sig3 = Signature::new(
            SignatureVersion::V4,
            SignatureType::CertPositive,
            PublicKeyAlgorithm::RSA,
            HashAlgorithm::SHA1,
            vec![0x02, 0x0c],
            vec![
                0x5b, 0x4b, 0xeb, 0xff, 0x1a, 0x89, 0xc2, 0xe1, 0x80, 0x20, 0x26, 0x3b, 0xf4, 0x4d,
                0x2d, 0x46, 0xba, 0x96, 0x78, 0xb2, 0x88, 0xf8, 0xf9, 0xd5, 0xf1, 0x5f, 0x7d, 0x45,
                0xeb, 0xbc, 0x25, 0x2e, 0x1b, 0x2f, 0x8e, 0xd4, 0xa9, 0x6e, 0x64, 0xfa, 0x97, 0x09,
                0xab, 0xd2, 0xab, 0x50, 0x04, 0x09, 0xa9, 0x33, 0x62, 0x00, 0xb8, 0x38, 0xf5, 0x53,
                0xb8, 0xe9, 0x43, 0xed, 0x59, 0x7f, 0x2f, 0xf9, 0x8f, 0xc7, 0xe1, 0xbb, 0x78, 0xdc,
                0xec, 0x12, 0x1a, 0xec, 0x17, 0x52, 0x86, 0xba, 0x2a, 0x1f, 0xd5, 0x2a, 0x99, 0x63,
                0x1c, 0x2f, 0x28, 0xa1, 0xb2, 0x9c, 0xb9, 0x76, 0x06, 0x06, 0x28, 0xc6, 0xe9, 0xbf,
                0xdb, 0x36, 0x87, 0xbe, 0x9e, 0xc7, 0x74, 0x7d, 0x4d, 0x5b, 0x10, 0x5c, 0x46, 0x65,
                0x20, 0x76, 0x0b, 0x5c, 0xc3, 0xe8, 0xe1, 0x55, 0xbb, 0xaf, 0x94, 0x6f, 0x44, 0x92,
                0xd5, 0xb5, 0x87, 0xc0, 0x42, 0x77, 0x5e, 0xc2, 0x04, 0x7e, 0x3d, 0x32, 0x60, 0x0f,
                0x26, 0x5c, 0x71, 0xd9, 0xaa, 0xa3, 0x2f, 0xe0, 0x65, 0xd3, 0xd2, 0xd0, 0x3e, 0x72,
                0xd3, 0x7c, 0xbe, 0x71, 0x94, 0xc3, 0xb5, 0x52, 0x1a, 0x9f, 0x72, 0x06, 0xb0, 0x0f,
                0xc9, 0xbb, 0x8a, 0xf3, 0xcf, 0xf6, 0x09, 0xd7, 0x63, 0x3d, 0x6b, 0x7c, 0xbc, 0x8b,
                0x05, 0x01, 0x1f, 0x22, 0x31, 0xf9, 0x8e, 0x53, 0xc8, 0xb8, 0x7b, 0x9e, 0x96, 0xc2,
                0xe5, 0x09, 0xac, 0xa5, 0xf4, 0xb8, 0xdb, 0xea, 0xdd, 0x79, 0x44, 0x17, 0x57, 0xa9,
                0x4d, 0xf5, 0xb9, 0x34, 0xcd, 0xc1, 0x3f, 0xeb, 0xe3, 0x6a, 0x80, 0x5c, 0xac, 0x83,
                0xcc, 0xf4, 0x7c, 0xbf, 0xac, 0xfd, 0x29, 0xee, 0x1f, 0x34, 0xc0, 0x4a, 0x08, 0x10,
                0x24, 0xe7, 0x04, 0x25, 0x3a, 0x7f, 0xff, 0x4b, 0x64, 0xc1, 0xf9, 0x7e, 0xc1, 0xb3,
                0xc1, 0x25, 0x0f, 0xf1, 0xb1, 0xf2, 0x66, 0x8d, 0x22, 0x8b, 0x56, 0x6f, 0x51, 0xf2,
                0xe4, 0x91, 0x5f, 0xc8, 0xc3, 0x55, 0xa2, 0xc8, 0x08, 0x1e, 0xd8, 0x4f, 0x07, 0x69,
                0x25, 0xb1, 0x96, 0xbb, 0x23, 0xe8, 0x7c, 0x5b, 0x4e, 0xe6, 0x0b, 0x32, 0x2b, 0x34,
                0xc1, 0x71, 0xee, 0x52, 0xbd, 0xf4, 0xf1, 0x67, 0x98, 0x57, 0xeb, 0x01, 0x32, 0x01,
                0x74, 0x49, 0xe5, 0xab, 0xfc, 0x79, 0xfe, 0x8a, 0x7c, 0xad, 0x95, 0xc9, 0xc2, 0x60,
                0x81, 0x2b, 0xf3, 0x45, 0x4b, 0x0b, 0xd0, 0xf4, 0xb1, 0x51, 0x75, 0x94, 0xe4, 0x6e,
                0xf0, 0x00, 0xb5, 0x51, 0xbd, 0x86, 0x74, 0xdb, 0xbe, 0xb9, 0xaa, 0x06, 0x70, 0x2a,
                0xd9, 0x6d, 0x69, 0x9f, 0xf1, 0x9a, 0x17, 0x64, 0xdd, 0x8e, 0xb4, 0xf8, 0x1a, 0x5a,
                0xbe, 0xdd, 0x0d, 0x78, 0x9d, 0x8c, 0x16, 0x7d, 0x99, 0xa6, 0xaf, 0xc5, 0x04, 0x3e,
                0xd7, 0x35, 0xe8, 0x1a, 0xc2, 0x6a, 0xce, 0x51, 0x38, 0x9a, 0x4c, 0x9c, 0x8b, 0xc3,
                0xaa, 0x48, 0x94, 0xda, 0x03, 0xae, 0xca, 0x93, 0x94, 0x70, 0x1a, 0x76, 0x02, 0x0d,
                0x21, 0x42, 0xe5, 0x7b, 0x9b, 0x4e, 0x59, 0x06, 0xd8, 0x72, 0xeb, 0xfe, 0x8d, 0x30,
                0xfc, 0x77, 0x67, 0x0c, 0x01, 0x46, 0xcf, 0x24, 0x19, 0x9c, 0x63, 0xe3, 0x8f, 0x35,
                0xc9, 0x53, 0x0c, 0x70, 0x55, 0x03, 0x3d, 0x67, 0x32, 0xfb, 0x86, 0xd0, 0x8b, 0x61,
                0x7f, 0x6f, 0xd4, 0xbc, 0xfd, 0xd6, 0x08, 0x4b, 0xee, 0xa1, 0x0c, 0x6c, 0x84, 0x3b,
                0xe1, 0xa8, 0x24, 0x87, 0x17, 0xa8, 0x67, 0xba, 0x03, 0xe7, 0xf7, 0xbb, 0xb4, 0x3d,
                0xbb, 0xa0, 0x5e, 0x76, 0xd6, 0x01, 0xe1, 0xa4, 0x9a, 0x14, 0x43, 0xcd, 0x99, 0xa0,
                0x2e, 0xa2, 0xda, 0x81, 0xe2, 0x9c, 0xab, 0x22, 0x41, 0x02, 0xcc, 0x2f, 0xca, 0xc5,
                0xf7, 0x26, 0x65, 0x7d, 0x0b, 0xcc, 0xab, 0x26,
            ],
        );

        sig3.key_flags = key_flags.clone();
        sig3.preferred_symmetric_algs = p_sym_algs.clone();
        sig3.preferred_compression_algs = p_com_algs.clone();
        sig3.preferred_hash_algs = p_hash_algs.clone();

        sig3.key_server_prefs = vec![128];
        sig3.features = vec![1];

        sig3.unhashed_subpackets.push(issuer.clone());

        sig3.created = Some(
            DateTime::parse_from_rfc3339("2014-06-06T16:05:43Z")
                .expect("failed to parse static time")
                .with_timezone(&Utc),
        );

        assert_eq!(ua.signatures, vec![sig3]);
    }
}

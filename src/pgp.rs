use nom::IResult;

use packet::{Packet, packet_parser};
use packet::types::Key;
use armor;

named!(packets_parser<Vec<Packet>>, many1!(packet_parser));

fn parse_key_raw<'a>(input: &'a [u8]) -> IResult<&'a [u8], armor::Block<'a>> {
    armor::parse(input).map(|(typ, headers, body)| {
        // TODO: Proper error handling
        let (_, packets) = packets_parser(body.as_slice()).unwrap();
        armor::Block {
            typ: typ,
            headers: headers,
            packets: packets,
        }
    })
}

// TODO: change to regular result
pub fn parse_key(input: &[u8]) -> IResult<&[u8], Key> {
    let block = parse_key_raw(input).to_result().expect("Invalid input");

    Key::from_block(block)
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet::types::{Signature, SignatureVersion, SignatureType, User, PublicKey, PrimaryKey,
                        KeyVersion, PublicKeyAlgorithm, HashAlgorithm, Subpacket,
                        SymmetricKeyAlgorithm, CompressionAlgorithm, UserAttributeType};
    use chrono::{DateTime, Utc};

    #[test]
    fn test_parse() {
        let raw = include_bytes!("../tests/opengpg-interop/testcases/keys/gnupg-v1-003.asc");
        let (_, key) = parse_key(raw).unwrap();

        // assert_eq!(key.primary_key.fingerprint(), "56c65c513a0d1b9cff532d784c073ae0c8445c0c");

        match key.primary_key {
            PrimaryKey::PublicKey(PublicKey::RSAPublicKey {
                                      version,
                                      algorithm,
                                      e,
                                      n,
                                  }) => {
                assert_eq!(version, KeyVersion::V4);
                assert_eq!(algorithm, PublicKeyAlgorithm::RSA);
                assert_eq!(n.len(), 512);
                assert_eq!(e, vec![1, 0, 1]);
            }
            _ => panic!("wrong key returned: {:?}", key.primary_key),
        }

        let mut sig1 = Signature::new(
            SignatureVersion::V4,
            SignatureType::CertPositive,
            PublicKeyAlgorithm::RSA,
            HashAlgorithm::SHA1,
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
            _ => panic!("invalid type {:?}", ua),
        }

        let mut sig3 = Signature::new(
            SignatureVersion::V4,
            SignatureType::CertPositive,
            PublicKeyAlgorithm::RSA,
            HashAlgorithm::SHA1,
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

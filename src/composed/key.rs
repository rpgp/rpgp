use errors::Result;
use packet::types;
use packet::types::key::KeyID;

// TODO: can detect armored vs binary using a check if the first bit in the data is set. If it is cleared it is not a binary message, so can try to parse as armor ascii. (from gnupg source)

// TODO: make armor parsing streaming
// TODO: rename armor parser to dearmor

/// Represents a Public PGP key.
#[derive(Debug, PartialEq, Eq)]
pub struct PublicKey {
    pub primary_key: types::key::PublicKey,
    pub revocation_signatures: Vec<types::Signature>,
    pub direct_signatures: Vec<types::Signature>,
    pub users: Vec<types::User>,
    pub user_attributes: Vec<types::UserAttribute>,
    pub subkeys: Vec<PublicSubKey>,
}

impl PublicKey {
    pub fn new(
        primary_key: types::key::PublicKey,
        revocation_signatures: Vec<types::Signature>,
        direct_signatures: Vec<types::Signature>,
        users: Vec<types::User>,
        user_attributes: Vec<types::UserAttribute>,
        subkeys: Vec<PublicSubKey>,
    ) -> PublicKey {
        PublicKey {
            primary_key,
            revocation_signatures,
            direct_signatures,
            users,
            user_attributes,
            subkeys,
        }
    }

    /// Returns the fingerprint of the associated primary key.
    pub fn fingerprint(&self) -> Vec<u8> {
        self.primary_key.fingerprint()
    }

    /// Returns the Key ID of the associated primary key.
    pub fn key_id(&self) -> Option<KeyID> {
        self.primary_key.key_id()
    }
}

/// Represents a Public PGP SubKey.
#[derive(Debug, PartialEq, Eq)]
pub struct PublicSubKey {
    pub key: types::key::PublicKey,
    pub signatures: Vec<types::Signature>,
}

impl PublicSubKey {
    pub fn new(key: types::key::PublicKey, signatures: Vec<types::Signature>) -> PublicSubKey {
        PublicSubKey { key, signatures }
    }

    /// Returns the fingerprint of the key.
    pub fn fingerprint(&self) -> Vec<u8> {
        self.key.fingerprint()
    }

    /// Returns the Key ID of the key.
    pub fn key_id(&self) -> Option<KeyID> {
        self.key.key_id()
    }
}

/// Represents a Private PGP key.
#[derive(Debug, PartialEq, Eq)]
pub struct PrivateKey {
    pub primary_key: types::key::PrivateKey,
    pub revocation_signatures: Vec<types::Signature>,
    pub direct_signatures: Vec<types::Signature>,
    pub users: Vec<types::User>,
    pub user_attributes: Vec<types::UserAttribute>,
    pub subkeys: Vec<PrivateSubKey>,
}

impl PrivateKey {
    pub fn new(
        primary_key: types::key::PrivateKey,
        revocation_signatures: Vec<types::Signature>,
        direct_signatures: Vec<types::Signature>,
        users: Vec<types::User>,
        user_attributes: Vec<types::UserAttribute>,
        subkeys: Vec<PrivateSubKey>,
    ) -> PrivateKey {
        PrivateKey {
            primary_key,
            revocation_signatures,
            direct_signatures,
            users,
            user_attributes,
            subkeys,
        }
    }

    /// Returns the fingerprint of the associated primary key.
    pub fn fingerprint(&self) -> Vec<u8> {
        self.primary_key.fingerprint()
    }

    /// Returns the Key ID of the associated primary key.
    pub fn key_id(&self) -> Option<KeyID> {
        self.primary_key.key_id()
    }

    pub fn unlock<F, G>(&self, pw: F, work: G) -> Result<()>
    where
        F: FnOnce() -> String,
        G: FnOnce(&types::key::PrivateKeyRepr) -> Result<()>,
    {
        self.primary_key.unlock(pw, work)
    }
}

/// Represents a composed private PGP SubKey.
#[derive(Debug, PartialEq, Eq)]
pub struct PrivateSubKey {
    pub key: types::key::PrivateKey,
    pub signatures: Vec<types::Signature>,
}

impl PrivateSubKey {
    pub fn new(key: types::key::PrivateKey, signatures: Vec<types::Signature>) -> PrivateSubKey {
        PrivateSubKey { key, signatures }
    }

    /// Returns the fingerprint of the key.
    pub fn fingerprint(&self) -> Vec<u8> {
        self.key.fingerprint()
    }

    /// Returns the Key ID of the key.
    pub fn key_id(&self) -> Option<KeyID> {
        self.key.key_id()
    }

    pub fn unlock<F, G>(&self, pw: F, work: G) -> Result<()>
    where
        F: FnOnce() -> String,
        G: FnOnce(&types::key::PrivateKeyRepr) -> Result<()>,
    {
        self.key.unlock(pw, work)
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Read;
    use std::path::{Path, PathBuf};

    use super::*;

    use chrono::{DateTime, Utc};
    use hex;
    use num_bigint::BigUint;
    use num_traits::cast::ToPrimitive;
    use rand::thread_rng;
    use rsa::padding::PaddingScheme;
    use rsa::{PublicKey as PublicKeyTrait, RSAPrivateKey, RSAPublicKey};
    use serde_json;

    use composed::Deserializable;
    use crypto::hash::HashAlgorithm;
    use crypto::sym::SymmetricKeyAlgorithm;
    use packet::types::key;
    use packet::types::{
        CompressionAlgorithm, KeyVersion, PublicKeyAlgorithm, Signature, SignatureType,
        SignatureVersion, StringToKeyType, Subpacket, User, UserAttributeType,
    };

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
        PublicKey::from_bytes_many(f).unwrap();
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
            PublicKey::from_string(input).expect("failed to parse key");
        }
    }

    #[test]
    fn test_parse_openpgp_sample_rsa_private() {
        let p = Path::new("./tests/openpgp/samplekeys/rsa-primary-auth-only.sec.asc");
        let mut file = read_file(p.to_path_buf());

        let mut buf = vec![];
        file.read_to_end(&mut buf).unwrap();

        let input = ::std::str::from_utf8(buf.as_slice()).expect("failed to convert to string");
        let key = PrivateKey::from_string(input).expect("failed to parse key");

        let pkey = key.primary_key;
        assert_eq!(pkey.version(), &KeyVersion::V4);
        assert_eq!(pkey.algorithm(), &PublicKeyAlgorithm::RSA);

        assert_eq!(
            pkey.private_params().checksum,
            Some(hex::decode("2c46").unwrap())
        );

        pkey.unlock(
            || "".to_string(),
            |unlocked_key| {
                match unlocked_key {
                    types::key::PrivateKeyRepr::RSA(k) => {
                        assert_eq!(k.d().bits(), 2044);
                        assert_eq!(k.primes()[0].bits(), 1024);
                        assert_eq!(k.primes()[1].bits(), 1024);

                        // test basic encrypt decrypt
                        let plaintext = vec![2u8; 128];
                        let mut rng = thread_rng();

                        let ciphertext = {
                            // TODO: fix this in rust-rsa
                            let k: RSAPrivateKey = k.clone();
                            let pk: RSAPublicKey = k.into();
                            pk.encrypt(&mut rng, PaddingScheme::PKCS1v15, plaintext.as_slice())
                                .unwrap()
                        };

                        let new_plaintext = k
                            .decrypt(PaddingScheme::PKCS1v15, ciphertext.as_slice())
                            .unwrap();
                        assert_eq!(plaintext, new_plaintext);
                    }
                    _ => panic!("unexpected params type {:?}", unlocked_key),
                }
                Ok(())
            },
        )
        .unwrap();
    }

    #[test]
    fn test_parse_details() {
        let file = File::open("./tests/opengpg-interop/testcases/keys/gnupg-v1-003.asc").unwrap();
        let key = PublicKey::from_armor_single(file).expect("failed to parse key");

        assert_eq!(
            hex::encode(key.primary_key.fingerprint()),
            "56c65c513a0d1b9cff532d784c073ae0c8445c0c"
        );

        assert_eq!(
            key.primary_key.key_id().unwrap().to_vec(),
            hex::decode("4c073ae0c8445c0c").unwrap().to_vec()
        );

        let primary_n = BigUint::from_bytes_be(hex::decode("a54cfa9142fb75265322055b11f750f49af37b64c67ad830ed7443d6c20477b0492ee9090e4cb8b0c2c5d49e87dff5ac801b1aaadb319eee9d3d29b25bd9aa634b126c0e5da4e66b414e9dbdde5dea0e38c5bfe7e5f7fdb9f4c1b1f39ed892dd4e0873a0df66ff46fd9236d291c276ce69fb972f5ef24746b6794a0f70e0694667b9de57353330c732733cc6d5f24cd772c5c7d5bdb77dc0a5b6e9d3ee0372146778cda6144976e33066fc57bfb515ef397b3aa882c0bde02d19f7a32df7b1195cb0f32e6e7455ac199fa434355f0fa43230e5237e9a6e0ff6ad5b21b4d892c6fc3842788ba48b020ee85edd135cff2808780e834b5d94cc2c2b5fa747167a20814589d7f030ee9f8a669737bdb063e6b0b88ab0fd7454c03f69678a1dd99442cfd0bf620bc5b6896cd6e2b51fdecf54c7e6368c11c70f302444ec9d5a17ceaacb4a9ac3c37db3478f8fb04a679f0957a3697e8d90152008927c751b34160c72e757efc85053dd86738931fd351cf134266e436efd64a14b35869040108082847f7f5215628e7f66513809ae0f66ea73d01f5fd965142cdb7860276d4c20faf716c40ae0632d3b180137438cb95257327607038fb3b82f76556e8dd186b77c2f51b0bfdd7552f168f2c4eb90844fdc05cf239a57690225903399783ad3736891edb87745a1180e04741526384045c2de03c463c43b27d5ab7ffd6d0ecccc249f").unwrap().to_vec().as_slice());

        let pk = key.primary_key;
        assert_eq!(pk.version(), &KeyVersion::V4);
        assert_eq!(pk.algorithm(), &PublicKeyAlgorithm::RSA);

        match pk.public_params() {
            key::PublicParams::RSA { n, e } => {
                assert_eq!(n, &primary_n);
                assert_eq!(e.to_u64().unwrap(), 0x010001);
            }
            _ => panic!("wrong public params: {:?}", pk.public_params()),
        }

        assert_eq!(pk.created_at(), 1402070261);
        assert_eq!(pk.expiration(), None);

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

    #[test]
    fn encrypted_private_key() {
        let p = Path::new("./tests/opengpg-interop/testcases/messages/gnupg-v1-001-decrypt.asc");
        let mut file = read_file(p.to_path_buf());

        let mut buf = vec![];
        file.read_to_end(&mut buf).unwrap();

        let input = ::std::str::from_utf8(buf.as_slice()).expect("failed to convert to string");
        let key = PrivateKey::from_string(input).expect("failed to parse key");

        let pp = key.primary_key.private_params().clone();

        assert_eq!(
            pp.iv,
            Some(
                hex::decode("2271f718af70d3bd9d60c2aed9469b67")
                    .unwrap()
                    .to_vec()
            )
        );

        assert_eq!(
            pp.string_to_key_salt,
            Some(hex::decode("CB18E77884F2F055").unwrap().to_vec())
        );

        assert_eq!(pp.string_to_key, Some(StringToKeyType::IteratedAndSalted));

        assert_eq!(pp.string_to_key_count, Some(65536));

        assert_eq!(pp.string_to_key_hash, Some(HashAlgorithm::SHA256));

        assert_eq!(pp.encryption_algorithm, Some(SymmetricKeyAlgorithm::AES128));
        assert_eq!(pp.string_to_key_id, 254);

        key.unlock(
            || "test".to_string(),
            |k| {
                println!("{:?}", k);
                match k {
                    types::key::PrivateKeyRepr::RSA(k) => {
                        assert_eq!(k.e().to_bytes_be(), hex::decode("010001").unwrap().to_vec());
                        assert_eq!(k.n().to_bytes_be(), hex::decode("9AF89C08A8EA84B5363268BAC8A06821194163CBCEEED2D921F5F3BDD192528911C7B1E515DCE8865409E161DBBBD8A4688C56C1E7DFCF639D9623E3175B1BCA86B1D12AE4E4FBF9A5B7D5493F468DA744F4ACFC4D13AD2D83398FFC20D7DF02DF82F3BC05F92EDC41B3C478638A053726586AAAC57E2B66C04F9775716A0C71").unwrap().to_vec());
                        assert_eq!(k.d().to_bytes_be(), hex::decode("33DE47E3421E1442CE9BFA9FA1ACC68D657594604FA7719CC91817F78D604B0DA38CD206D9D571621C589E3DF19CA2BB0C5F045EAC2C25AEB2BCE0D00E2E29538F8239F8A499EAF872497809E524A9EDA88E7ECEE78DF722E33DD62C9E204FE0F90DCF6F4247D1F7C8CE3BB3F0A4BAB23CFD95D41BC8A39C22C99D5BC38BC51D").unwrap().to_vec());
                        assert_eq!(k.primes()[0].to_bytes_be(), hex::decode("C62B8CD033331BFF171188C483B5B87E41A84415A004A83A4109014A671A5A3DA0A467CDB786F0BB75354245DA0DFFF53B6E25A44E28CBFF8CC1AC58A968AF57").unwrap().to_vec());
                       assert_eq!(k.primes()[1].to_bytes_be(), hex::decode("C831D89F49E642383C115413B2CB5F6EC09012B50C1E8596877E8F7B88C82C8F14FC354C21B6032BEF78B3C5EC92E434BEB2436B12C7C9FEDEFD866678DBED77").unwrap().to_vec());
                    }
                    _ => panic!("wrong key format"),
                }
                Ok(())
            },
        ).unwrap();
    }

    fn get_test_fingerprint(filename: &str) -> (serde_json::Value, PublicKey) {
        let mut asc = read_file(
            Path::new(&format!(
                "./tests/opengpg-interop/testcases/keys/{}.asc",
                filename
            ))
            .to_path_buf(),
        );
        let json_file = read_file(
            Path::new(&format!(
                "./tests/opengpg-interop/testcases/keys/{}.json",
                filename
            ))
            .to_path_buf(),
        );

        let mut asc_string = String::new();
        asc.read_to_string(&mut asc_string).unwrap();
        let key = PublicKey::from_string(&asc_string).unwrap();

        let json: serde_json::Value = serde_json::from_reader(json_file).unwrap();

        (json, key)
    }

    #[test]
    fn test_fingerprint_rsa() {
        let (json, key) = get_test_fingerprint("gnupg-v1-003");

        assert_eq!(json["expected_fingerprint"], hex::encode(key.fingerprint()));
    }

    #[test]
    fn test_fingerprint_dsa() {
        let (json, key) = get_test_fingerprint("gnupg-v1-001");

        assert_eq!(json["expected_fingerprint"], hex::encode(key.fingerprint()));
    }

    #[test]
    fn test_fingerprint_ecdsa() {
        let (json, key) = get_test_fingerprint("e2e-001");

        assert_eq!(json["expected_fingerprint"], hex::encode(key.fingerprint()));
    }

    #[test]
    fn test_fingerprint_ecdh() {
        let (json, key) = get_test_fingerprint("gnupg-v1-001");

        assert_eq!(
            json["expected_subkeys"].as_array().unwrap()[0]
                .as_object()
                .unwrap()["expected_fingerprint"],
            hex::encode(key.subkeys[0].key.fingerprint())
        );

        let (json, key) = get_test_fingerprint("e2e-001");

        assert_eq!(
            json["expected_subkeys"].as_array().unwrap()[0]
                .as_object()
                .unwrap()["expected_fingerprint"],
            hex::encode(key.subkeys[0].key.fingerprint())
        );
    }

    #[test]
    fn test_fingerprint_elgamel() {
        let (json, key) = get_test_fingerprint("gnupg-v1-001");

        assert_eq!(
            json["expected_subkeys"].as_array().unwrap()[0]
                .as_object()
                .unwrap()["expected_fingerprint"],
            hex::encode(key.subkeys[0].key.fingerprint())
        );
    }

    fn test_parse_openpgp_key(key: &str) {
        let f = read_file(Path::new("./tests/openpgp/").join(key));
        PublicKey::from_armor_many(f).expect(&format!("failed to parse {}", key));
    }

    fn test_parse_openpgp_key_bin(key: &str) {
        let f = read_file(Path::new("./tests/openpgp/").join(key));
        PublicKey::from_bytes_many(f).expect(&format!("failed to parse {}", key));
    }

    macro_rules! openpgp_key_bin {
        ($name:ident, $path:expr) => {
            #[test]
            fn $name() {
                test_parse_openpgp_key_bin($path);
            }
        };
    }

    macro_rules! openpgp_key {
        ($name:ident, $path:expr) => {
            #[test]
            fn $name() {
                test_parse_openpgp_key($path);
            }
        };
    }

    openpgp_key!(
        key_openpgp_samplekeys_e6,
        "samplekeys/E657FB607BB4F21C90BB6651BC067AF28BC90111.asc"
    );
    openpgp_key!(
        key_openpgp_samplekeys_authenticate_only_pub,
        "samplekeys/authenticate-only.pub.asc"
    );
    openpgp_key!(
        key_openpgp_samplekeys_authenticate_only_sec,
        "samplekeys/authenticate-only.sec.asc"
    );
    openpgp_key!(
        key_openpgp_samplekeys_dda252ebb8ebe1af_1,
        "samplekeys/dda252ebb8ebe1af-1.asc"
    );
    openpgp_key!(
        key_openpgp_samplekeys_dda252ebb8ebe1af_2,
        "samplekeys/dda252ebb8ebe1af-2.asc"
    );
    openpgp_key!(
        key_openpgp_samplekeys_e2e_p256_1_clr,
        "samplekeys/e2e-p256-1-clr.asc"
    );
    openpgp_key!(
        key_openpgp_samplekeys_e2e_p256_1_prt,
        "samplekeys/e2e-p256-1-prt.asc"
    );
    openpgp_key!(
        key_openpgp_samplekeys_ecc_sample_1_pub,
        "samplekeys/ecc-sample-1-pub.asc"
    );
    openpgp_key!(
        key_openpgp_samplekeys_ecc_sample_1_sec,
        "samplekeys/ecc-sample-1-sec.asc"
    );
    openpgp_key!(
        key_openpgp_samplekeys_ecc_sample_2_pub,
        "samplekeys/ecc-sample-2-pub.asc"
    );
    openpgp_key!(
        key_openpgp_samplekeys_ecc_sample_2_sec,
        "samplekeys/ecc-sample-2-sec.asc"
    );
    openpgp_key!(
        key_openpgp_samplekeys_ecc_sample_3_pub,
        "samplekeys/ecc-sample-3-pub.asc"
    );
    openpgp_key!(
        key_openpgp_samplekeys_ecc_sample_3_sec,
        "samplekeys/ecc-sample-3-sec.asc"
    );
    openpgp_key!(
        key_openpgp_samplekeys_ed25519_cv25519_sample_1,
        "samplekeys/ed25519-cv25519-sample-1.asc"
    );
    openpgp_key!(
        key_openpgp_samplekeys_eddsa_sample_1_pub,
        "samplekeys/eddsa-sample-1-pub.asc"
    );
    openpgp_key!(
        key_openpgp_samplekeys_eddsa_sample_1_sec,
        "samplekeys/eddsa-sample-1-sec.asc"
    );
    openpgp_key!(key_openpgp_samplekeys_issue2346, "samplekeys/issue2346.gpg");
    openpgp_key_bin!(
        key_openpgp_samplekeys_no_creation_time,
        "samplekeys/no-creation-time.gpg"
    );
    openpgp_key!(
        key_openpgp_samplekeys_rsa_primary_auth_only_pub,
        "samplekeys/rsa-primary-auth-only.pub.asc"
    );
    openpgp_key!(
        key_openpgp_samplekeys_rsa_primary_auth_only_sec,
        "samplekeys/rsa-primary-auth-only.sec.asc"
    );
    openpgp_key!(
        key_openpgp_samplekeys_rsa_rsa_sample_1,
        "samplekeys/rsa-rsa-sample-1.asc"
    );
    openpgp_key!(
        key_openpgp_samplekeys_silent_running,
        "samplekeys/silent-running.asc"
    );

    // PKCS#1
    // openpgp_key!(key_openpgp_samplekeys_ssh_dsa, "samplekeys/ssh-dsa.key");

    // PKCS#1
    // openpgp_key!(key_openpgp_samplekeys_ssh_ecdsa, "samplekeys/ssh-ecdsa.key");

    // OpenSSH
    // openpgp_key!(
    //     key_openpgp_samplekeys_ssh_ed25519,
    //     "samplekeys/ssh-ed25519.key"
    // );

    // PKCS#1
    // openpgp_key!(key_openpgp_samplekeys_ssh_rsa, "samplekeys/ssh-rsa.key");

    openpgp_key!(
        key_openpgp_samplekeys_whats_new_in_2_1,
        "samplekeys/whats-new-in-2.1.asc"
    );

    #[test]
    #[ignore] // Not implemented yet
    fn private_x25519_verify() {
        let f = read_file(Path::new("./tests/openpgpjs/x25519.sec.asc").to_path_buf());
        let sk = PrivateKey::from_armor_single(f).expect("failed to parse key");
        assert_eq!(sk.subkeys.len(), 1);

        sk.unlock(
            || "moon".to_string(),
            |k| {
                match k {
                    types::key::PrivateKeyRepr::ECDH(ref inner_key) => {
                        assert_eq!(inner_key.hash, HashAlgorithm::SHA256);
                    }
                    _ => panic!("invalid key"),
                }
                Ok(())
            },
        )
        .unwrap();
    }
}

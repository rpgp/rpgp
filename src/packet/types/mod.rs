use nom::IResult;
use armor;

mod pubkey;

enum_from_primitive!{
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum KeyVersion {
    V2 = 2,
    V3 = 3,
    V4 = 4,
}
}

enum_from_primitive!{
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PublicKeyAlgorithm {
    /// RSA (Encrypt and Sign) [HAC]
    RSA = 1,
    /// DEPRECATED: RSA (Encrypt-Only) [HAC]
    RSAEncrypt = 2,
    /// DEPRECATED: RSA (Sign-Only) [HAC]
    RSASign = 3,
    /// Elgamal (Encrypt-Only) [ELGAMAL] [HAC]
    ELSign = 16,
    /// DSA (Digital Signature Algorithm) [FIPS186] [HAC]
    DSA = 17,
    /// RESERVED: Elliptic Curve
    EC = 18,
    /// RESERVED: ECDSA
    ECDSA = 19,
    /// DEPRECATED: Elgamal (Encrypt and Sign)
    EL = 20,
    /// Reserved for Diffie-Hellman (X9.42, as defined for IETF-S/MIME)
    DiffieHellman = 21,
}
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PrimaryKey {
    PublicKey {
        version: KeyVersion,
        algorithm: PublicKeyAlgorithm,
        n: Vec<u8>,
        e: Vec<u8>,
    },
    SecretKey {
        version: KeyVersion,
        algorithm: PublicKeyAlgorithm,
    },
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Key {
    pub primary_key: PrimaryKey,
    // pub revocation_signature:
    // pub direct_signatures: Vec<>
    // pub users: Vec<>
    // pub subkeys: Vec<>
}

impl Key {
    /// Parse a raw armor block
    pub fn from_block(block: armor::Block) -> IResult<&[u8], Self> {
        match block.typ {
            armor::BlockType::PublicKey => pubkey::parse(block.packets),
            _ => unimplemented!(),
        }
    }
}

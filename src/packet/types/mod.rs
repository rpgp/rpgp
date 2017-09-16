use nom::IResult;
use armor;

mod pubkey;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PrimaryKey {
    PublicKey { n: Vec<u8>, e: Vec<u8> },
    SecretKey {},
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

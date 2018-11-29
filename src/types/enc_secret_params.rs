use std::io;

use crypto::sym::SymmetricKeyAlgorithm;
use errors::Result;
use ser::Serialize;
use types::StringToKey;
use util::{write_bignum_mpi, write_mpi};

/// A list of params that are used to represent the values of possibly encrypted key, from imports and exports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedSecretParams {
    /// The raw data as generated when imported.
    pub data: Vec<u8>,
    /// Hash or checksum of the raw data.
    pub checksum: Option<Vec<u8>>,
    /// IV, exist encrypted raw data.
    pub iv: Option<Vec<u8>>,
    /// If raw is encrypted, the encryption algorithm used.
    pub encryption_algorithm: Option<SymmetricKeyAlgorithm>,
    /// If raw is encrypted, the string-to-key method and its parameters.
    pub string_to_key: Option<StringToKey>,
    /// The identifier for how this data is stored.
    pub string_to_key_id: u8,
}

impl EncryptedSecretParams {
    pub fn new_plaintext(data: Vec<u8>, checksum: Option<Vec<u8>>) -> EncryptedSecretParams {
        EncryptedSecretParams {
            data,
            checksum,
            iv: None,
            encryption_algorithm: None,
            string_to_key: None,
            string_to_key_id: 0,
        }
    }

    pub fn is_encrypted(&self) -> bool {
        self.string_to_key_id != 0
    }
}

impl Serialize for EncryptedSecretParams {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        // TODO:
        // s2k typ
        // enc_params
        // data
        // checksum

        Ok(())
    }
}

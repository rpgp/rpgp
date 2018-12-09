use std::{fmt, io};

use crypto::sym::SymmetricKeyAlgorithm;
use errors::Result;
use ser::Serialize;
use types::StringToKey;

/// A list of params that are used to represent the values of possibly encrypted key, from imports and exports.
#[derive(Clone, PartialEq, Eq)]
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
        writer.write_all(&[self.string_to_key_id])?;
        match self.string_to_key_id {
            0 => {}
            1...253 => {
                writer.write_all(self.iv.as_ref().expect("inconsistent string to key id"))?;
            }
            254...255 => {
                let s2k = self
                    .string_to_key
                    .as_ref()
                    .expect("inconsistent string to key id");

                writer.write_all(&[self
                    .encryption_algorithm
                    .expect("inconsistent string to key id")
                    as u8])?;
                s2k.to_writer(writer)?;
                writer.write_all(self.iv.as_ref().expect("inconsistent string to key id"))?;
            }
            _ => unreachable!("this is a u8"),
        }

        writer.write_all(&self.data)?;

        if let Some(ref checksum) = self.checksum {
            writer.write_all(checksum)?;
        }

        Ok(())
    }
}

impl fmt::Debug for EncryptedSecretParams {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("EncryptedSecretParams")
            .field("data", &hex::encode(&self.data))
            .field("checksum", &self.checksum.as_ref().map(hex::encode))
            .field("iv", &self.iv.as_ref().map(hex::encode))
            .field("encryption_algorithm", &self.encryption_algorithm)
            .field("string_to_key", &self.string_to_key)
            .field("string_to_key_id", &self.string_to_key_id)
            .finish()
    }
}

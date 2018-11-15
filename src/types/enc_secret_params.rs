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
    /// If raw is encrypted, the string-to-key method used.
    pub string_to_key: Option<StringToKeyType>,
    /// If raw is encrypted, the hash algorithm for the s2k method.
    pub string_to_key_hash: Option<HashAlgorithm>,
    /// If raw is encrypted, and a salt is used the salt for the s2k method.
    pub string_to_key_salt: Option<Vec<u8>>,
    /// If raw is encrypted, and a count is used the hash algorithm for the s2k method.
    pub string_to_key_count: Option<usize>,
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
            string_to_key_hash: None,
            string_to_key_salt: None,
            string_to_key_count: None,
        }
    }

    pub fn is_encrypted(&self) -> bool {
        self.string_to_key_id != 0
    }
}

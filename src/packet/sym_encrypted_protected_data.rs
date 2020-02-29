use std::{fmt, io};

use crate::crypto::SymmetricKeyAlgorithm;
use crate::errors::Result;
use crate::packet::PacketTrait;
use crate::ser::Serialize;
use crate::types::{Tag, Version};
use rand::{thread_rng, CryptoRng, Rng};

/// Symmetrically Encrypted Integrity Protected Data Packet
/// https://tools.ietf.org/html/rfc4880.html#section-5.12
#[derive(Clone, PartialEq, Eq)]
pub struct SymEncryptedProtectedData {
    packet_version: Version,
    data: Vec<u8>,
}

impl SymEncryptedProtectedData {
    /// Parses a `SymEncryptedData` packet from the given slice.
    pub fn from_slice(packet_version: Version, input: &[u8]) -> Result<Self> {
        ensure!(input.len() > 1, "invalid input length");
        ensure_eq!(input[0], 0x01, "first bytes must be 0x01");

        Ok(SymEncryptedProtectedData {
            data: input[1..].to_vec(),
            packet_version,
        })
    }

    /// Encrypts the data using the given symmetric key.
    pub fn encrypt_with_rng<R: CryptoRng + Rng>(
        rng: &mut R,
        alg: SymmetricKeyAlgorithm,
        key: &[u8],
        plaintext: &[u8],
    ) -> Result<Self> {
        let data = alg.encrypt_protected_with_rng(rng, key, plaintext)?;

        Ok(SymEncryptedProtectedData {
            packet_version: Default::default(),
            data,
        })
    }

    /// Same as [`encrypt_with_rng`], but uses [`thread_rng`] for RNG.
    ///
    /// [`encrypt_with_rng`]: SymEncryptedProtectedData::encrypt_with_rng
    /// [`thread_rng`]: rand::thread_rng
    pub fn encrypt(alg: SymmetricKeyAlgorithm, key: &[u8], plaintext: &[u8]) -> Result<Self> {
        Self::encrypt_with_rng(&mut thread_rng(), alg, key, plaintext)
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

impl Serialize for SymEncryptedProtectedData {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&[0x01])?;
        writer.write_all(&self.data)?;

        Ok(())
    }
}

impl PacketTrait for SymEncryptedProtectedData {
    fn packet_version(&self) -> Version {
        self.packet_version
    }

    fn tag(&self) -> Tag {
        Tag::SymEncryptedProtectedData
    }
}

impl fmt::Debug for SymEncryptedProtectedData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SymEncryptedProtectedData")
            .field("packet_version", &self.packet_version)
            .field("data", &hex::encode(&self.data))
            .finish()
    }
}

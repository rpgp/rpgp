use std::{fmt, io};

use nom::number::streaming::be_u8;
use rand::{thread_rng, CryptoRng, Rng};

use crate::crypto::aead::AeadAlgorithm;
use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::errors::{Error, IResult, Result};
use crate::packet::PacketTrait;
use crate::ser::Serialize;
use crate::types::{Tag, Version};

/// Symmetrically Encrypted Integrity Protected Data Packet
/// https://tools.ietf.org/html/rfc4880.html#section-5.12
#[derive(Clone, PartialEq, Eq)]
pub struct SymEncryptedProtectedData {
    packet_version: Version,
    data: Data,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Data {
    V1 {
        data: Vec<u8>,
    },
    V2 {
        sym_alg: SymmetricKeyAlgorithm,
        aead: AeadAlgorithm,
        chunk_size: u8,
        salt: [u8; 32],
        data: Vec<u8>,
        auth_tag: Vec<u8>,
    },
}

impl SymEncryptedProtectedData {
    /// Parses a `SymEncryptedData` packet from the given slice.
    pub fn from_slice(packet_version: Version, input: &[u8]) -> Result<Self> {
        ensure!(input.len() > 1, "invalid input length");
        let (_, data) = parse()(input)?;

        Ok(SymEncryptedProtectedData {
            data,
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
            data: Data::V1 { data },
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
        match &self.data {
            Data::V1 { data } => &data,
            Data::V2 { data, .. } => &data,
        }
    }
}

impl Serialize for SymEncryptedProtectedData {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&[0x01])?;

        match &self.data {
            Data::V1 { data } => {
                writer.write_all(&data)?;
            }
            Data::V2 { .. } => {
                todo!()
            }
        }
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
            .field("data", &self.data)
            .finish()
    }
}

fn parse() -> impl Fn(&[u8]) -> IResult<&[u8], Data> {
    move |i: &[u8]| {
        let (i, version) = be_u8(i)?;
        match version {
            0x01 => Ok((&[][..], Data::V1 { data: i.to_vec() })),
            0x02 => {
                todo!()
            }
            _ => {
                return Err(nom::Err::Error(Error::Unsupported(format!(
                    "unknown SymEncryptedProtecedData version {}",
                    version
                ))))
            }
        }
    }
}

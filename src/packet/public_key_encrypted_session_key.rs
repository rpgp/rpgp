use std::{fmt, io};

use nom::be_u8;
use num_traits::FromPrimitive;

use crypto::public_key::PublicKeyAlgorithm;
use errors::Result;
use packet::PacketTrait;
use ser::Serialize;
use types::{KeyId, Tag, Version};
use util::{mpi, write_mpi};

/// Public Key Encrypted Session Key Packet
/// https://tools.ietf.org/html/rfc4880.html#section-5.1
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKeyEncryptedSessionKey {
    packet_version: Version,
    version: u8,
    id: KeyId,
    algorithm: PublicKeyAlgorithm,
    mpis: Vec<Vec<u8>>,
}

impl PublicKeyEncryptedSessionKey {
    /// Parses a `PublicKeyEncryptedSessionKey` packet from the given slice.
    pub fn from_slice(version: Version, input: &[u8]) -> Result<Self> {
        let (_, pk) = parse(input, version)?;

        ensure_eq!(pk.version, 3, "invalid version");

        Ok(pk)
    }

    pub fn id(&self) -> &KeyId {
        &self.id
    }

    pub fn mpis(&self) -> &[Vec<u8>] {
        &self.mpis
    }

    pub fn packet_version(&self) -> Version {
        self.packet_version
    }
}

#[rustfmt::skip]
named_args!(parse_mpis<'a>(alg: &'a PublicKeyAlgorithm) <Vec<Vec<u8>>>, switch!(
    value!(alg),
    &PublicKeyAlgorithm::RSA |
    &PublicKeyAlgorithm::RSASign |
    &PublicKeyAlgorithm::RSAEncrypt => map!(mpi, |v| vec![v.to_vec()]) |
    &PublicKeyAlgorithm::Elgamal |
    &PublicKeyAlgorithm::ElgamalSign => do_parse!(
          first: mpi
      >> second: mpi
      >> (vec![first.to_vec(), second.to_vec()])
    ) |
    &PublicKeyAlgorithm::ECDSA |
    &PublicKeyAlgorithm::DSA |
    &PublicKeyAlgorithm::DiffieHellman => value!(Vec::new())|
    &PublicKeyAlgorithm::ECDH => do_parse!(
           a: mpi
        >> blen: be_u8
        >> b: take!(blen)
        >> ({
            vec![a.to_vec(), b.to_vec()]
        })
    )
));

/// Parses a Public-Key Encrypted Session Key Packets
#[rustfmt::skip]
named_args!(parse(packet_version: Version) <PublicKeyEncryptedSessionKey>, do_parse!(
    // version, only 3 is allowed
       version: be_u8
    // the key id this maps to
    >>     id: map_res!(take!(8), KeyId::from_slice)
    // the symmetric key algorithm
    >>    alg: map_opt!(be_u8, PublicKeyAlgorithm::from_u8)
    // key algorithm specific data
    >>   mpis: call!(parse_mpis, &alg)
    >> (PublicKeyEncryptedSessionKey {
        packet_version,
        version,
        id,
        algorithm: alg,
        mpis,
    })
));

impl Serialize for PublicKeyEncryptedSessionKey {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&[self.version])?;
        writer.write_all(self.id.as_ref())?;
        writer.write_all(&[self.algorithm as u8])?;

        match self.algorithm {
            PublicKeyAlgorithm::RSA
            | PublicKeyAlgorithm::RSASign
            | PublicKeyAlgorithm::RSAEncrypt
            | PublicKeyAlgorithm::Elgamal
            | PublicKeyAlgorithm::ElgamalSign => {
                for mpi in &self.mpis {
                    write_mpi(mpi, writer)?;
                }
            }
            PublicKeyAlgorithm::ECDH => {
                write_mpi(&self.mpis[0], writer)?;
                writer.write_all(&[self.mpis[1].len() as u8])?;
                writer.write_all(&self.mpis[1])?;
            }
            _ => {
                unimplemented_err!("writing {:?}", self.algorithm);
            }
        }

        Ok(())
    }
}

impl PacketTrait for PublicKeyEncryptedSessionKey {
    fn packet_version(&self) -> Version {
        self.packet_version
    }

    fn tag(&self) -> Tag {
        Tag::PublicKeyEncryptedSessionKey
    }
}

impl fmt::Debug for PublicKeyEncryptedSessionKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("PublicKeyEncryptedSessionKey")
            .field("packet_version", &self.packet_version)
            .field("version", &self.version)
            .field("id", &self.id)
            .field("algorithm", &self.algorithm)
            .field(
                "mpis",
                &format!(
                    "[{}]",
                    self.mpis
                        .iter()
                        .map(hex::encode)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            )
            .finish()
    }
}

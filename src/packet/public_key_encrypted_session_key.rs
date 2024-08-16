use std::io;

use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use nom::bytes::streaming::take;
use nom::combinator::{map, map_res};
use nom::number::streaming::be_u8;
use nom::sequence::pair;
use rand::{CryptoRng, Rng};

use crate::crypto::checksum;
use crate::crypto::public_key::PublicKeyAlgorithm;
use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::errors::{IResult, Result};
use crate::packet::PacketTrait;
use crate::ser::Serialize;
use crate::types::{mpi, KeyId, Mpi, PublicKeyTrait, Tag, Version};

/// Public Key Encrypted Session Key Packet
/// <https://tools.ietf.org/html/rfc4880.html#section-5.1>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyEncryptedSessionKey {
    packet_version: Version,
    version: u8,
    id: KeyId,
    algorithm: PublicKeyAlgorithm,
    mpis: Vec<Mpi>,
}

impl PublicKeyEncryptedSessionKey {
    /// Parses a `PublicKeyEncryptedSessionKey` packet from the given slice.
    pub fn from_slice(version: Version, input: &[u8]) -> Result<Self> {
        let (_, pk) = parse(version)(input)?;

        if pk.version != 3 {
            unsupported_err!("unsupported PKESK version {}", pk.version);
        }

        Ok(pk)
    }

    /// Encrypts the given session key to the passed in public key.
    pub fn from_session_key<R: CryptoRng + Rng>(
        rng: R,
        session_key: &[u8],
        alg: SymmetricKeyAlgorithm,
        pkey: &impl PublicKeyTrait,
    ) -> Result<Self> {
        // the session key is prefixed with symmetric key algorithm
        let len = session_key.len();
        let mut data = vec![0u8; len + 3];
        data[0] = u8::from(alg);
        data[1..=len].copy_from_slice(session_key);

        // and appended a checksum
        BigEndian::write_u16(
            &mut data[len + 1..],
            checksum::calculate_simple(session_key),
        );

        let mpis = pkey.encrypt(rng, &data)?;

        Ok(PublicKeyEncryptedSessionKey {
            packet_version: Default::default(),
            version: 3,
            id: pkey.key_id(),
            algorithm: pkey.algorithm(),
            mpis,
        })
    }

    pub fn id(&self) -> &KeyId {
        &self.id
    }

    pub fn mpis(&self) -> &[Mpi] {
        &self.mpis
    }

    pub fn packet_version(&self) -> Version {
        self.packet_version
    }
}

fn parse_mpis<'i>(alg: &PublicKeyAlgorithm, i: &'i [u8]) -> IResult<&'i [u8], Vec<Mpi>> {
    match alg {
        PublicKeyAlgorithm::RSA | PublicKeyAlgorithm::RSASign | PublicKeyAlgorithm::RSAEncrypt => {
            map(mpi, |v| vec![v.to_owned()])(i)
        }
        PublicKeyAlgorithm::Elgamal | PublicKeyAlgorithm::ElgamalSign => {
            map(pair(mpi, mpi), |(first, second)| {
                vec![first.to_owned(), second.to_owned()]
            })(i)
        }
        PublicKeyAlgorithm::ECDSA | PublicKeyAlgorithm::DSA | PublicKeyAlgorithm::DiffieHellman => {
            Ok((i, vec![]))
        }
        PublicKeyAlgorithm::ECDH => {
            let (i, a) = mpi(i)?;
            let (i, blen) = be_u8(i)?;
            let (i, b) = take(blen)(i)?;
            let v: [u8; 1] = [blen];
            Ok((i, vec![a.to_owned(), (&v[..]).into(), b.into()]))
        }
        PublicKeyAlgorithm::Unknown(_) => Ok((i, vec![])), // we don't know the format of this data
        _ => Err(nom::Err::Error(crate::errors::Error::ParsingError(
            nom::error::ErrorKind::Switch,
        ))),
    }
}

/// Parses a Public-Key Encrypted Session Key Packets.
fn parse(
    packet_version: Version,
) -> impl Fn(&[u8]) -> IResult<&[u8], PublicKeyEncryptedSessionKey> {
    move |i: &[u8]| {
        // version, only 3 is allowed
        let (i, version) = be_u8(i)?;
        // the key id this maps to
        let (i, id) = map_res(take(8u8), KeyId::from_slice)(i)?;
        // the symmetric key algorithm
        let (i, alg) = map(be_u8, PublicKeyAlgorithm::from)(i)?;

        // key algorithm specific data
        let (i, mpis) = parse_mpis(&alg, i)?;

        Ok((
            i,
            PublicKeyEncryptedSessionKey {
                packet_version,
                version,
                id,
                algorithm: alg,
                mpis,
            },
        ))
    }
}

impl Serialize for PublicKeyEncryptedSessionKey {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&[self.version])?;
        writer.write_all(self.id.as_ref())?;
        writer.write_all(&[self.algorithm.into()])?;

        match self.algorithm {
            PublicKeyAlgorithm::RSA
            | PublicKeyAlgorithm::RSASign
            | PublicKeyAlgorithm::RSAEncrypt
            | PublicKeyAlgorithm::Elgamal
            | PublicKeyAlgorithm::ElgamalSign => {
                for mpi in &self.mpis {
                    mpi.to_writer(writer)?;
                }
            }
            PublicKeyAlgorithm::ECDH => {
                self.mpis[0].to_writer(writer)?;
                // The second value is not encoded as an actual MPI, but rather as a length prefixed
                // number.
                let blen: usize = match self.mpis[1].first() {
                    Some(l) => *l as usize,
                    None => 0,
                };
                writer.write_all(&[blen.try_into()?])?;
                let padding_len = blen - self.mpis[2].as_bytes().len();
                for _ in 0..padding_len {
                    writer.write_u8(0)?;
                }
                writer.write_all(self.mpis[2].as_bytes())?;
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

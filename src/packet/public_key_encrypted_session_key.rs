use std::io;

use byteorder::{BigEndian, ByteOrder};
use nom::be_u8;
use num_traits::FromPrimitive;
use rand::{CryptoRng, Rng};

use crypto::{checksum, PublicKeyAlgorithm, SymmetricKeyAlgorithm};
use errors::Result;
use packet::PacketTrait;
use ser::Serialize;
use types::{mpi, KeyId, Mpi, PublicKeyTrait, Tag, Version};

/// Public Key Encrypted Session Key Packet
/// https://tools.ietf.org/html/rfc4880.html#section-5.1
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
        let (_, pk) = parse(input, version)?;

        ensure_eq!(pk.version, 3, "invalid version");

        Ok(pk)
    }

    /// Encryptes the given session key to the passed in public key.
    pub fn from_session_key<R: CryptoRng + Rng>(
        rng: &mut R,
        session_key: &[u8],
        alg: SymmetricKeyAlgorithm,
        pkey: &impl PublicKeyTrait,
    ) -> Result<Self> {
        // the session key is prefixed with symmetric key algorithm
        let len = session_key.len();
        let mut data = vec![0u8; len + 3];
        data[0] = alg as u8;
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

#[rustfmt::skip]
named_args!(parse_mpis<'a>(alg: &'a PublicKeyAlgorithm) <Vec<Mpi>>, switch!(
    value!(alg),
    &PublicKeyAlgorithm::RSA |
    &PublicKeyAlgorithm::RSASign |
    &PublicKeyAlgorithm::RSAEncrypt => map!(mpi, |v| vec![v.to_owned()]) |
    &PublicKeyAlgorithm::Elgamal |
    &PublicKeyAlgorithm::ElgamalSign => do_parse!(
          first: mpi
      >> second: mpi
      >> (vec![first.to_owned(), second.to_owned()])
    ) |
    &PublicKeyAlgorithm::ECDSA |
    &PublicKeyAlgorithm::DSA |
    &PublicKeyAlgorithm::DiffieHellman => value!(Vec::new())|
    &PublicKeyAlgorithm::ECDH => do_parse!(
           a: mpi
        >> blen: be_u8
        >> b: take!(blen)
        >> ({
            vec![a.to_owned(), b.into()]
        })
    )
));

// Parses a Public-Key Encrypted Session Key Packets
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
                    mpi.to_writer(writer)?;
                }
            }
            PublicKeyAlgorithm::ECDH => {
                self.mpis[0].to_writer(writer)?;
                // The second value is not encoded as an actual MPI, but rather as a length prefixed
                // number.
                writer.write_all(&[self.mpis[1].len() as u8])?;
                writer.write_all(self.mpis[1].as_bytes())?;
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

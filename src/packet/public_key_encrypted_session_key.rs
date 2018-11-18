use nom::be_u8;
use num_traits::FromPrimitive;

use crypto::public_key::PublicKeyAlgorithm;
use errors::Result;
use types::KeyId;
use util::mpi;

/// Public Key Encrypted Session Key Packet
/// https://tools.ietf.org/html/rfc4880.html#section-5.1
#[derive(Debug, Clone)]
pub struct PublicKeyEncryptedSessionKey {
    version: u8,
    id: KeyId,
    algorithm: PublicKeyAlgorithm,
    mpis: Vec<Vec<u8>>,
}

impl PublicKeyEncryptedSessionKey {
    /// Parses a `PublicKeyEncryptedSessionKey` packet from the given slice.
    pub fn from_slice(input: &[u8]) -> Result<Self> {
        let (_, pk) = parse(input)?;

        ensure_eq!(pk.version, 3, "invalid version");

        Ok(pk)
    }

    pub fn id(&self) -> &KeyId {
        &self.id
    }

    pub fn mpis(&self) -> &[Vec<u8>] {
        &self.mpis
    }
}

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
    &PublicKeyAlgorithm::ECDSA => value!(Vec::new())|
    &PublicKeyAlgorithm::ECDH => do_parse!(
           a: mpi
        >> blen: be_u8
        >> b: take!(blen)
      >> ({
          info!("{:?} {:?}", a, b);
          vec![a.to_vec(), b.to_vec()]
      })
    )
));

/// Parses a Public-Key Encrypted Session Key Packets
named!(
    parse<PublicKeyEncryptedSessionKey>,
    do_parse!(
        // version, only 3 is allowed
        version: be_u8
        // the key id this maps to
        >> id: map_res!(take!(8), KeyId::from_slice)
        // the symmetric key algorithm
        >> alg: map_opt!(be_u8, |v| {
                let a = PublicKeyAlgorithm::from_u8(v);
                info!("alg {:?}",a);
                a
        })
        // key algorithm specific data
        >> mpis: call!(parse_mpis, &alg)
        >> (PublicKeyEncryptedSessionKey {
            version,
            id,
            algorithm: alg,
            mpis,
        })
    )
);

use nom::be_u8;
use num_traits::FromPrimitive;

use errors::Result;
use packet::types::key::KeyID;
use packet::types::PublicKeyAlgorithm;
use util::mpi;

#[derive(Debug, Clone)]
pub struct PKESK {
    pub version: u8,
    pub id: KeyID,
    pub algorithm: PublicKeyAlgorithm,
    pub mpis: Vec<Vec<u8>>,
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
/// Ref. https://tools.ietf.org/html/rfc4880#section-5.1
named!(
    parse_inner<PKESK>,
    do_parse!(
        // version, only 3 is allowed
        version: be_u8
        // the key id this maps to
        >> id: map_res!(take!(8), KeyID::from_slice)
        // the symmetric key algorithm
        >> alg: map_opt!(be_u8, |v| {
                let a = PublicKeyAlgorithm::from_u8(v);
                info!("alg {:?}",a);
                a
        })
        // key algorithm specific data
        >> mpis: call!(parse_mpis, &alg)
        >> (PKESK {
            version,
            id,
            algorithm: alg,
            mpis,
        })
    )
);

/// Parses a single Public-Key Encrypted Session Key Packet.
pub fn parse(body: &[u8]) -> Result<PKESK> {
    let (_, pk) = parse_inner(body)?;

    // TODO: move this into a constructor
    ensure_eq!(pk.version, 3, "invalid version");

    Ok(pk)
}
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
    )
    // TODO: handle other algorithms
));

/// Parses a Public-Key Encrypted Session Key Packets
/// Ref. https://tools.ietf.org/html/rfc4880#section-5.1
named!(
    parse_inner<PKESK>,
    do_parse!(
        // version, only 3 is allowed
        // TODO: validate
        version: be_u8
            // the key id this maps to
            >> id: map_res!(take!(8), KeyID::from_slice)
            // the symmetric key algorithm
            >> alg: map_opt!(be_u8, PublicKeyAlgorithm::from_u8)
            // key algorithm specific data
            >> mpis: call!(parse_mpis, &alg) >> (PKESK {
            version,
            id,
            algorithm: alg,
            mpis,
        })
    )
);

pub fn parse(body: &[u8]) -> Result<PKESK> {
    let (_, res) = parse_inner(body)?;
    Ok(res)
}

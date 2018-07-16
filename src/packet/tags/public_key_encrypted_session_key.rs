use enum_primitive::FromPrimitive;
use nom::be_u8;
use openssl::bn::BigNum;

use errors::Result;
use packet::types::PublicKeyAlgorithm;
use util::mpi_big;

#[derive(Debug)]
pub struct KeyID([u8; 8]);

impl KeyID {
    pub fn from_vec(input: &[u8]) -> Result<KeyID> {
        // TODO: return an error
        assert_eq!(input.len(), 8);
        let mut r = [0u8; 8];
        r.copy_from_slice(input);
        Ok(KeyID(r))
    }
}

#[derive(Debug)]
pub struct PKESK {
    pub version: u8,
    pub id: KeyID,
    pub algorithm: PublicKeyAlgorithm,
    pub mpis: Vec<BigNum>,
}

named_args!(parse_mpis<'a>(alg: &'a PublicKeyAlgorithm) <Vec<BigNum>>, switch!(
    value!(alg),
    &PublicKeyAlgorithm::RSA |
    &PublicKeyAlgorithm::RSASign |
    &PublicKeyAlgorithm::RSAEncrypt => map!(mpi_big, |v| vec![v]) |
    &PublicKeyAlgorithm::Elgamal |
    &PublicKeyAlgorithm::ElgamalSign => do_parse!(
        first: mpi_big
            >> second: mpi_big
            >> (vec![first, second])
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
            >> id: map_res!(take!(8), KeyID::from_vec)
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

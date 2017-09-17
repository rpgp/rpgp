use enum_primitive::FromPrimitive;

use packet::types::{KeyVersion, PrimaryKey, PublicKeyAlgorithm};
use util::mpi;

named!(rsa_fields<(&[u8], &[u8])>, do_parse!(
    n: mpi >>
    e: mpi >>
    ((n, e))
));

named!(new_public_key_parser((&[u8], usize)) -> (u32, u16, PublicKeyAlgorithm, (&[u8], &[u8])), do_parse!(
       key_time: take_bits!(u32, 32)
    >>      alg: map_opt!(
                     take_bits!(u8, 8),
                     PublicKeyAlgorithm::from_u8
                 ) 
    >>   fields: bytes!(switch!(value!(&alg), 
                   &PublicKeyAlgorithm::RSA => call!(rsa_fields) |
                   &PublicKeyAlgorithm::RSAEncrypt => call!(rsa_fields) |
                   &PublicKeyAlgorithm::RSASign => call!(rsa_fields) 
                 ))
    >> ((key_time, 0, alg, fields))
));

named!(old_public_key_parser((&[u8], usize)) -> (u32, u16, PublicKeyAlgorithm, (&[u8], &[u8])), do_parse!(
       key_time: take_bits!(u32, 32)
    >>      exp: take_bits!(u16, 16) 
    >>      alg: map_opt!(
                     take_bits!(u8, 8),
                     PublicKeyAlgorithm::from_u8
                 )
    >> ((key_time, exp, alg, (&b""[..], &b""[..])))
));

/// Parse a public key packet (Tag 6)
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.5.1.1
named!(pub parser<PrimaryKey>, bits!(do_parse!(
          key_ver: map_opt!(
                       take_bits!(u8, 8), 
                       KeyVersion::from_u8
                   )
    >>    details: switch!(value!(&key_ver), 
                       &KeyVersion::V2 => call!(old_public_key_parser) |
                       &KeyVersion::V3 => call!(old_public_key_parser) |
                       &KeyVersion::V4 => call!(new_public_key_parser)
                   ) 
    >> (PrimaryKey::new_public_rsa(
        key_ver,            
        details.2,
        (details.3).0.to_vec(),
        (details.3).1.to_vec()
    ))
)));

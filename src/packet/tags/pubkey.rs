use enum_primitive::FromPrimitive;
use nom::{be_u8, be_u16, be_u32};

use packet::types::{KeyVersion, PrimaryKey, PublicKeyAlgorithm, ecc_curve_from_oid};
use util::mpi;

type Fields<'a> = (&'a [u8], &'a [u8], Option<&'a [u8]>, Option<&'a [u8]>);

// Ref: https://tools.ietf.org/html/rfc6637#section-9
named!(ecdsa_fields<Fields>, do_parse!(
    // a one-octet size of the following field
       len: be_u8
    // octets representing a curve OID
    >> oid: take!(len)
    // MPI of an EC point representing a public key
    >>   p: mpi
    >> (oid, p, None, None)
));

// Ref: https://tools.ietf.org/html/rfc6637#section-9
named!(ecdh_fields<Fields>, do_parse!(
    // a one-octet size of the following field
        len: be_u8
    // octets representing a curve OID
    >>  oid: take!(len)
    // MPI of an EC point representing a public key
    >>    p: mpi
    // a one-octet size of the following fields
    >> _len2: be_u8
    // a one-octet value 01, reserved for future extensions
    >>       tag!(&[1][..])
    // a one-octet hash function ID used with a KDF
    >> hash: take!(1)
    // a one-octet algorithm ID for the symmetric algorithm used to wrap
    // the symmetric key used for the message encryption
    >>  alg: take!(1)
    >> (oid, p, Some(hash), Some(alg))
));

named!(elgamal_fields<Fields>, do_parse!(
    // MPI of Elgamal prime p
       p: mpi
    // MPI of Elgamal group generator g
    >> g: mpi
    // MPI of Elgamal public key value y (= g**x mod p where x is secret)
    >> y: mpi
    >> (p, g, Some(y), None)
));

named!(dsa_fields<Fields>, do_parse!(
       p: mpi
    >> q: mpi
    >> g: mpi
    >> y: mpi
    >> (p, q, Some(g), Some(y))
));

named!(rsa_fields<Fields>, do_parse!(
       n: mpi
    >> e: mpi
    >> (n, e, None, None)
));

named!(new_public_key_parser<(u32, u16, PublicKeyAlgorithm, Fields)>, do_parse!(
       key_time: be_u32
    >>      alg: map_opt!(be_u8, |v| PublicKeyAlgorithm::from_u8(v))
    >>   fields: switch!(value!(&alg), 
                 &PublicKeyAlgorithm::RSA        => call!(rsa_fields)   |
                 &PublicKeyAlgorithm::RSAEncrypt => call!(rsa_fields)   |
                 &PublicKeyAlgorithm::RSASign    => call!(rsa_fields)   |
                 &PublicKeyAlgorithm::DSA        => call!(dsa_fields)   |
                 &PublicKeyAlgorithm::ECDSA      => call!(ecdsa_fields) |
                 &PublicKeyAlgorithm::ECDH       => call!(ecdh_fields)    |
                 &PublicKeyAlgorithm::Elgamal    => call!(elgamal_fields) |
                 &PublicKeyAlgorithm::ElgamalSign => call!(elgamal_fields)
                 // &PublicKeyAlgorithm::DiffieHellman => 
                 )
    >> (key_time, 0, alg, fields)
));

named!(old_public_key_parser<(u32, u16, PublicKeyAlgorithm, Fields)>, do_parse!(
       key_time: be_u32
    >>      exp: be_u16
    >>      alg: map_opt!(be_u8, PublicKeyAlgorithm::from_u8)
    >> (key_time, exp, alg, (&b""[..], &b""[..], None, None))
));

/// Parse a public key packet (Tag 6)
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.5.1.1
named!(pub parser<PrimaryKey>, do_parse!(
          key_ver: map_opt!(be_u8, KeyVersion::from_u8)
    >>    details: switch!(value!(&key_ver), 
                       &KeyVersion::V2 => call!(old_public_key_parser) |
                       &KeyVersion::V3 => call!(old_public_key_parser) |
                       &KeyVersion::V4 => call!(new_public_key_parser)
                   ) 
    >> ({
        match details.2 {
            PublicKeyAlgorithm::RSA | PublicKeyAlgorithm::RSASign | PublicKeyAlgorithm::RSAEncrypt => PrimaryKey::new_public_rsa(
                key_ver,            
                details.2,
                (details.3).0.to_vec(),
                (details.3).1.to_vec()
            ),
            PublicKeyAlgorithm::DSA => PrimaryKey::new_public_dsa(
                key_ver,
                details.2,
                (details.3).0.to_vec(),
                (details.3).1.to_vec(),
                (details.3).2.unwrap().to_vec(),
                (details.3).3.unwrap().to_vec()
            ),
            PublicKeyAlgorithm::ECDSA => PrimaryKey::new_public_ecdsa(
                key_ver,
                details.2,
                ecc_curve_from_oid((details.3).0).unwrap(),
                (details.3).1.to_vec()
            ),
            PublicKeyAlgorithm::ECDH => PrimaryKey::new_public_ecdh(
                key_ver,
                details.2,
                ecc_curve_from_oid((details.3).0).unwrap(),
                (details.3).1.to_vec(),
                (details.3).2.unwrap()[0],
                (details.3).3.unwrap()[0]
            ),
            PublicKeyAlgorithm::Elgamal | PublicKeyAlgorithm::ElgamalSign => PrimaryKey::new_public_elgamal(
                key_ver,
                details.2,
                (details.3).0.to_vec(),
                (details.3).1.to_vec(),
                (details.3).2.unwrap().to_vec()
            ),
            _ => unimplemented!("{:?}", details)
        }
    })
));

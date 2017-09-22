use enum_primitive::FromPrimitive;
use nom::{be_u8, be_u16, be_u32};

use packet::types::{KeyVersion, PrimaryKey, PublicKeyAlgorithm, ECCCurve};
use util::mpi;

type Fields<'a> = (&'a [u8], &'a [u8], Option<&'a [u8]>, Option<&'a [u8]>);

const ECC_P256: [u8; 8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const ECC_P384: [u8; 5] = [0x2B, 0x81, 0x04, 0x00, 0x22];
const ECC_P521: [u8; 5] = [0x2B, 0x81, 0x04, 0x00, 0x23];

fn to_ecc_curve(oid: &[u8]) -> Option<ECCCurve> {
    if oid == &ECC_P256[..] {
        Some(ECCCurve::P256)
    } else if oid == &ECC_P384[..] {
        Some(ECCCurve::P384)
    } else if oid == &ECC_P521[..] {
        Some(ECCCurve::P521)
    } else {
        None
    }
}

// Ref: https://tools.ietf.org/html/rfc6637#section-9
named!(ecdsa_fields<Fields>, do_parse!(
    // a one-octet size of the following field
       len: be_u8
    >> oid: take!(len)
    >>   p: mpi
    >> ((oid, p, None, None))
));

named!(dsa_fields<Fields>, do_parse!(
       p: mpi
    >> q: mpi
    >> g: mpi
    >> y: mpi
    >> ((p, q, Some(g), Some(y)))
));

named!(rsa_fields<Fields>, do_parse!(
       n: mpi
    >> e: mpi
    >> ((n, e, None, None))
));

named!(new_public_key_parser<(u32, u16, PublicKeyAlgorithm, Fields)>, do_parse!(
       key_time: be_u32
    >>      alg: map_opt!(be_u8, PublicKeyAlgorithm::from_u8)
    >>   fields: switch!(value!(&alg), 
                 &PublicKeyAlgorithm::RSA        => call!(rsa_fields)   |
                 &PublicKeyAlgorithm::RSAEncrypt => call!(rsa_fields)   |
                 &PublicKeyAlgorithm::RSASign    => call!(rsa_fields)   |
                 &PublicKeyAlgorithm::DSA        => call!(dsa_fields)   |
                 &PublicKeyAlgorithm::ECDSA      => call!(ecdsa_fields)
                 )
    >> ((key_time, 0, alg, fields))
));

named!(old_public_key_parser<(u32, u16, PublicKeyAlgorithm, Fields)>, do_parse!(
       key_time: be_u32
    >>      exp: be_u16
    >>      alg: map_opt!(be_u8, PublicKeyAlgorithm::from_u8)
    >> ((key_time, exp, alg, (&b""[..], &b""[..], None, None)))
));

/// Parse a public key packet (Tag 6)
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.5.1.1
named!(pub parser<PrimaryKey>, dbg_dmp!(do_parse!(
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
                to_ecc_curve((details.3).0).unwrap(),
                (details.3).1.to_vec()
            ),
            _ => unimplemented!("{:?}", details)
        }
    })
)));

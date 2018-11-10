use nom::{self, be_u16, be_u32, be_u8};
use num_traits::FromPrimitive;

use composed;
use crypto::hash::HashAlgorithm;
use crypto::sym::SymmetricKeyAlgorithm;
use packet::types::ecc_curve::ecc_curve_from_oid;
use packet::types::key::*;
use packet::types::{KeyVersion, PublicKeyAlgorithm};
use util::{mpi, mpi_big};

// Ref: https://tools.ietf.org/html/rfc6637#section-9
named!(
    ecdsa<PublicParams>,
    do_parse!(
        // a one-octet size of the following field
        len: be_u8
    // octets representing a curve OID
    >> curve: map_opt!(take!(len), ecc_curve_from_oid)
    // MPI of an EC point representing a public key
    >>   p: mpi >> (PublicParams::ECDSA {
            curve,
            p: p.to_vec(),
        })
    )
);

// https://tools.ietf.org/html/draft-koch-eddsa-for-openpgp-00#section-4
named!(
    eddsa<PublicParams>,
    do_parse!(
        // a one-octet size of the following field
        len: be_u8
    // octets representing a curve OID
    >> curve: map_opt!(take!(len), ecc_curve_from_oid)
    // MPI of an EC point representing a public key
    >>   q: mpi >> (PublicParams::EdDSA {
            curve,
            q: q.to_vec(),
        })
    )
);

// Ref: https://tools.ietf.org/html/rfc6637#section-9
named!(
    ecdh<PublicParams>,
    do_parse!(
        // a one-octet size of the following field
        len: be_u8
    // octets representing a curve OID
    >>  curve: map_opt!(take!(len), ecc_curve_from_oid)
    // MPI of an EC point representing a public key
    >>    p: mpi_big
    // a one-octet size of the following fields
    >> _len2: be_u8
    // a one-octet value 01, reserved for future extensions
    >>       tag!(&[1][..])
    // a one-octet hash function ID used with a KDF
    >> hash: map_opt!(be_u8, HashAlgorithm::from_u8)
    // a one-octet algorithm ID for the symmetric algorithm used to wrap
    // the symmetric key used for the message encryption
    >>  alg_sym: map_opt!(be_u8, SymmetricKeyAlgorithm::from_u8)
    >> (PublicParams::ECDH {
            curve,
            p,
            hash: hash,
            alg_sym: alg_sym,
        })
    )
);

named!(
    elgamal<PublicParams>,
    do_parse!(
        // MPI of Elgamal prime p
        p: mpi_big
    // MPI of Elgamal group generator g
    >> g: mpi_big
    // MPI of Elgamal public key value y (= g**x mod p where x is secret)
    >> y: mpi_big
    >> (PublicParams::Elgamal{ p, g, y })
    )
);

named!(
    dsa<PublicParams>,
    do_parse!(
        p: mpi_big >> q: mpi_big >> g: mpi_big >> y: mpi_big >> (PublicParams::DSA { p, q, g, y })
    )
);

named!(
    rsa<PublicParams>,
    do_parse!(n: mpi_big >> e: mpi_big >> (PublicParams::RSA { n, e }))
);

/// Parse the fields of a public key.
named_args!(pub parse_pub_fields<'a>(typ: &PublicKeyAlgorithm) <PublicParams>, switch!(
    value!(typ),
    &PublicKeyAlgorithm::RSA        |
    &PublicKeyAlgorithm::RSAEncrypt |
    &PublicKeyAlgorithm::RSASign    => call!(rsa)     |
    &PublicKeyAlgorithm::DSA        => call!(dsa)     |
    &PublicKeyAlgorithm::ECDSA      => call!(ecdsa)   |
    &PublicKeyAlgorithm::ECDH       => call!(ecdh)    |
    &PublicKeyAlgorithm::Elgamal    |
    &PublicKeyAlgorithm::ElgamalSign => call!(elgamal) |
    &PublicKeyAlgorithm::EdDSA       => call!(eddsa)
    // &PublicKeyAlgorithm::DiffieHellman =>
));

named_args!(new_public_key_parser<'a>(key_ver: &'a KeyVersion) <PublicKey>, do_parse!(
       created_at: be_u32
    >>        alg: map_opt!(be_u8, |v| PublicKeyAlgorithm::from_u8(v))
    >>     params: call!(parse_pub_fields, &alg)
    >> (PublicKey::new(*key_ver, alg, created_at, None, params))
));

named_args!(old_public_key_parser<'a>(key_ver: &'a KeyVersion) <PublicKey>, do_parse!(
        created_at: be_u32
    >>         exp: be_u16
    >>         alg: map_opt!(be_u8, PublicKeyAlgorithm::from_u8)
    >>      params: call!(parse_pub_fields, &alg)
    >> (PublicKey::new(*key_ver, alg, created_at, Some(exp), params))
));

/// Parse a public key packet (Tag 6)
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.5.1.1
named!(pub parser<PublicKey>, do_parse!(
          key_ver: map_opt!(be_u8, KeyVersion::from_u8)
    >>    key: switch!(value!(&key_ver),
                       &KeyVersion::V2 => call!(old_public_key_parser, &key_ver) |
                       &KeyVersion::V3 => call!(old_public_key_parser, &key_ver) |
                       &KeyVersion::V4 => call!(new_public_key_parser, &key_ver)
                   )
    >> (key)
));

impl composed::key::PublicKey {
    /// Parse a single private key packet.
    pub fn key_packet_parser(packet: &[u8]) -> nom::IResult<&[u8], PublicKey> {
        parser(packet)
    }
}

use enum_primitive::FromPrimitive;
use nom::{be_u8, be_u16, be_u32};

use packet::types::{KeyVersion, PublicKeyAlgorithm};
use packet::types::ecc_curve::ecc_curve_from_oid;
use packet::types::key::*;
use util::mpi;

// Ref: https://tools.ietf.org/html/rfc6637#section-9
named_args!(ecdsa<'a>(alg: &'a PublicKeyAlgorithm, ver: &'a KeyVersion) <Key<Private>>, do_parse!(
    // a one-octet size of the following field
       len: be_u8
    // octets representing a curve OID
    >> curve: map_opt!(take!(len), ecc_curve_from_oid)
    // MPI of an EC point representing a public key
    >>   p: mpi
    >> (ECDSA::<Private>::new(*ver, *alg, ECDSAPublicParams{ curve, p: p.to_vec()}, ECDSAPrivateParams{}).into())
));

// Ref: https://tools.ietf.org/html/rfc6637#section-9
named_args!(ecdh<'a>(alg: &'a PublicKeyAlgorithm, ver: &'a KeyVersion) <Key<Private>>, do_parse!(
    // a one-octet size of the following field
        len: be_u8
    // octets representing a curve OID
    >>  curve: map_opt!(take!(len), ecc_curve_from_oid)
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
    >>  alg_sym: take!(1)
    >> (ECDH::<Private>::new(*ver, *alg, ECDHPublicParams{curve, p: p.to_vec(), hash: hash[0], alg_sym: alg_sym[0]}, ECDHPrivateParams{}).into())
));

named_args!(elgamal<'a>(alg: &'a PublicKeyAlgorithm, ver: &'a KeyVersion) <Key<Private>>, do_parse!(
    // MPI of Elgamal prime p
       p: mpi
    // MPI of Elgamal group generator g
    >> g: mpi
    // MPI of Elgamal public key value y (= g**x mod p where x is secret)
    >> y: mpi
        >> (Elgamal::<Private>::new(*ver, *alg, ElgamalPublicParams{p: p.to_vec(), g: g.to_vec(), y: y.to_vec()},ElgamalPrivateParams{}).into())
));

named_args!(dsa<'a>(alg: &'a PublicKeyAlgorithm, ver: &'a KeyVersion) <Key<Private>>, do_parse!(
       p: mpi
    >> q: mpi
    >> g: mpi
    >> y: mpi
    >> (DSA::<Private>::new(*ver, *alg, DSAPublicParams{p: p.to_vec(), q: q.to_vec(), g: g.to_vec(), y: y.to_vec()}, DSAPrivateParams{}).into())
));

named_args!(rsa<'a>(alg: &PublicKeyAlgorithm, ver: &'a KeyVersion) <Key<Private>>, do_parse!(
       n: mpi
    >> e: mpi
    >> (RSA::<Private>::new(*ver, *alg, RSAPublicParams{n: n.to_vec(), e: e.to_vec()}, RSAPrivateParams{}).into())
));

named_args!(key_from_fields<'a>(typ: PublicKeyAlgorithm, ver: &'a KeyVersion) <Key<Private>>, switch!(
    value!(&typ), 
    &PublicKeyAlgorithm::RSA        |
    &PublicKeyAlgorithm::RSAEncrypt |
    &PublicKeyAlgorithm::RSASign    => call!(rsa, &typ, ver)     |
    &PublicKeyAlgorithm::DSA        => call!(dsa, &typ, ver)     |
    &PublicKeyAlgorithm::ECDSA      => call!(ecdsa, &typ, ver)   |
    &PublicKeyAlgorithm::ECDH       => call!(ecdh, &typ, ver)    |
    &PublicKeyAlgorithm::Elgamal    |
    &PublicKeyAlgorithm::ElgamalSign => call!(elgamal, &typ, ver)
    // &PublicKeyAlgorithm::DiffieHellman => 
));

named_args!(new_public_key_parser<'a>(key_ver: &'a KeyVersion) <Key<Private>>, do_parse!(
       _key_time: be_u32
    >>      alg: map_opt!(be_u8, |v| PublicKeyAlgorithm::from_u8(v))
    >>   key: call!(key_from_fields, alg, key_ver)
    >> (key)
));

named_args!(old_public_key_parser<'a>(key_ver: &'a KeyVersion) <Key<Private>>, do_parse!(
       _key_time: be_u32
    >>      _exp: be_u16
    >>      alg: map_opt!(be_u8, PublicKeyAlgorithm::from_u8)
    >>   key: call!(key_from_fields, alg, key_ver)
    >> (key)
));

/// Parse a private key packet (Tag 5)
/// Ref: https://tpools.ietf.org/html/rfc4880.html#section-5.5.1.3
named!(pub parser<Key<Private>>, do_parse!(
          key_ver: map_opt!(be_u8, KeyVersion::from_u8)
    >>    key: switch!(value!(&key_ver), 
                       &KeyVersion::V2 => call!(old_public_key_parser, &key_ver) |
                       &KeyVersion::V3 => call!(old_public_key_parser, &key_ver) |
                       &KeyVersion::V4 => call!(new_public_key_parser, &key_ver)
                   ) 
    >> (key)
));

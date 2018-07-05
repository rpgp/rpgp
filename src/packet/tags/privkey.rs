use enum_primitive::FromPrimitive;
use nom::{be_u8, be_u16, be_u32};

use packet::types::{KeyVersion, PublicKeyAlgorithm, SymmetricKeyAlgorithm, StringToKeyType};
use packet::types::ecc_curve::ecc_curve_from_oid;
use packet::types::key::*;
use composed;
use util::{mpi, rest_len};

// Ref: https://tools.ietf.org/html/rfc6637#section-9
named_args!(ecdsa<'a>(alg: &'a PublicKeyAlgorithm, ver: &'a KeyVersion) <PrivateKey>, do_parse!(
    // a one-octet size of the following field
       len: be_u8
    // octets representing a curve OID
    >> curve: map_opt!(take!(len), ecc_curve_from_oid)
    // MPI of an EC point representing a public key
    >>   p: mpi
    >> (PrivateKey::new(*ver, *alg, PublicParams::ECDSA{ curve, p: p.to_vec()}, PrivateParams::ECDSA{}).into())
));

// Ref: https://tools.ietf.org/html/rfc6637#section-9
named_args!(ecdh<'a>(alg: &'a PublicKeyAlgorithm, ver: &'a KeyVersion) <PrivateKey>, do_parse!(
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
    >> (PrivateKey::new(
        *ver,
        *alg,
        PublicParams::ECDH{
            curve, p:
            p.to_vec(),
            hash: hash[0],
            alg_sym: alg_sym[0]
        },
        PrivateParams::ECDH{}
    ).into())
));

named_args!(elgamal<'a>(alg: &'a PublicKeyAlgorithm, ver: &'a KeyVersion) <PrivateKey>, do_parse!(
    // MPI of Elgamal prime p
       p: mpi
    // MPI of Elgamal group generator g
    >> g: mpi
    // MPI of Elgamal public key value y (= g**x mod p where x is secret)
    >> y: mpi
    >> (PrivateKey::new(
        *ver,
        *alg,
        PublicParams::Elgamal{
            p: p.to_vec(),
            g: g.to_vec(),
            y: y.to_vec()
        },
        PrivateParams::Elgamal{
            x: vec![],
        }
    ).into())
));

named_args!(dsa<'a>(alg: &'a PublicKeyAlgorithm, ver: &'a KeyVersion) <PrivateKey>, do_parse!(
       p: mpi
    >> q: mpi
    >> g: mpi
    >> y: mpi
    >> (PrivateKey::new(
        *ver,
        *alg,
        PublicParams::DSA{
            p: p.to_vec(),
            q: q.to_vec(),
            g: g.to_vec(),
            y: y.to_vec()
        },
        PrivateParams::DSA{
            x: vec![],
        }
    ).into())
));

named_args!(rsa<'a>(alg: &PublicKeyAlgorithm, ver: &'a KeyVersion) <PrivateKey>, do_parse!(
             n: mpi
    >>       e: mpi
    >> s2k_typ: be_u8
    >> enc_params: switch!(value!(s2k_typ), 
        // 0 is no encryption
        0       => value!((None, None, None, None)) |
        // symmetric key algorithm
        1...253 => do_parse!(
               sym_alg: map_opt!(value!(s2k_typ), SymmetricKeyAlgorithm::from_u8)
            >>      iv: take!(sym_alg.block_size())
            >> (Some(sym_alg), Some(iv), None, None)
        ) |
        // symmetric key + string-to-key
        254...255 => do_parse!(
                      sym_alg: map_opt!(be_u8, SymmetricKeyAlgorithm::from_u8)
                >>        s2k: map_opt!(be_u8, StringToKeyType::from_u8)
                >> s2k_params: take!(s2k.param_len())
                >>         iv: take!(sym_alg.block_size())
                >> (Some(sym_alg), Some(iv), Some(s2k), Some(s2k_params))
        )
    )
    >> checksum_len: switch!(value!(s2k_typ),
                     0   => value!(0) |
                     // 20 octect hash at the end
                     254 => value!(20) |
                     // 2 octet checksum at the end
                     _   => value!(2)
                         
    )
    >> data_len: map!(rest_len, |r| r - checksum_len)
    >>     data: take!(data_len)
    >> checksum: take!(checksum_len)
    >> ({
        PrivateKey::new(
        *ver,
        *alg,
        PublicParams::RSA {
            n: n.to_vec(),
            e: e.to_vec()
        },
        EncryptedPrivateParams {
            data: data.to_vec(),
            checksum: checksum.to_vec(),
            iv: enc_params.1.map(|iv| iv.to_vec()),
            encryption_algorithm: enc_params.0,
            string_to_key: enc_params.2,
            string_to_key_params: enc_params.3.map(|p| p.to_vec()),
            string_to_key_id: s2k_typ,
        }
        ).into()
    })
));

named_args!(key_from_fields<'a>(typ: PublicKeyAlgorithm, ver: &'a KeyVersion) <PrivateKey>, switch!(
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

named_args!(new_private_key_parser<'a>(key_ver: &'a KeyVersion) <PrivateKey>, do_parse!(
       _key_time: be_u32
    >>      alg: map_opt!(be_u8, |v| PublicKeyAlgorithm::from_u8(v))
    >>   key: call!(key_from_fields, alg, key_ver)
    >> (key)
));

named_args!(old_private_key_parser<'a>(key_ver: &'a KeyVersion) <PrivateKey>, do_parse!(
       _key_time: be_u32
    >>      _exp: be_u16
    >>      alg: map_opt!(be_u8, PublicKeyAlgorithm::from_u8)
    >>   key: call!(key_from_fields, alg, key_ver)
    >> (key)
));

/// Parse a private key packet (Tag 5)
/// Ref: https://tpools.ietf.org/html/rfc4880.html#section-5.5.1.3
named!(pub parser<PrivateKey>, do_parse!(
          key_ver: map_opt!(be_u8, KeyVersion::from_u8)
    >>    key: switch!(value!(&key_ver), 
                       &KeyVersion::V2 => call!(old_private_key_parser, &key_ver) |
                       &KeyVersion::V3 => call!(old_private_key_parser, &key_ver) |
                       &KeyVersion::V4 => call!(new_private_key_parser, &key_ver)
                   ) 
    >> (key)
));

impl composed::key::PrivateKey {
    /// Parse a single private key packet.
    fn key_packet_parser(packet: &[u8]) -> Result<(), ()> {
        parser(packet)
    }
}

/// Parse the decrpyted private params of an RSA private key.
named!(pub rsa_private_params<(Vec<u8>, Vec<u8>,Vec<u8>, Vec<u8>)>, do_parse!(
       d: mpi
    >> p: mpi
    >> q: mpi
    >> u: mpi
    >> (d.to_vec(), p.to_vec(), q.to_vec(), u.to_vec())
));
    

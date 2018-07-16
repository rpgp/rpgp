use enum_primitive::FromPrimitive;
use nom::{be_u8, be_u16, be_u32, self};
use openssl::bn::BigNum;

use packet::types::{KeyVersion, PublicKeyAlgorithm, StringToKeyType};
use crypto::hash::HashAlgorithm;
use crypto::sym::SymmetricKeyAlgorithm;
use packet::types::ecc_curve::ecc_curve_from_oid;
use packet::types::key::*;
use composed;
use util::{mpi_big, rest_len, mpi};

/// Has the given s2k type a salt?
fn has_salt(typ: &StringToKeyType) -> bool {
    match typ {
        StringToKeyType::Salted | StringToKeyType::IteratedAndSalted => true,
        _ => false
    }
}

/// Has the given s2k type a count?
fn has_count(typ: &StringToKeyType) -> bool {
    match typ {
        StringToKeyType::IteratedAndSalted => true,
        _ => false
    }
}

/// Converts a coded count into the count.
/// Ref: https://tools.ietf.org/html/rfc4880#section-3.7.1.3
fn coded_to_count(c: u8) -> usize {
    let expbias = 6;
    (16 as usize + (c & 15) as usize) << ((c >> 4) + expbias)
}

named_args!(s2k_param_parser<'a>(typ: &'a StringToKeyType) <(HashAlgorithm, Option<Vec<u8>>, Option<usize>)>, do_parse!(
       hash_alg: map_opt!(be_u8, HashAlgorithm::from_u8)
    >>     salt: cond!(has_salt(typ), map!(take!(8), |v| v.to_vec()))
    >>    count: cond!(has_count(typ), map!(be_u8, coded_to_count))
    >> (hash_alg, salt, count)
));

named!(enc_priv_params<EncryptedPrivateParams>, do_parse!(
          s2k_typ: be_u8
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
                >> s2k_params: flat_map!(take!(s2k.param_len()), call!(s2k_param_parser, &s2k))
                >>         iv: take!(sym_alg.block_size())
                >> (Some(sym_alg), Some(iv), Some(s2k), Some(s2k_params))
        )
    )
    >> checksum_len: switch!(value!(s2k_typ),
                     // 20 octect hash at the end, but part of the encrypted part
                     254 => value!(0) |
                     // 2 octet checksum at the end
                     _   => value!(2)
    )
    >> data_len: map!(rest_len, |r| r - checksum_len)
    >>     data: take!(data_len)
    >> checksum: take!(checksum_len)
    >> ({
        println!("data_len: {} checksum_len: {} data: {:?}", data_len, checksum_len, data);
        let (hash, salt, count) = match enc_params.3 {
            Some((hash, salt, count)) => (Some(hash), salt, count),
            None => (None, None, None),
        };
        EncryptedPrivateParams {
            data: data.to_vec(),
            checksum: checksum.to_vec(),
            iv: enc_params.1.map(|iv| iv.to_vec()),
            encryption_algorithm: enc_params.0,
            string_to_key: enc_params.2,
            string_to_key_hash: hash,
            string_to_key_salt: salt,
            string_to_key_count: count,
            string_to_key_id: s2k_typ,
        }
    })
));

// Ref: https://tools.ietf.org/html/rfc6637#section-9
named!(ecdsa<(PublicParams, EncryptedPrivateParams)>, do_parse!(
    // a one-octet size of the following field
       len: be_u8
    // octets representing a curve OID
    >> curve: map_opt!(take!(len), ecc_curve_from_oid)
    // MPI of an EC point representing a public key
    >>   p: mpi
    >>  pp: enc_priv_params
    >> (PublicParams::ECDSA { curve, p: p.to_vec() }, pp)
));

// Ref: https://tools.ietf.org/html/rfc6637#section-9
named!(ecdh<(PublicParams, EncryptedPrivateParams)>, do_parse!(
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
    >> hash: take!(1)
    // a one-octet algorithm ID for the symmetric algorithm used to wrap
    // the symmetric key used for the message encryption
    >>  alg_sym: take!(1)
    >>  pp: enc_priv_params
    >> (PublicParams::ECDH {
        curve,
        p,
        hash: hash[0],
        alg_sym: alg_sym[0]
    }, pp)
));

named!(elgamal<(PublicParams, EncryptedPrivateParams)>, do_parse!(
    // MPI of Elgamal prime p
       p: mpi_big
    // MPI of Elgamal group generator g
    >> g: mpi_big
    // MPI of Elgamal public key value y (= g**x mod p where x is secret)
    >> y: mpi_big
    >>  pp: enc_priv_params
    >> (PublicParams::Elgamal {
            p,
            g,
            y,
        },
        pp)
));

named!(dsa<(PublicParams, EncryptedPrivateParams)>, do_parse!(
       p: mpi_big
    >> q: mpi_big
    >> g: mpi_big
    >> y: mpi_big
    >>  pp: enc_priv_params
    >> (PublicParams::DSA {
            p,
            q,
            g,
            y,
        },
        pp)
));

named!(rsa<(PublicParams, EncryptedPrivateParams)>, do_parse!(
             n: mpi_big
    >>       e: mpi_big
    >>      pp: enc_priv_params
    >> (PublicParams::RSA { n, e, }, pp)
));

named_args!(key_from_fields<'a>(typ: &'a PublicKeyAlgorithm) <(PublicParams, EncryptedPrivateParams)>, switch!(
    value!(&typ), 
    &PublicKeyAlgorithm::RSA        |
    &PublicKeyAlgorithm::RSAEncrypt |
    &PublicKeyAlgorithm::RSASign    => call!(rsa)     |
    &PublicKeyAlgorithm::DSA        => call!(dsa)     |
    &PublicKeyAlgorithm::ECDSA      => call!(ecdsa)   |
    &PublicKeyAlgorithm::ECDH       => call!(ecdh)    |
    &PublicKeyAlgorithm::Elgamal    |
    &PublicKeyAlgorithm::ElgamalSign => call!(elgamal)
    // &PublicKeyAlgorithm::DiffieHellman => 
));

named_args!(new_private_key_parser<'a>(key_ver: &'a KeyVersion) <PrivateKey>, do_parse!(
        created_at: be_u32
    >>         alg: map_opt!(be_u8, |v| PublicKeyAlgorithm::from_u8(v))
    >>      params: call!(key_from_fields, &alg)
    >> (PrivateKey::new(*key_ver, alg, created_at, None, params.0, params.1))
));

named_args!(old_private_key_parser<'a>(key_ver: &'a KeyVersion) <PrivateKey>, do_parse!(
       created_at: be_u32
    >>        exp: be_u16
    >>        alg: map_opt!(be_u8, PublicKeyAlgorithm::from_u8)
    >>     params: call!(key_from_fields, &alg)
    >> (PrivateKey::new(*key_ver, alg, created_at, Some(exp), params.0, params.1))
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
    pub fn key_packet_parser(packet: &[u8]) -> nom::IResult<&[u8], PrivateKey> {
        parser(packet)
    }
}

/// Parse the decrpyted private params of an RSA private key.
named!(pub rsa_private_params<(BigNum, BigNum,BigNum, BigNum)>, do_parse!(
       d: mpi_big
    >> p: mpi_big
    >> q: mpi_big
    >> u: mpi_big
    >> (d, p, q, u)
));
    
named!(pub ecc_private_params<BigNum>, do_parse!(
       key: mpi_big
    >> (key) 
));

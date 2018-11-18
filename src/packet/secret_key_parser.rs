use chrono::{DateTime, TimeZone, Utc};
use nom::{be_u16, be_u32, be_u8};
use num_bigint::BigUint;
use num_traits::FromPrimitive;

use crypto::public_key::{PublicKeyAlgorithm, PublicParams};
use crypto::sym::SymmetricKeyAlgorithm;
use packet::public_key_parser::parse_pub_fields;
use types::{s2k_parser, EncryptedSecretParams, KeyVersion};
use util::{mpi, mpi_big, rest_len};

/// Parse possibly encrypted private fields of a key.
#[rustfmt::skip]
named!(parse_enc_priv_fields<EncryptedSecretParams>, do_parse!(
          s2k_typ: be_u8
    >> enc_params: switch!(value!(s2k_typ),
                   // 0 is no encryption
                   0       => value!((None, None, None)) |
                   // symmetric key algorithm
                   1...253 => do_parse!(
                          sym_alg: map_opt!(
                                    value!(s2k_typ),
                                    SymmetricKeyAlgorithm::from_u8
                                )
                       >>      iv: take!(sym_alg.block_size())
                       >> (Some(sym_alg), Some(iv), None)
                   ) |
                   // symmetric key + string-to-key
                   254...255 => do_parse!(
                             sym_alg: map_opt!(
                                        be_u8,
                                        SymmetricKeyAlgorithm::from_u8
                                      )
                       >>        s2k: s2k_parser
                       >>         iv: take!(sym_alg.block_size())
                       >> (Some(sym_alg), Some(iv), Some(s2k))
                   )
    )
    >> checksum_len: switch!(value!(s2k_typ),
        // 20 octect hash at the end, but part of the encrypted part
        254 => value!(0) |
        // 2 octet checksum at the end
        _   => value!(2)
    )
    >> data_len: map!(rest_len, |r| r - checksum_len)
    >>     data: map!(take!(data_len), |d| d.to_vec())
    >> checksum: map!(
                   cond!(checksum_len > 0, take!(checksum_len)),
                   |c| c.map(|c| c.to_vec())
                 )
    >> ({
        let encryption_algorithm = enc_params.0;
        let iv = enc_params.1.map(|iv| iv.to_vec());
        let string_to_key = enc_params.2;

        EncryptedSecretParams {
            data,
            checksum,
            iv,
            encryption_algorithm,
            string_to_key,
            string_to_key_id: s2k_typ,
        }
    })
));

/// Parse the whole private key, both public and private fields.
#[rustfmt::skip]
named_args!(parse_pub_priv_fields<'a>(typ: &'a PublicKeyAlgorithm) <(PublicParams, EncryptedSecretParams)>, do_parse!(
      pub_params: call!(parse_pub_fields, typ)
  >> priv_params: parse_enc_priv_fields
  >> (pub_params, priv_params)
));

#[rustfmt::skip]
named_args!(new_private_key_parser<'a>(key_ver: &'a KeyVersion) <(KeyVersion, PublicKeyAlgorithm, DateTime<Utc>, Option<u16>, PublicParams, EncryptedSecretParams)>, do_parse!(
        created_at: map!(be_u32, |v| Utc.timestamp(i64::from(v), 0))
    >>         alg: map_opt!(be_u8, |v| PublicKeyAlgorithm::from_u8(v))
    >>      params: call!(parse_pub_priv_fields, &alg)
    >> (*key_ver, alg, created_at, None, params.0, params.1)
));

#[rustfmt::skip]
named_args!(old_private_key_parser<'a>(key_ver: &'a KeyVersion) <(KeyVersion, PublicKeyAlgorithm, DateTime<Utc>, Option<u16>, PublicParams, EncryptedSecretParams)>, do_parse!(
       created_at: map!(be_u32, |v| Utc.timestamp(i64::from(v), 0))
    >>        exp: be_u16
    >>        alg: map_opt!(be_u8, PublicKeyAlgorithm::from_u8)
    >>     params: call!(parse_pub_priv_fields, &alg)
    >> (*key_ver, alg, created_at, Some(exp), params.0, params.1)
));

/// Parse a private key packet (Tag 5)
/// Ref: https://tpools.ietf.org/html/rfc4880.html#section-5.5.1.3
#[rustfmt::skip]
named!(pub(crate) parse<(KeyVersion, PublicKeyAlgorithm, DateTime<Utc>, Option<u16>, PublicParams, EncryptedSecretParams)>, do_parse!(
       key_ver: map_opt!(be_u8, KeyVersion::from_u8)
    >>     key: switch!(value!(&key_ver),
                       &KeyVersion::V2 => call!(
                           old_private_key_parser, &key_ver
                       ) |
                       &KeyVersion::V3 => call!(
                           old_private_key_parser, &key_ver
                       ) |
                       &KeyVersion::V4 => call!(
                           new_private_key_parser, &key_ver
                       )
                )
    >> (key)
));

/// Parse the decrpyted private params of an RSA private key.
#[rustfmt::skip]
named!(pub(crate) rsa_secret_params<(BigUint, BigUint, BigUint, BigUint)>, do_parse!(
       d: mpi_big
    >> p: mpi_big
    >> q: mpi_big
    >> u: mpi_big
    >> (d, p, q, u)
));

#[rustfmt::skip]
named!(pub(crate) ecc_secret_params<&[u8]>, do_parse!(
       key: mpi
    >> (key)
));

use chrono::{DateTime, TimeZone, Utc};
use nom::{be_u16, be_u32, be_u8, rest};
use num_traits::FromPrimitive;

use crate::crypto::PublicKeyAlgorithm;
use crate::packet::public_key_parser::parse_pub_fields;
use crate::types::{KeyVersion, PublicParams, SecretParams};

// Parse the whole private key, both public and private fields.
#[rustfmt::skip]
named_args!(parse_pub_priv_fields(typ: PublicKeyAlgorithm) <(PublicParams, SecretParams)>, do_parse!(
      pub_params: call!(parse_pub_fields, typ)
  >> priv_params: map_res!(rest, |v| SecretParams::from_slice(v, typ))
  >> (pub_params, priv_params)
));

#[rustfmt::skip]
named_args!(new_private_key_parser<'a>(key_ver: &'a KeyVersion) <(KeyVersion, PublicKeyAlgorithm, DateTime<Utc>, Option<u16>, PublicParams, SecretParams)>, do_parse!(
        created_at: map!(be_u32, |v| Utc.timestamp(i64::from(v), 0))
    >>         alg: map_opt!(be_u8, |v| PublicKeyAlgorithm::from_u8(v))
    >>      params: call!(parse_pub_priv_fields, alg)
    >> (*key_ver, alg, created_at, None, params.0, params.1)
));

#[rustfmt::skip]
named_args!(old_private_key_parser<'a>(key_ver: &'a KeyVersion) <(KeyVersion, PublicKeyAlgorithm, DateTime<Utc>, Option<u16>, PublicParams, SecretParams)>, do_parse!(
       created_at: map!(be_u32, |v| Utc.timestamp(i64::from(v), 0))
    >>        exp: be_u16
    >>        alg: map_opt!(be_u8, PublicKeyAlgorithm::from_u8)
    >>     params: call!(parse_pub_priv_fields, alg)
    >> (*key_ver, alg, created_at, Some(exp), params.0, params.1)
));

// Parse a private key packet (Tag 5)
// Ref: https://tpools.ietf.org/html/rfc4880.html#section-5.5.1.3
#[rustfmt::skip]
named!(pub(crate) parse<(KeyVersion, PublicKeyAlgorithm, DateTime<Utc>, Option<u16>, PublicParams, SecretParams)>, do_parse!(
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

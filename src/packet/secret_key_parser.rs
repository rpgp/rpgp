use chrono::{DateTime, TimeZone, Utc};
use nom::combinator::{map, map_opt, map_res, rest};
use nom::number::streaming::{be_u16, be_u32, be_u8};
use nom::sequence::tuple;

use crate::crypto::public_key::PublicKeyAlgorithm;
use crate::errors::{Error, IResult};
use crate::packet::public_key_parser::parse_pub_fields;
use crate::types::{KeyVersion, PublicParams, SecretParams};

/// Parse the whole private key, both public and private fields.
fn parse_pub_priv_fields(
    key_ver: KeyVersion,
    typ: PublicKeyAlgorithm,
    pub_len: Option<usize>,
) -> impl Fn(&[u8]) -> IResult<&[u8], (PublicParams, SecretParams)> {
    move |i| {
        map_res(
            tuple((parse_pub_fields(typ, pub_len), rest)),
            |(pub_params, v)| {
                if let Some(pub_len) = pub_len {
                    // if we received a public key material length (from a v6 secret key packet),
                    // make sure that we consumed the expected number of bytes
                    if i.len() - v.len() != pub_len {
                        return Err(Error::Message(format!(
                            "Inconsistent pub_len in secret key packet {}",
                            pub_len
                        )));
                    }
                }

                let secret_params = SecretParams::from_slice(v, key_ver, typ, &pub_params)?;
                Ok::<_, Error>((pub_params, secret_params))
            },
        )(i)
    }
}

fn private_key_parser_v4_v6(
    key_ver: &KeyVersion,
) -> impl Fn(
    &[u8],
) -> IResult<
    &[u8],
    (
        KeyVersion,
        PublicKeyAlgorithm,
        DateTime<Utc>,
        Option<u16>,
        PublicParams,
        SecretParams,
    ),
> + '_ {
    |i: &[u8]| {
        let (i, created_at) = map_opt(be_u32, |v| Utc.timestamp_opt(i64::from(v), 0).single())(i)?;
        let (i, alg) = map(be_u8, PublicKeyAlgorithm::from)(i)?;

        let (i, pub_len) = if *key_ver == KeyVersion::V6 {
            // "scalar octet count for the following public key material" -> pass on for checking
            let (i, pub_len) = be_u32(i)?;

            (i, Some(pub_len as usize))
        } else {
            (i, None)
        };

        let (i, params) = parse_pub_priv_fields(*key_ver, alg, pub_len)(i)?;
        Ok((i, (*key_ver, alg, created_at, None, params.0, params.1)))
    }
}

fn private_key_parser_v2_v3(
    key_ver: &KeyVersion,
) -> impl Fn(
    &[u8],
) -> IResult<
    &[u8],
    (
        KeyVersion,
        PublicKeyAlgorithm,
        DateTime<Utc>,
        Option<u16>,
        PublicParams,
        SecretParams,
    ),
> + '_ {
    |i: &[u8]| {
        let (i, created_at) = map_opt(be_u32, |v| Utc.timestamp_opt(i64::from(v), 0).single())(i)?;
        let (i, exp) = be_u16(i)?;
        let (i, alg) = map(be_u8, PublicKeyAlgorithm::from)(i)?;
        let (i, params) = parse_pub_priv_fields(*key_ver, alg, None)(i)?;
        Ok((
            i,
            (*key_ver, alg, created_at, Some(exp), params.0, params.1),
        ))
    }
}

/// Parse a private key packet (Tag 5)
/// Ref: https://tpools.ietf.org/html/rfc4880.html#section-5.5.1.3
#[allow(clippy::type_complexity)]
pub(crate) fn parse(
    i: &[u8],
) -> IResult<
    &[u8],
    (
        KeyVersion,
        PublicKeyAlgorithm,
        DateTime<Utc>,
        Option<u16>,
        PublicParams,
        SecretParams,
    ),
> {
    let (i, key_ver) = map(be_u8, KeyVersion::from)(i)?;
    let (i, key) = match &key_ver {
        &KeyVersion::V2 | &KeyVersion::V3 => private_key_parser_v2_v3(&key_ver)(i)?,
        &KeyVersion::V4 | KeyVersion::V6 => private_key_parser_v4_v6(&key_ver)(i)?,
        KeyVersion::V5 | KeyVersion::Other(_) => {
            return Err(nom::Err::Error(Error::Unsupported(format!(
                "Unsupported key version {}",
                u8::from(key_ver)
            ))))
        }
    };
    Ok((i, key))
}

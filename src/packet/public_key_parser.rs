use chrono::{DateTime, TimeZone, Utc};
use nom::combinator::{map, map_opt};
use nom::number::streaming::{be_u16, be_u32, be_u8};

use crate::crypto::public_key::PublicKeyAlgorithm;
use crate::errors::IResult;
use crate::types::{KeyVersion, PublicParams};

fn public_key_parser_v4_v6(
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
    ),
> + '_ {
    |i: &[u8]| {
        let (i, created_at) = map_opt(be_u32, |v| Utc.timestamp_opt(i64::from(v), 0).single())(i)?;
        let (i, alg) = map(be_u8, PublicKeyAlgorithm::from)(i)?;

        let (i, pub_len) = if *key_ver == KeyVersion::V6 {
            // "scalar octet count for the following public key material"
            let (i, len) = be_u32(i)?;
            if len == 0 {
                return Err(nom::Err::Error(crate::errors::Error::InvalidInput));
            }
            (i, Some(len as usize))
        } else {
            (i, None)
        };

        // If we got a pub_len, we expect to consume this amount of data, and have `expected_rest`
        // left after `parse_pub_fields`
        let expected_rest = match pub_len {
            Some(len) => {
                if i.len() < len {
                    return Err(nom::Err::Error(crate::errors::Error::InvalidInput));
                }
                Some(i.len() - len)
            }
            None => None,
        };

        let (i, params) = PublicParams::try_from_slice(alg, pub_len)(i)?;

        // consistency check for pub_len, if available
        if let Some(expected_rest) = expected_rest {
            if expected_rest != i.len() {
                return Err(nom::Err::Error(crate::errors::Error::Message(format!(
                    "Inconsistent pub_len in secret key packet {}",
                    pub_len.expect("if expected_rest is Some, pub_len is Some")
                ))));
            }
        }

        Ok((i, (*key_ver, alg, created_at, None, params)))
    }
}

fn public_key_parser_v2_v3(
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
    ),
> + '_ {
    |i: &[u8]| {
        let (i, created_at) = map_opt(be_u32, |v| Utc.timestamp_opt(i64::from(v), 0).single())(i)?;
        let (i, exp) = be_u16(i)?;
        let (i, alg) = map(be_u8, PublicKeyAlgorithm::from)(i)?;
        let (i, params) = PublicParams::try_from_slice(alg, None)(i)?;

        Ok((i, (*key_ver, alg, created_at, Some(exp), params)))
    }
}

/// Parse a public key packet (Tag 6)
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-public-key-packet-type-id-6
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
    ),
> {
    let (i, key_ver) = map(be_u8, KeyVersion::from)(i)?;
    let (i, key) = match &key_ver {
        &KeyVersion::V2 | &KeyVersion::V3 => public_key_parser_v2_v3(&key_ver)(i)?,
        &KeyVersion::V4 | &KeyVersion::V6 => public_key_parser_v4_v6(&key_ver)(i)?,
        KeyVersion::V5 | KeyVersion::Other(_) => {
            return Err(nom::Err::Error(crate::errors::Error::Unsupported(format!(
                "Unsupported key version {}",
                u8::from(key_ver)
            ))))
        }
    };
    Ok((i, key))
}

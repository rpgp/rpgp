use std::io::BufRead;

use chrono::{DateTime, TimeZone, Utc};

use crate::{
    crypto::public_key::PublicKeyAlgorithm,
    errors::Result,
    parsing_reader::BufReadParsing,
    types::{KeyVersion, PublicParams},
};

fn public_key_parser_v4_v6<B: BufRead>(
    key_ver: &KeyVersion,
    mut i: B,
) -> Result<(
    KeyVersion,
    PublicKeyAlgorithm,
    DateTime<Utc>,
    Option<u16>,
    PublicParams,
)> {
    let created_at = i
        .read_be_u32()
        .map(|v| Utc.timestamp_opt(i64::from(v), 0).single())?
        .ok_or_else(|| format_err!("invalid created at timestamp"))?;
    let alg = i.read_u8().map(PublicKeyAlgorithm::from)?;

    let pub_len = if *key_ver == KeyVersion::V6 {
        // "scalar octet count for the following public key material"
        let len = i.read_be_u32()?;
        ensure!(len > 0, "key length must not be 0");
        Some(len as usize)
    } else {
        None
    };

    let params = if let Some(pub_len) = pub_len {
        PublicParams::try_from_reader(alg, Some(pub_len), i.read_take(pub_len))?
    } else {
        PublicParams::try_from_reader(alg, None, &mut i)?
    };

    Ok((*key_ver, alg, created_at, None, params))
}

fn public_key_parser_v2_v3<B: BufRead>(
    key_ver: &KeyVersion,
    mut i: B,
) -> Result<(
    KeyVersion,
    PublicKeyAlgorithm,
    DateTime<Utc>,
    Option<u16>,
    PublicParams,
)> {
    let created_at = i
        .read_be_u32()
        .map(|v| Utc.timestamp_opt(i64::from(v), 0).single())?
        .ok_or_else(|| format_err!("invalid created at timestamp"))?;
    let exp = i.read_be_u16()?;
    let alg = i.read_u8().map(PublicKeyAlgorithm::from)?;
    let params = PublicParams::try_from_reader(alg, None, &mut i)?;

    Ok((*key_ver, alg, created_at, Some(exp), params))
}

/// Parse a public key packet (Tag 6)
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-public-key-packet-type-id-6
#[allow(clippy::type_complexity)]
pub(crate) fn parse<B: BufRead>(
    mut i: B,
) -> Result<(
    KeyVersion,
    PublicKeyAlgorithm,
    DateTime<Utc>,
    Option<u16>,
    PublicParams,
)> {
    let key_ver = i.read_u8().map(KeyVersion::from)?;
    let key = match key_ver {
        KeyVersion::V2 | KeyVersion::V3 => public_key_parser_v2_v3(&key_ver, i)?,
        KeyVersion::V4 | KeyVersion::V6 => public_key_parser_v4_v6(&key_ver, i)?,
        KeyVersion::V5 | KeyVersion::Other(_) => {
            unsupported_err!("key version {:?}", key_ver);
        }
    };
    Ok(key)
}

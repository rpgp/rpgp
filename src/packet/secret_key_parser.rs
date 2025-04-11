use std::io::BufRead;

use chrono::{DateTime, TimeZone, Utc};
use log::debug;

use crate::{
    crypto::public_key::PublicKeyAlgorithm,
    errors::{ensure, format_err, unsupported_err, Result},
    parsing_reader::BufReadParsing,
    types::{KeyVersion, PublicParams, SecretParams},
};

/// Parse the whole private key, both public and private fields.
fn parse_pub_priv_fields<B: BufRead>(
    key_ver: KeyVersion,
    typ: PublicKeyAlgorithm,
    pub_len: Option<usize>,
    mut i: B,
) -> Result<(PublicParams, SecretParams)> {
    debug!(
        "KeyVersion: {:?}, alg: {:?}, len {:?}",
        key_ver, typ, pub_len
    );
    let pub_params = match pub_len {
        Some(pub_len) => {
            // Use the pub_len hint to make sure we consume no more or less
            let mut public = i.read_take(pub_len);
            let pp = PublicParams::try_from_reader(typ, Some(pub_len), &mut public)?;

            ensure!(
                !public.has_remaining()?,
                "PublicParams::try_from_reader didn't consume all data"
            );
            pp
        }
        None => PublicParams::try_from_reader(typ, None, &mut i)?,
    };

    let v = i.rest()?;
    debug!("rest: {}", hex::encode(&v));

    let secret_params = SecretParams::from_slice(&v, key_ver, typ, &pub_params)?;
    Ok((pub_params, secret_params))
}

fn private_key_parser_v4_v6<B: BufRead>(
    key_ver: &KeyVersion,
    mut i: B,
) -> Result<(
    KeyVersion,
    PublicKeyAlgorithm,
    DateTime<Utc>,
    Option<u16>,
    PublicParams,
    SecretParams,
)> {
    let created_at = i
        .read_be_u32()
        .map(|v| Utc.timestamp_opt(i64::from(v), 0).single())?
        .ok_or_else(|| format_err!("invalid timestamp"))?;

    let alg = i.read_u8().map(PublicKeyAlgorithm::from)?;

    let pub_len = if *key_ver == KeyVersion::V6 {
        // "scalar octet count for the following public key material" -> pass on for checking
        let pub_len = i.read_be_u32()?;

        Some(pub_len as usize)
    } else {
        None
    };

    let params = parse_pub_priv_fields(*key_ver, alg, pub_len, i)?;
    Ok((*key_ver, alg, created_at, None, params.0, params.1))
}

fn private_key_parser_v2_v3<B: BufRead>(
    key_ver: &KeyVersion,
    mut i: B,
) -> Result<(
    KeyVersion,
    PublicKeyAlgorithm,
    DateTime<Utc>,
    Option<u16>,
    PublicParams,
    SecretParams,
)> {
    let created_at = i
        .read_be_u32()
        .map(|v| Utc.timestamp_opt(i64::from(v), 0).single())?
        .ok_or_else(|| format_err!("invalid imestamp"))?;

    let exp = i.read_be_u16()?;
    let alg = i.read_u8().map(PublicKeyAlgorithm::from)?;
    let params = parse_pub_priv_fields(*key_ver, alg, None, i)?;

    Ok((*key_ver, alg, created_at, Some(exp), params.0, params.1))
}

/// Parse a secret key packet (Tag 5)
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-secret-key-packet-formats
#[allow(clippy::type_complexity)]
pub(crate) fn parse<B: BufRead>(
    mut i: B,
) -> Result<(
    KeyVersion,
    PublicKeyAlgorithm,
    DateTime<Utc>,
    Option<u16>,
    PublicParams,
    SecretParams,
)> {
    let key_ver = i.read_u8().map(KeyVersion::from)?;
    let key = match key_ver {
        KeyVersion::V2 | KeyVersion::V3 => private_key_parser_v2_v3(&key_ver, i)?,
        KeyVersion::V4 | KeyVersion::V6 => private_key_parser_v4_v6(&key_ver, i)?,
        KeyVersion::V5 | KeyVersion::Other(_) => {
            unsupported_err!("key version {:?}", key_ver);
        }
    };
    Ok(key)
}

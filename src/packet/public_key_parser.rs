use chrono::{DateTime, TimeZone, Utc};
use nom::bytes::streaming::{tag, take};
use nom::combinator::{map, map_opt, map_res};
use nom::multi::length_data;
use nom::number::streaming::{be_u16, be_u32, be_u8};
use nom::sequence::{pair, tuple};

use crate::crypto::ecc_curve::ecc_curve_from_oid;
use crate::crypto::hash::HashAlgorithm;
use crate::crypto::public_key::PublicKeyAlgorithm;
use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::errors::IResult;
use crate::types::{mpi, EcdsaPublicParams, KeyVersion, Mpi, MpiRef, PublicParams};

#[inline]
fn to_owned(mref: MpiRef<'_>) -> Mpi {
    mref.to_owned()
}

/// Ref: https://tools.ietf.org/html/rfc6637#section-9
fn ecdsa(i: &[u8]) -> IResult<&[u8], PublicParams> {
    let (i, curve) = map_opt(
        // a one-octet size of the following field
        length_data(be_u8),
        // octets representing a curve OID
        ecc_curve_from_oid,
    )(i)?;

    // MPI of an EC point representing a public key
    let (i, p) = mpi(i)?;
    Ok((
        i,
        PublicParams::ECDSA(EcdsaPublicParams::try_from_mpi(p, curve)?),
    ))
}

/// https://tools.ietf.org/html/draft-koch-eddsa-for-openpgp-00#section-4
fn eddsa_legacy(i: &[u8]) -> IResult<&[u8], PublicParams> {
    let (i, curve) = map_opt(
        // a one-octet size of the following field
        length_data(be_u8),
        // octets representing a curve OID
        ecc_curve_from_oid,
    )(i)?;
    // MPI of an EC point representing a public key
    let (i, q) = mpi(i)?;
    Ok((
        i,
        PublicParams::EdDSALegacy {
            curve,
            q: q.to_owned(),
        },
    ))
}

/// https://www.rfc-editor.org/rfc/rfc9580.html#name-algorithm-specific-part-for-ed2
fn ed25519(i: &[u8]) -> IResult<&[u8], PublicParams> {
    // 32 bytes of public key
    let (i, p) = nom::bytes::complete::take(32u8)(i)?;
    Ok((
        i,
        PublicParams::Ed25519 {
            public: p.try_into().expect("we took 32 bytes"),
        },
    ))
}

/// https://www.rfc-editor.org/rfc/rfc9580.html#name-algorithm-specific-part-for-x
fn x25519(i: &[u8]) -> IResult<&[u8], PublicParams> {
    // 32 bytes of public key
    let (i, p) = nom::bytes::complete::take(32u8)(i)?;
    Ok((
        i,
        PublicParams::X25519 {
            public: p.try_into().expect("we took 32 bytes"),
        },
    ))
}

/// https://www.rfc-editor.org/rfc/rfc9580.html#name-algorithm-specific-part-for-x4
fn x448(i: &[u8]) -> IResult<&[u8], PublicParams> {
    // 56 bytes of public key
    let (i, p) = nom::bytes::complete::take(56u8)(i)?;
    Ok((
        i,
        PublicParams::X448 {
            public: p.try_into().expect("we took 56 bytes"),
        },
    ))
}

/// Ref: https://tools.ietf.org/html/rfc6637#section-9
fn ecdh(i: &[u8]) -> IResult<&[u8], PublicParams> {
    map(
        tuple((
            // a one-octet size of the following field
            // octets representing a curve OID
            map_opt(length_data(be_u8), ecc_curve_from_oid),
            // MPI of an EC point representing a public key
            mpi,
            // a one-octet size of the following fields
            be_u8,
            // a one-octet value 01, reserved for future extensions
            tag(&[1][..]),
            // a one-octet hash function ID used with a KDF
            map(be_u8, HashAlgorithm::from),
            // a one-octet algorithm ID for the symmetric algorithm used to wrap
            // the symmetric key used for the message encryption
            map_res(be_u8, SymmetricKeyAlgorithm::try_from),
        )),
        |(curve, p, _len2, _tag, hash, alg_sym)| PublicParams::ECDH {
            curve,
            p: p.to_owned(),
            hash,
            alg_sym,
        },
    )(i)
}

fn elgamal(i: &[u8]) -> IResult<&[u8], PublicParams> {
    map(
        tuple((
            // MPI of Elgamal prime p
            map(mpi, to_owned),
            // MPI of Elgamal group generator g
            map(mpi, to_owned),
            // MPI of Elgamal public key value y (= g**x mod p where x is secret)
            map(mpi, to_owned),
        )),
        |(p, g, y)| PublicParams::Elgamal { p, g, y },
    )(i)
}

fn dsa(i: &[u8]) -> IResult<&[u8], PublicParams> {
    map(
        tuple((
            map(mpi, to_owned),
            map(mpi, to_owned),
            map(mpi, to_owned),
            map(mpi, to_owned),
        )),
        |(p, q, g, y)| PublicParams::DSA { p, q, g, y },
    )(i)
}

fn rsa(i: &[u8]) -> IResult<&[u8], PublicParams> {
    map(pair(map(mpi, to_owned), map(mpi, to_owned)), |(n, e)| {
        PublicParams::RSA { n, e }
    })(i)
}

fn unknown(i: &[u8], len: Option<usize>) -> IResult<&[u8], PublicParams> {
    if let Some(pub_len) = len {
        let (i, data) = take(pub_len)(i)?;
        Ok((
            i,
            PublicParams::Unknown {
                data: data.to_vec(),
            },
        ))
    } else {
        // we don't know how many bytes to consume
        Ok((i, PublicParams::Unknown { data: vec![] }))
    }
}

/// Parse the fields of a public key.
pub fn parse_pub_fields(
    typ: PublicKeyAlgorithm,
    len: Option<usize>,
) -> impl Fn(&[u8]) -> IResult<&[u8], PublicParams> {
    move |i: &[u8]| match typ {
        PublicKeyAlgorithm::RSA | PublicKeyAlgorithm::RSAEncrypt | PublicKeyAlgorithm::RSASign => {
            rsa(i)
        }
        PublicKeyAlgorithm::DSA => dsa(i),
        PublicKeyAlgorithm::ECDSA => ecdsa(i),
        PublicKeyAlgorithm::ECDH => ecdh(i),
        PublicKeyAlgorithm::Elgamal | PublicKeyAlgorithm::ElgamalSign => elgamal(i),
        PublicKeyAlgorithm::EdDSALegacy => eddsa_legacy(i),

        PublicKeyAlgorithm::Ed25519 => ed25519(i),
        PublicKeyAlgorithm::X25519 => x25519(i),
        PublicKeyAlgorithm::Ed448 => unknown(i, len), // FIXME: implement later
        PublicKeyAlgorithm::X448 => x448(i),

        PublicKeyAlgorithm::DiffieHellman
        | PublicKeyAlgorithm::Private100
        | PublicKeyAlgorithm::Private101
        | PublicKeyAlgorithm::Private102
        | PublicKeyAlgorithm::Private103
        | PublicKeyAlgorithm::Private104
        | PublicKeyAlgorithm::Private105
        | PublicKeyAlgorithm::Private106
        | PublicKeyAlgorithm::Private107
        | PublicKeyAlgorithm::Private108
        | PublicKeyAlgorithm::Private109
        | PublicKeyAlgorithm::Private110
        | PublicKeyAlgorithm::Unknown(_) => unknown(i, len),
    }
}

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

            (i, Some(len as usize))
        } else {
            (i, None)
        };

        // If we got a pub_len, we expect to consume this amount of data, and have `expected_rest`
        // left after `parse_pub_fields`
        let expected_rest = pub_len.map(|len| i.len() - len);

        let (i, params) = parse_pub_fields(alg, pub_len)(i)?;

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
        let (i, params) = parse_pub_fields(alg, None)(i)?;

        Ok((i, (*key_ver, alg, created_at, Some(exp), params)))
    }
}

/// Parse a public key packet (Tag 6)
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.5.1.1
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

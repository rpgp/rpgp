use chrono::{DateTime, TimeZone, Utc};
use nom::bytes::streaming::tag;
use nom::combinator::{map, map_opt, map_res};
use nom::multi::length_data;
use nom::number::streaming::{be_u16, be_u32, be_u8};
use nom::sequence::{pair, tuple};

use crate::crypto::ecc_curve::ecc_curve_from_oid;
use crate::crypto::hash::HashAlgorithm;
use crate::crypto::public_key::PublicKeyAlgorithm;
use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::errors::IResult;
use crate::packet::Span;
use crate::types::{mpi, EcdsaPublicParams, KeyVersion, Mpi, MpiRef, PublicParams};

#[inline]
fn to_owned(mref: MpiRef<'_>) -> Mpi {
    mref.to_owned()
}

/// Ref: https://tools.ietf.org/html/rfc6637#section-9
fn ecdsa(i: Span<'_>) -> IResult<Span<'_>, PublicParams> {
    // a one-octet size of the following field
    // octets representing a curve OID
    let (i, curve) = map_opt(length_data(be_u8), |curve_raw: Span<'_>| {
        ecc_curve_from_oid(*curve_raw.fragment())
    })(i)?;

    // MPI of an EC point representing a public key
    let (i, p) = mpi(i)?;
    Ok((
        i,
        PublicParams::ECDSA(EcdsaPublicParams::try_from_mpi(p, curve)?),
    ))
}

/// https://tools.ietf.org/html/draft-koch-eddsa-for-openpgp-00#section-4
fn eddsa(i: Span<'_>) -> IResult<Span<'_>, PublicParams> {
    let (i, curve) = map_opt(
        // a one-octet size of the following field
        length_data(be_u8),
        // octets representing a curve OID
        |c: Span<'_>| ecc_curve_from_oid(*c.fragment()),
    )(i)?;
    // MPI of an EC point representing a public key
    let (i, q) = mpi(i)?;
    Ok((
        i,
        PublicParams::EdDSA {
            curve,
            q: q.to_owned(),
        },
    ))
}

/// Ref: https://tools.ietf.org/html/rfc6637#section-9
fn ecdh(i: Span<'_>) -> IResult<Span<'_>, PublicParams> {
    // a one-octet size of the following field
    // octets representing a curve OID
    let (i, curve) = map_opt(length_data(be_u8), |s: Span<'_>| {
        ecc_curve_from_oid(*s.fragment())
    })(i)?;
    // MPI of an EC point representing a public key
    let (i, p) = mpi(i)?;
    // a one-octet size of the following fields
    let (i, _len2) = be_u8(i)?;
    // a one-octet value 01, reserved for future extensions
    let (i, _tag) = tag(&[1][..])(i)?;
    // a one-octet hash function ID used with a KDF
    let (i, hash) = map(be_u8, HashAlgorithm::from)(i)?;
    // a one-octet algorithm ID for the symmetric algorithm used to wrap
    // the symmetric key used for the message encryption
    let (i, alg_sym) = map_res(be_u8, SymmetricKeyAlgorithm::try_from)(i)?;

    Ok((
        i,
        PublicParams::ECDH {
            curve,
            p: p.to_owned(),
            hash,
            alg_sym,
        },
    ))
}

fn elgamal(i: Span<'_>) -> IResult<Span<'_>, PublicParams> {
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

fn dsa(i: Span<'_>) -> IResult<Span<'_>, PublicParams> {
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

fn rsa(i: Span<'_>) -> IResult<Span<'_>, PublicParams> {
    map(pair(map(mpi, to_owned), map(mpi, to_owned)), |(n, e)| {
        PublicParams::RSA { n, e }
    })(i)
}

fn unknown(i: Span<'_>) -> IResult<Span<'_>, PublicParams> {
    Ok((i, PublicParams::Unknown { data: vec![] })) // FIXME
}

/// Parse the fields of a public key.
pub fn parse_pub_fields(
    typ: PublicKeyAlgorithm,
) -> impl Fn(Span<'_>) -> IResult<Span<'_>, PublicParams> {
    move |i: Span<'_>| match typ {
        PublicKeyAlgorithm::RSA | PublicKeyAlgorithm::RSAEncrypt | PublicKeyAlgorithm::RSASign => {
            rsa(i)
        }
        PublicKeyAlgorithm::DSA => dsa(i),
        PublicKeyAlgorithm::ECDSA => ecdsa(i),
        PublicKeyAlgorithm::ECDH => ecdh(i),
        PublicKeyAlgorithm::Elgamal | PublicKeyAlgorithm::ElgamalSign => elgamal(i),
        PublicKeyAlgorithm::EdDSA => eddsa(i),

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
        | PublicKeyAlgorithm::Unknown(_) => unknown(i),
    }
}

fn new_public_key_parser(
    key_ver: &KeyVersion,
) -> impl Fn(
    Span<'_>,
) -> IResult<
    Span<'_>,
    (
        KeyVersion,
        PublicKeyAlgorithm,
        DateTime<Utc>,
        Option<u16>,
        PublicParams,
    ),
> + '_ {
    |i: Span<'_>| {
        let (i, created_at) = map_opt(be_u32, |v| Utc.timestamp_opt(i64::from(v), 0).single())(i)?;
        let (i, alg) = map(be_u8, PublicKeyAlgorithm::from)(i)?;
        let (i, params) = parse_pub_fields(alg)(i)?;
        Ok((i, (*key_ver, alg, created_at, None, params)))
    }
}

fn old_public_key_parser(
    key_ver: &KeyVersion,
) -> impl Fn(
    Span<'_>,
) -> IResult<
    Span<'_>,
    (
        KeyVersion,
        PublicKeyAlgorithm,
        DateTime<Utc>,
        Option<u16>,
        PublicParams,
    ),
> + '_ {
    |i: Span<'_>| {
        let (i, created_at) = map_opt(be_u32, |v| Utc.timestamp_opt(i64::from(v), 0).single())(i)?;
        let (i, exp) = be_u16(i)?;
        let (i, alg) = map(be_u8, PublicKeyAlgorithm::from)(i)?;
        let (i, params) = parse_pub_fields(alg)(i)?;

        Ok((i, (*key_ver, alg, created_at, Some(exp), params)))
    }
}

/// Parse a public key packet (Tag 6)
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.5.1.1
#[allow(clippy::type_complexity)]
pub(crate) fn parse(
    i: Span<'_>,
) -> IResult<
    Span<'_>,
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
        &KeyVersion::V2 | &KeyVersion::V3 => old_public_key_parser(&key_ver)(i)?,
        &KeyVersion::V4 => new_public_key_parser(&key_ver)(i)?,
        KeyVersion::V5 | KeyVersion::Other(_) => {
            return Err(nom::Err::Error(crate::errors::Error::Unsupported(format!(
                "Unsupported key version {}",
                u8::from(key_ver)
            ))))
        }
    };
    Ok((i, key))
}

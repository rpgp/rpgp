use chrono::{DateTime, TimeZone, Utc};
use nom::bytes::streaming::tag;
use nom::combinator::{map, map_opt};
use nom::multi::length_data;
use nom::number::streaming::{be_u16, be_u32, be_u8};
use nom::sequence::{pair, tuple};
use num_traits::FromPrimitive;

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
fn eddsa(i: &[u8]) -> IResult<&[u8], PublicParams> {
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
        PublicParams::EdDSA {
            curve,
            q: q.to_owned(),
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
            map_opt(be_u8, HashAlgorithm::from_u8),
            // a one-octet algorithm ID for the symmetric algorithm used to wrap
            // the symmetric key used for the message encryption
            map_opt(be_u8, SymmetricKeyAlgorithm::from_u8),
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

/// Parse the fields of a public key.
pub fn parse_pub_fields(typ: PublicKeyAlgorithm) -> impl Fn(&[u8]) -> IResult<&[u8], PublicParams> {
    move |i: &[u8]| match typ {
        PublicKeyAlgorithm::RSA | PublicKeyAlgorithm::RSAEncrypt | PublicKeyAlgorithm::RSASign => {
            rsa(i)
        }
        PublicKeyAlgorithm::DSA => dsa(i),
        PublicKeyAlgorithm::ECDSA => ecdsa(i),
        PublicKeyAlgorithm::ECDH => ecdh(i),
        PublicKeyAlgorithm::Elgamal | PublicKeyAlgorithm::ElgamalSign => elgamal(i),
        PublicKeyAlgorithm::EdDSA => eddsa(i),
        _ => Err(nom::Err::Error(crate::errors::Error::ParsingError(
            nom::error::ErrorKind::Switch,
        ))),
    }
}

fn new_public_key_parser(
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
        let (i, alg) = map_opt(be_u8, PublicKeyAlgorithm::from_u8)(i)?;
        let (i, params) = parse_pub_fields(alg)(i)?;
        Ok((i, (*key_ver, alg, created_at, None, params)))
    }
}

fn old_public_key_parser(
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
        let (i, alg) = map_opt(be_u8, PublicKeyAlgorithm::from_u8)(i)?;
        let (i, params) = parse_pub_fields(alg)(i)?;

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
    let (i, key_ver) = map_opt(be_u8, KeyVersion::from_u8)(i)?;
    let (i, key) = match &key_ver {
        &KeyVersion::V2 | &KeyVersion::V3 => old_public_key_parser(&key_ver)(i)?,
        &KeyVersion::V4 => new_public_key_parser(&key_ver)(i)?,
        KeyVersion::V5 => {
            return Err(nom::Err::Error(crate::errors::Error::ParsingError(
                nom::error::ErrorKind::Switch,
            )))
        }
    };
    Ok((i, key))
}

use bstr::BString;
use chrono::{DateTime, Duration, TimeZone, Utc};
use nom::bytes::streaming::{tag, take};
use nom::combinator::{complete, map, map_opt, map_parser, map_res, rest};
use nom::multi::{length_data, many0};
use nom::number::streaming::{be_u16, be_u32, be_u8};
use nom::sequence::{pair, tuple};
use nom::InputLength;
use smallvec::SmallVec;

use crate::crypto::aead::AeadAlgorithm;
use crate::crypto::hash::HashAlgorithm;
use crate::crypto::public_key::PublicKeyAlgorithm;
use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::de::Deserialize;
use crate::errors::{IResult, Result};
use crate::packet::signature::types::*;
use crate::packet::single::Span;
use crate::types::{
    mpi, CompressionAlgorithm, KeyId, Mpi, RevocationKey, RevocationKeyClass, Version,
};
use crate::util::{clone_into_array, packet_length};

impl Deserialize for Signature {
    /// Parses a `Signature` packet from the given slice.
    fn from_slice(packet_version: Version, input: Span<'_>) -> Result<Self> {
        let (_, pk) = parse(packet_version)(input)?;

        Ok(pk)
    }
}

/// Convert an epoch timestamp to a `DateTime`
fn dt_from_timestamp(ts: u32) -> Option<DateTime<Utc>> {
    DateTime::from_timestamp(i64::from(ts), 0)
}

/// Convert a u32 to a `Duration`
fn duration_from_timestamp(ts: u32) -> Option<Duration> {
    Duration::try_seconds(i64::from(ts))
}

/// Parse a signature creation time subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.4
fn signature_creation_time(i: Span<'_>) -> IResult<Span<'_>, SubpacketData> {
    map_opt(
        // 4-octet time field
        be_u32,
        |date| dt_from_timestamp(date).map(SubpacketData::SignatureCreationTime),
    )(i)
}

/// Parse an issuer subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.5
fn issuer(i: Span<'_>) -> IResult<Span<'_>, SubpacketData> {
    map(
        map_res(complete(take(8u8)), KeyId::from_slice),
        SubpacketData::Issuer,
    )(i)
}

/// Parse a key expiration time subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.6
fn key_expiration(i: Span<'_>) -> IResult<Span<'_>, SubpacketData> {
    map_opt(
        // 4-octet time field
        be_u32,
        |date| duration_from_timestamp(date).map(SubpacketData::KeyExpirationTime),
    )(i)
}

/// Parse a preferred symmetric algorithms subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.7
fn pref_sym_alg(mut body: Span<'_>) -> IResult<Span<'_>, SubpacketData> {
    let mut list: SmallVec<[SymmetricKeyAlgorithm; 8]> = Default::default();
    while body.input_len() > 0 {
        let (i, el) = be_u8(body)?;
        list.push(SymmetricKeyAlgorithm::from(el));
        body = i;
    }

    Ok((body, SubpacketData::PreferredSymmetricAlgorithms(list)))
}

/// Parse a preferred hash algorithms subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.8
fn pref_hash_alg(mut body: Span<'_>) -> IResult<Span<'_>, SubpacketData> {
    let mut list: SmallVec<[HashAlgorithm; 8]> = Default::default();
    while body.input_len() > 0 {
        let (i, el) = be_u8(body)?;
        list.push(HashAlgorithm::from(el));
        body = i;
    }

    Ok((body, SubpacketData::PreferredHashAlgorithms(list)))
}

/// Parse a preferred compression algorithms subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.9
fn pref_com_alg(mut body: Span<'_>) -> IResult<Span<'_>, SubpacketData> {
    let mut list: SmallVec<[CompressionAlgorithm; 8]> = Default::default();
    while body.input_len() > 0 {
        let (i, el) = be_u8(body)?;
        list.push(CompressionAlgorithm::from(el));
        body = i;
    }

    Ok((body, SubpacketData::PreferredCompressionAlgorithms(list)))
}

/// Parse a signature expiration time subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.10
fn signature_expiration_time(i: Span<'_>) -> IResult<Span<'_>, SubpacketData> {
    map_opt(
        // 4-octet time field
        be_u32,
        |date| duration_from_timestamp(date).map(SubpacketData::SignatureExpirationTime),
    )(i)
}

/// Parse a exportable certification subpacket.
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.11
fn exportable_certification(i: Span<'_>) -> IResult<Span<'_>, SubpacketData> {
    map(complete(be_u8), |v| {
        SubpacketData::ExportableCertification(v == 1)
    })(i)
}

/// Parse a revocable subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.12
fn revocable(i: Span<'_>) -> IResult<Span<'_>, SubpacketData> {
    map(complete(be_u8), |v| SubpacketData::Revocable(v == 1))(i)
}

/// Parse a trust signature subpacket.
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.13
fn trust_signature(i: Span<'_>) -> IResult<Span<'_>, SubpacketData> {
    map(pair(be_u8, be_u8), |(depth, value)| {
        SubpacketData::TrustSignature(depth, value)
    })(i)
}

/// Parse a regular expression subpacket.
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.14
fn regular_expression(i: Span<'_>) -> IResult<Span<'_>, SubpacketData> {
    let (i, data) = rest(i)?;
    let regex = BString::from(*data.fragment());
    Ok((i, SubpacketData::RegularExpression(regex)))
}

/// Parse a revocation key subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.15
fn revocation_key(i: Span<'_>) -> IResult<Span<'_>, SubpacketData> {
    let (i, class) = map_res(be_u8, RevocationKeyClass::try_from)(i)?;
    let (i, pub_alg) = map(be_u8, PublicKeyAlgorithm::from)(i)?;
    // TODO: V5 Keys have 32 octets here
    let (i, fp) = take(20u8)(i)?;

    Ok((
        i,
        SubpacketData::RevocationKey(RevocationKey::new(class, pub_alg, *fp.fragment())),
    ))
}

/// Parse a notation data subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.16
fn notation_data(i: Span<'_>) -> IResult<Span<'_>, SubpacketData> {
    // Flags
    let (i, readable) = map(be_u8, |v| v == 0x80)(i)?;
    let (i, _) = tag(&[0, 0, 0])(i)?;
    let (i, name_len) = be_u16(i)?;
    let (i, value_len) = be_u16(i)?;
    let (i, name) = take(name_len)(i)?;
    let (i, value) = take(value_len)(i)?;

    Ok((
        i,
        SubpacketData::Notation(Notation {
            readable,
            name: BString::from(*name.fragment()),
            value: BString::from(*value.fragment()),
        }),
    ))
}

/// Parse a key server preferences subpacket
/// https://tools.ietf.org/html/rfc4880.html#section-5.2.3.17
fn key_server_prefs(i: Span<'_>) -> IResult<Span<'_>, SubpacketData> {
    let (i, data) = rest(i)?;

    Ok((
        i,
        SubpacketData::KeyServerPreferences(SmallVec::from_slice(*data.fragment())),
    ))
}

/// Parse a preferred key server subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.18
fn preferred_key_server(i: Span<'_>) -> IResult<Span<'_>, SubpacketData> {
    let (i, body) = map_res(rest, |body: Span<'_>| std::str::from_utf8(*body.fragment()))(i)?;

    Ok((i, SubpacketData::PreferredKeyServer(body.to_string())))
}

/// Parse a primary user id subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.19
fn primary_userid(i: Span<'_>) -> IResult<Span<'_>, SubpacketData> {
    map(be_u8, |a| SubpacketData::IsPrimary(a == 1))(i)
}

/// Parse a policy URI subpacket.
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.20
fn policy_uri(i: Span<'_>) -> IResult<Span<'_>, SubpacketData> {
    let (i, body) = map_res(rest, |body: Span<'_>| std::str::from_utf8(*body.fragment()))(i)?;

    Ok((i, SubpacketData::PolicyURI(body.to_string())))
}

/// Parse a key flags subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.21
fn key_flags(i: Span<'_>) -> IResult<Span<'_>, SubpacketData> {
    let (i, body) = rest(i)?;

    Ok((
        i,
        SubpacketData::KeyFlags(SmallVec::from_slice(*body.fragment())),
    ))
}

/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.22
fn signers_userid(i: Span<'_>) -> IResult<Span<'_>, SubpacketData> {
    let (i, body) = rest(i)?;

    Ok((
        i,
        SubpacketData::SignersUserID(BString::from(*body.fragment())),
    ))
}

/// Parse a features subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.24
fn features(i: Span<'_>) -> IResult<Span<'_>, SubpacketData> {
    let (i, body) = rest(i)?;
    Ok((
        i,
        SubpacketData::Features(SmallVec::from_slice(*body.fragment())),
    ))
}

/// Parse a revocation reason subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.23
fn rev_reason(i: Span<'_>) -> IResult<Span<'_>, SubpacketData> {
    let (i, code) = be_u8(i)?;
    let (i, reason) = rest(i)?;

    Ok((
        i,
        SubpacketData::RevocationReason(code.into(), BString::from(*reason.fragment())),
    ))
}

/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.25
fn sig_target(i: Span<'_>) -> IResult<Span<'_>, SubpacketData> {
    map(
        tuple((
            map(be_u8, PublicKeyAlgorithm::from),
            map(be_u8, HashAlgorithm::from),
            rest,
        )),
        |(pub_alg, hash_alg, hash): (_, _, Span<'_>)| {
            SubpacketData::SignatureTarget(pub_alg, hash_alg, hash.to_vec())
        },
    )(i)
}

/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.26
fn embedded_sig(i: Span<'_>) -> IResult<Span<'_>, SubpacketData> {
    let (i, sig) = parse(Version::New)(i)?;

    Ok((i, SubpacketData::EmbeddedSignature(Box::new(sig))))
}

/// Parse an issuer subpacket
/// Ref: https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-05#section-5.2.3.28
fn issuer_fingerprint(i: Span<'_>) -> IResult<Span<'_>, SubpacketData> {
    let (i, version) = be_u8(i)?;
    let (i, fingerprint) = rest(i)?;

    Ok((
        i,
        SubpacketData::IssuerFingerprint(
            version.into(),
            SmallVec::from_slice(*fingerprint.fragment()),
        ),
    ))
}

/// Parse a preferred aead subpacket
fn pref_aead_alg(mut body: Span<'_>) -> IResult<Span<'_>, SubpacketData> {
    let mut list: SmallVec<[AeadAlgorithm; 2]> = Default::default();
    while body.input_len() > 0 {
        let (i, el) = be_u8(body)?;
        list.push(AeadAlgorithm::from(el));
        body = i;
    }

    Ok((body, SubpacketData::PreferredAeadAlgorithms(list)))
}

fn subpacket(
    typ: SubpacketType,
    is_critical: bool,
    body: Span<'_>,
) -> IResult<Span<'_>, Subpacket> {
    use self::SubpacketType::*;
    debug!(
        "parsing subpacket: {:?} {}",
        typ,
        hex::encode(body.fragment())
    );

    let res = match typ {
        SignatureCreationTime => signature_creation_time(body),
        SignatureExpirationTime => signature_expiration_time(body),
        ExportableCertification => exportable_certification(body),
        TrustSignature => trust_signature(body),
        RegularExpression => regular_expression(body),
        Revocable => revocable(body),
        KeyExpirationTime => key_expiration(body),
        PreferredSymmetricAlgorithms => pref_sym_alg(body),
        RevocationKey => revocation_key(body),
        Issuer => issuer(body),
        Notation => notation_data(body),
        PreferredHashAlgorithms => pref_hash_alg(body),
        PreferredCompressionAlgorithms => pref_com_alg(body),
        KeyServerPreferences => key_server_prefs(body),
        PreferredKeyServer => preferred_key_server(body),
        PrimaryUserId => primary_userid(body),
        PolicyURI => policy_uri(body),
        KeyFlags => key_flags(body),
        SignersUserID => signers_userid(body),
        RevocationReason => rev_reason(body),
        Features => features(body),
        SignatureTarget => sig_target(body),
        EmbeddedSignature => embedded_sig(body),
        IssuerFingerprint => issuer_fingerprint(body),
        PreferredAead => pref_aead_alg(body),
        Experimental(n) => {
            let (i, body) = rest(body)?;
            Ok((
                i,
                SubpacketData::Experimental(n, SmallVec::from_slice(*body.fragment())),
            ))
        }
        Other(n) => {
            let (i, body) = rest(body)?;
            Ok((i, SubpacketData::Other(n, body.to_vec())))
        }
    };
    let res = res.map(|(body, data)| (body, Subpacket { is_critical, data }));

    if res.is_err() {
        warn!("invalid subpacket: {:?} {:?}", typ, res);
    }

    res
}

fn subpackets(i: Span<'_>) -> IResult<Span<'_>, Vec<Subpacket>> {
    many0(complete(subpacket_with_header))(i)
}

fn subpacket_with_header(i: Span<'_>) -> IResult<Span<'_>, Subpacket> {
    // the subpacket length (1, 2, or 5 octets)
    let (i, len) = packet_length(i)?;
    // the subpacket type (1 octet)
    let (i, typ) = map(be_u8, SubpacketType::from_u8)(i)?;
    let (i, val) = take(len - 1)(i)?;
    let (sub_rest, subpacket) = subpacket(typ.0, typ.1, val)?;
    debug_assert!(sub_rest.is_empty());

    Ok((i, subpacket))
}

fn actual_signature(
    typ: &PublicKeyAlgorithm,
) -> impl Fn(Span<'_>) -> IResult<Span<'_>, Vec<Mpi>> + '_ {
    move |i: Span<'_>| match typ {
        &PublicKeyAlgorithm::RSA | &PublicKeyAlgorithm::RSASign => {
            map(mpi, |v| vec![v.to_owned()])(i)
        }
        &PublicKeyAlgorithm::DSA | &PublicKeyAlgorithm::ECDSA | &PublicKeyAlgorithm::EdDSA => {
            let (i, first) = mpi(i)?;
            let (i, second) = mpi(i)?;
            let mpis = vec![first.to_owned(), second.to_owned()];
            Ok((i, mpis))
        }
        &PublicKeyAlgorithm::Private100
        | &PublicKeyAlgorithm::Private101
        | &PublicKeyAlgorithm::Private102
        | &PublicKeyAlgorithm::Private103
        | &PublicKeyAlgorithm::Private104
        | &PublicKeyAlgorithm::Private105
        | &PublicKeyAlgorithm::Private106
        | &PublicKeyAlgorithm::Private107
        | &PublicKeyAlgorithm::Private108
        | &PublicKeyAlgorithm::Private109
        | &PublicKeyAlgorithm::Private110 => map(mpi, |v| vec![v.to_owned()])(i),
        _ => Ok((i, vec![])), // don't assume format, could be non-MPI
    }
}

/// Parse a v2 or v3 signature packet
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.2
fn v3_parser(
    packet_version: Version,
    version: SignatureVersion,
) -> impl Fn(Span<'_>) -> IResult<Span<'_>, Signature> {
    move |i: Span<'_>| {
        // let (i, (_tag, typ, created, issuer, pub_alg, hash_alg, ls_hash)) = tuple((
        // One-octet length of following hashed material. MUST be 5.
        let (i, _tag) = tag(&[5])(i)?;
        // One-octet signature type.
        let (i, typ) = map_res(be_u8, SignatureType::try_from)(i)?;
        // Four-octet creation time.
        let (i, created) = map_opt(be_u32, |v| Utc.timestamp_opt(i64::from(v), 0).single())(i)?;
        // Eight-octet Key ID of signer.
        let (i, issuer) = take(8usize)(i)?;
        let issuer = KeyId::from_slice(issuer)?;
        // One-octet public-key algorithm.
        let (i, pub_alg) = map(be_u8, PublicKeyAlgorithm::from)(i)?;
        // One-octet hash algorithm.
        let (i, hash_alg) = map(be_u8, HashAlgorithm::from)(i)?;
        // Two-octet field holding left 16 bits of signed hash value.
        let (i, ls_hash) = take(2usize)(i)?;

        // One or more multiprecision integers comprising the signature.
        let (i, sig) = actual_signature(&pub_alg)(i)?;
        Ok((i, {
            let mut s = Signature::new(
                packet_version,
                version,
                typ,
                pub_alg,
                hash_alg,
                clone_into_array(ls_hash.fragment()),
                sig,
                vec![],
                vec![],
            );

            s.config.created = Some(created);
            s.config.issuer = Some(issuer);

            s
        }))
    }
}

/// Parse a v4 or v5 signature packet
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3
fn v4_parser(
    packet_version: Version,
    version: SignatureVersion,
) -> impl Fn(Span<'_>) -> IResult<Span<'_>, Signature> {
    move |i: Span<'_>| {
        let (i, (typ, pub_alg, hash_alg, hsub, usub, ls_hash)) = tuple((
            // One-octet signature type.
            map_res(be_u8, SignatureType::try_from),
            // One-octet public-key algorithm.
            map(be_u8, PublicKeyAlgorithm::from),
            // One-octet hash algorithm.
            map(be_u8, HashAlgorithm::from),
            // Two-octet scalar octet count for following hashed subpacket data.
            // Hashed subpacket data set (zero or more subpackets).
            map_parser(length_data(be_u16), subpackets),
            // Two-octet scalar octet count for the following unhashed subpacket data.
            // Unhashed subpacket data set (zero or more subpackets).
            map_parser(length_data(be_u16), subpackets),
            // Two-octet field holding the left 16 bits of the signed hash value.
            take(2usize),
        ))(i)?;
        // One or more multiprecision integers comprising the signature.
        let (i, sig) = actual_signature(&pub_alg)(i)?;
        Ok((
            i,
            Signature::new(
                packet_version,
                version,
                typ,
                pub_alg,
                hash_alg,
                clone_into_array(ls_hash.fragment()),
                sig,
                hsub,
                usub,
            ),
        ))
    }
}

fn invalid_version(_body: Span<'_>, version: SignatureVersion) -> IResult<Span<'_>, Signature> {
    Err(nom::Err::Error(crate::errors::Error::Unsupported(format!(
        "unknown signature version {version:?}"
    ))))
}

/// Parse a signature packet (Tag 2)
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2
fn parse(packet_version: Version) -> impl Fn(Span<'_>) -> IResult<Span<'_>, Signature> {
    move |i| {
        let (i, version) = map(be_u8, SignatureVersion::from)(i)?;

        debug!("parsing signature: {:?}", version);

        let (i, signature) = match &version {
            &SignatureVersion::V2 | &SignatureVersion::V3 => v3_parser(packet_version, version)(i),
            &SignatureVersion::V4 | &SignatureVersion::V5 => v4_parser(packet_version, version)(i),
            _ => invalid_version(i, version),
        }?;
        Ok((i, signature))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::{Deserializable, StandaloneSignature};

    #[test]
    fn test_subpacket_pref_sym_alg() {
        let input = vec![9, 8, 7, 3, 2];
        let (_, res) = pref_sym_alg(Span::new(input.as_slice())).unwrap();
        assert_eq!(
            res,
            SubpacketData::PreferredSymmetricAlgorithms(
                input
                    .iter()
                    .map(|i| SymmetricKeyAlgorithm::from(*i))
                    .collect()
            )
        );
    }

    #[test]
    fn test_unknown_revocation_code() {
        let revocation = "-----BEGIN PGP SIGNATURE-----

wsASBCAWCgCEBYJlrwiYCRACvMqAWdPpHUcUAAAAAAAeACBzYWx0QG5vdGF0aW9u
cy5zZXF1b2lhLXBncC5vcmfPfjVZJ9PXSt4854s05WU+Tj5QZwuhA5+LEHEUborP
PxQdQnJldm9jYXRpb24gbWVzc2FnZRYhBKfuT6/w5BLl1XTGUgK8yoBZ0+kdAABi
lQEAkpvZ3A2RGtRdCne/dOZtqoX7oCCZKCPyfZS9I9roc5oBAOj4aklEBejYuTKF
SW+kj0jFDKC2xb/o8hbkTpwPtsoI
=0ajX
-----END PGP SIGNATURE-----";

        let (sig, _) = StandaloneSignature::from_armor_single(revocation.as_bytes()).unwrap();

        let rc = sig.signature.revocation_reason_code();

        assert!(rc.is_some());
        assert!(matches!(rc.unwrap(), RevocationCode::Other(0x42)));
    }
}

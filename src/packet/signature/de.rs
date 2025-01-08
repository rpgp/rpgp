use std::str;

use bstr::BString;
use chrono::{DateTime, Duration, TimeZone, Utc};
use log::{debug, warn};
use nom::bytes::streaming::{tag, take};
use nom::combinator::{complete, map, map_opt, map_parser, map_res, rest};
use nom::multi::{fold_many_m_n, length_data, many0};
use nom::number::streaming::{be_u16, be_u32, be_u8};
use nom::sequence::{pair, tuple};
use smallvec::SmallVec;

use crate::crypto::aead::AeadAlgorithm;
use crate::crypto::hash::HashAlgorithm;
use crate::crypto::public_key::PublicKeyAlgorithm;
use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::errors::{IResult, Result};
use crate::packet::signature::types::*;
use crate::types::{
    mpi, CompressionAlgorithm, Fingerprint, KeyId, KeyVersion, Mpi, MpiRef, RevocationKey,
    RevocationKeyClass, SignatureBytes, Version,
};
use crate::util::{clone_into_array, packet_length};

impl Signature {
    /// Parses a `Signature` packet from the given slice.
    pub fn from_slice(packet_version: Version, input: &[u8]) -> Result<Self> {
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

/// Parse a Signature Creation Time subpacket
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-signature-creation-time
fn signature_creation_time(i: &[u8]) -> IResult<&[u8], SubpacketData> {
    map_opt(
        // 4-octet time field
        be_u32,
        |date| dt_from_timestamp(date).map(SubpacketData::SignatureCreationTime),
    )(i)
}

/// Parse an Issuer Key ID subpacket
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-issuer-key-id
fn issuer(i: &[u8]) -> IResult<&[u8], SubpacketData> {
    let (i, key_id_raw) = take(8u8)(i)?;
    let key_id_raw: [u8; 8] = key_id_raw.try_into().expect("took 8");
    let key_id = KeyId::from(key_id_raw);
    Ok((i, SubpacketData::Issuer(key_id)))
}

/// Parse a Key Expiration Time subpacket
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-key-expiration-time
fn key_expiration(i: &[u8]) -> IResult<&[u8], SubpacketData> {
    map_opt(
        // 4-octet time field
        be_u32,
        |date| duration_from_timestamp(date).map(SubpacketData::KeyExpirationTime),
    )(i)
}

/// Parse a Preferred Symmetric Ciphers for v1 SEIPD subpacket
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#preferred-v1-seipd
fn pref_sym_alg(body: &[u8]) -> IResult<&[u8], SubpacketData> {
    let list: SmallVec<[SymmetricKeyAlgorithm; 8]> = body
        .iter()
        .map(|v| Ok(SymmetricKeyAlgorithm::from(*v)))
        .collect::<Result<_>>()?;

    Ok((&b""[..], SubpacketData::PreferredSymmetricAlgorithms(list)))
}

/// Parse a Preferred AEAD Ciphersuites subpacket (for SEIPD v2)
///
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-preferred-aead-ciphersuites
fn pref_aead_alg(body: &[u8]) -> IResult<&[u8], SubpacketData> {
    if body.len() % 2 != 0 {
        return Err(nom::Err::Error(crate::errors::Error::Message(format!(
            "Illegal preferred aead subpacket len {} must be a multiple of 2",
            body.len(),
        ))));
    }

    let list: SmallVec<[(SymmetricKeyAlgorithm, AeadAlgorithm); 4]> = body
        .chunks(2)
        .map(|v| (SymmetricKeyAlgorithm::from(v[0]), AeadAlgorithm::from(v[1])))
        .collect();

    Ok((&b""[..], SubpacketData::PreferredAeadAlgorithms(list)))
}

/// Parse a Preferred Hash Algorithms subpacket
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-preferred-hash-algorithms
fn pref_hash_alg(body: &[u8]) -> IResult<&[u8], SubpacketData> {
    let list: SmallVec<[HashAlgorithm; 8]> = body
        .iter()
        .map(|v| Ok(HashAlgorithm::from(*v)))
        .collect::<Result<_>>()?;

    Ok((&b""[..], SubpacketData::PreferredHashAlgorithms(list)))
}

/// Parse a Preferred Compression Algorithms subpacket
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-preferred-compression-algor
fn pref_com_alg(body: &[u8]) -> IResult<&[u8], SubpacketData> {
    let list: SmallVec<[CompressionAlgorithm; 8]> = body
        .iter()
        .map(|v| Ok(CompressionAlgorithm::from(*v)))
        .collect::<Result<_>>()?;

    Ok((
        &b""[..],
        SubpacketData::PreferredCompressionAlgorithms(list),
    ))
}

/// Parse a Signature Expiration Time subpacket
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-signature-expiration-time
fn signature_expiration_time(i: &[u8]) -> IResult<&[u8], SubpacketData> {
    map_opt(
        // 4-octet time field
        be_u32,
        |date| duration_from_timestamp(date).map(SubpacketData::SignatureExpirationTime),
    )(i)
}

/// Parse an Exportable Certification subpacket.
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-exportable-certification
fn exportable_certification(i: &[u8]) -> IResult<&[u8], SubpacketData> {
    map(complete(be_u8), |v| {
        SubpacketData::ExportableCertification(v == 1)
    })(i)
}

/// Parse a Revocable subpacket
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-revocable
fn revocable(i: &[u8]) -> IResult<&[u8], SubpacketData> {
    map(complete(be_u8), |v| SubpacketData::Revocable(v == 1))(i)
}

/// Parse a Trust Signature subpacket.
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-trust-signature
fn trust_signature(i: &[u8]) -> IResult<&[u8], SubpacketData> {
    map(pair(be_u8, be_u8), |(depth, value)| {
        SubpacketData::TrustSignature(depth, value)
    })(i)
}

/// Parse a Regular Expression subpacket.
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-regular-expression
fn regular_expression(i: &[u8]) -> IResult<&[u8], SubpacketData> {
    map(map(rest, BString::from), SubpacketData::RegularExpression)(i)
}

/// Parse a Revocation Key subpacket (Deprecated)
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-revocation-key-deprecated
fn revocation_key(i: &[u8]) -> IResult<&[u8], SubpacketData> {
    map(
        tuple((
            map_res(be_u8, RevocationKeyClass::try_from),
            map(be_u8, PublicKeyAlgorithm::from),
            // TODO: V5 Keys have 32 octets here
            take(20u8),
        )),
        |(class, algorithm, fp)| {
            SubpacketData::RevocationKey(RevocationKey::new(class, algorithm, fp))
        },
    )(i)
}

/// Parse a Notation Data subpacket
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-notation-data
fn notation_data(i: &[u8]) -> IResult<&[u8], SubpacketData> {
    // Flags
    let (i, readable) = map(be_u8, |v| v == 0x80)(i)?;
    let (i, _) = tag(&[0, 0, 0])(i)?;
    let (i, name_len) = be_u16(i)?;
    let (i, value_len) = be_u16(i)?;
    let (i, name) = map(take(name_len), BString::from)(i)?;
    let (i, value) = map(take(value_len), BString::from)(i)?;

    Ok((
        i,
        SubpacketData::Notation(Notation {
            readable,
            name,
            value,
        }),
    ))
}

/// Parse a Key Server Preferences subpacket
/// https://www.rfc-editor.org/rfc/rfc9580.html#name-key-server-preferences
fn key_server_prefs(body: &[u8]) -> IResult<&[u8], SubpacketData> {
    Ok((
        &b""[..],
        SubpacketData::KeyServerPreferences(SmallVec::from_slice(body)),
    ))
}

/// Parse a Preferred Key Server subpacket
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-preferred-key-server
fn preferred_key_server(i: &[u8]) -> IResult<&[u8], SubpacketData> {
    map(map_res(rest, str::from_utf8), |body| {
        SubpacketData::PreferredKeyServer(body.to_string())
    })(i)
}

/// Parse a Primary User ID subpacket
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-primary-user-id
fn primary_userid(i: &[u8]) -> IResult<&[u8], SubpacketData> {
    map(be_u8, |a| SubpacketData::IsPrimary(a == 1))(i)
}

/// Parse a Policy URI subpacket.
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-policy-uri
fn policy_uri(i: &[u8]) -> IResult<&[u8], SubpacketData> {
    map(map_res(rest, str::from_utf8), |body| {
        SubpacketData::PolicyURI(body.to_owned())
    })(i)
}

/// Parse a Key Flags subpacket
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-key-flags
fn key_flags(body: &[u8]) -> IResult<&[u8], SubpacketData> {
    Ok((
        &b""[..],
        SubpacketData::KeyFlags(SmallVec::from_slice(body)),
    ))
}

/// Parse a Signer's User ID subpacket
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-key-flags
fn signers_userid(i: &[u8]) -> IResult<&[u8], SubpacketData> {
    Ok((&[], SubpacketData::SignersUserID(BString::from(i))))
}

/// Parse a Reason for Revocation subpacket
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-key-flags
fn rev_reason(i: &[u8]) -> IResult<&[u8], SubpacketData> {
    map(
        pair(map(be_u8, RevocationCode::from), map(rest, BString::from)),
        |(code, reason)| SubpacketData::RevocationReason(code, reason),
    )(i)
}

/// Parse a Features subpacket
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-features
fn features(body: &[u8]) -> IResult<&[u8], SubpacketData> {
    Ok((
        &b""[..],
        SubpacketData::Features(SmallVec::from_slice(body)),
    ))
}

/// Parse a Signature Target subpacket
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-signature-target
fn sig_target(i: &[u8]) -> IResult<&[u8], SubpacketData> {
    map(
        tuple((
            map(be_u8, PublicKeyAlgorithm::from),
            map(be_u8, HashAlgorithm::from),
            rest,
        )),
        |(pub_alg, hash_alg, hash): (_, _, &[u8])| {
            SubpacketData::SignatureTarget(pub_alg, hash_alg, hash.to_vec())
        },
    )(i)
}

/// Parse an Embedded Signature subpacket
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-embedded-signature
fn embedded_sig(i: &[u8]) -> IResult<&[u8], SubpacketData> {
    map(parse(Version::New), |sig| {
        SubpacketData::EmbeddedSignature(Box::new(sig))
    })(i)
}

/// Parse an Issuer Fingerprint subpacket
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-issuer-fingerprint
fn issuer_fingerprint(i: &[u8]) -> IResult<&[u8], SubpacketData> {
    let (i, version) = map(be_u8, KeyVersion::from)(i)?;

    // This subpacket is only used for v4 and newer fingerprints
    if version != KeyVersion::V4 && version != KeyVersion::V5 && version != KeyVersion::V6 {
        return Err(invalid_key_version(version));
    }

    if let Some(fingerprint_len) = version.fingerprint_len() {
        let (i, fingerprint) = take(fingerprint_len)(i)?;
        let fp = Fingerprint::new(version, fingerprint)?;

        Ok((i, SubpacketData::IssuerFingerprint(fp)))
    } else {
        Err(invalid_key_version(version))
    }
}

/// Parse a preferred encryption modes subpacket (non-RFC subpacket for GnuPG "OCB" mode)
fn preferred_encryption_modes(body: &[u8]) -> IResult<&[u8], SubpacketData> {
    let list: SmallVec<[AeadAlgorithm; 2]> = body.iter().map(|v| AeadAlgorithm::from(*v)).collect();

    Ok((&b""[..], SubpacketData::PreferredEncryptionModes(list)))
}

/// Parse an Intended Recipient Fingerprint subpacket
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-intended-recipient-fingerpr
fn intended_recipient_fingerprint(i: &[u8]) -> IResult<&[u8], SubpacketData> {
    let (i, version) = map(be_u8, KeyVersion::from)(i)?;

    // This subpacket is only used for v4 and newer fingerprints
    if version != KeyVersion::V4 && version != KeyVersion::V5 && version != KeyVersion::V6 {
        return Err(invalid_key_version(version));
    }

    if let Some(fingerprint_len) = version.fingerprint_len() {
        let (i, fingerprint) = take(fingerprint_len)(i)?;
        let fp = Fingerprint::new(version, fingerprint)?;

        Ok((i, SubpacketData::IntendedRecipientFingerprint(fp)))
    } else {
        Err(invalid_key_version(version))
    }
}

fn subpacket(typ: SubpacketType, is_critical: bool, body: &[u8]) -> IResult<&[u8], Subpacket> {
    use self::SubpacketType::*;
    debug!("parsing subpacket: {:?} {}", typ, hex::encode(body));

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
        PreferredEncryptionModes => preferred_encryption_modes(body),
        IntendedRecipientFingerprint => intended_recipient_fingerprint(body),
        PreferredAead => pref_aead_alg(body),
        Experimental(n) => Ok((
            body,
            SubpacketData::Experimental(n, SmallVec::from_slice(body)),
        )),
        Other(n) => Ok((body, SubpacketData::Other(n, body.to_vec()))),
    };

    let res = res.map(|(body, data)| (body, Subpacket { is_critical, data }));

    if res.is_err() {
        warn!("invalid subpacket: {:?} {:?}", typ, res);
    }

    res
}

fn subpackets<'a>(i: &'a [u8]) -> IResult<&'a [u8], Vec<Subpacket>> {
    many0(complete(|i: &'a [u8]| {
        // the subpacket length (1, 2, or 5 octets)
        let (i, len) = packet_length(i)?;
        if len == 0 {
            return Err(nom::Err::Error(crate::errors::Error::InvalidInput));
        }
        // the subpacket type (1 octet)
        let (i, typ) = map(be_u8, SubpacketType::from_u8)(i)?;
        map_parser(take(len - 1), move |b| subpacket(typ.0, typ.1, b))(i)
    }))(i)
}

fn actual_signature(
    typ: &PublicKeyAlgorithm,
) -> impl Fn(&[u8]) -> IResult<&[u8], SignatureBytes> + '_ {
    move |i: &[u8]| match typ {
        &PublicKeyAlgorithm::RSA | &PublicKeyAlgorithm::RSASign => {
            map(mpi, |v| vec![v.to_owned()].into())(i)
        }
        &PublicKeyAlgorithm::DSA
        | &PublicKeyAlgorithm::ECDSA
        | &PublicKeyAlgorithm::EdDSALegacy => fold_many_m_n(
            2,
            2,
            mpi,
            Vec::new,
            |mut acc: Vec<Mpi>, item: MpiRef<'_>| {
                acc.push(item.to_owned());
                acc
            },
        )(i)
        .map(|(i, sig)| (i, sig.into())),

        &PublicKeyAlgorithm::Ed25519 => {
            let (i, sig) = nom::bytes::complete::take(64u8)(i)?;

            Ok((i, SignatureBytes::Native(sig.to_vec())))
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
        | &PublicKeyAlgorithm::Private110 => map(mpi, |v| vec![v.to_owned()].into())(i),
        _ => Ok((i, SignatureBytes::Native(vec![]))), // don't assume format, could be non-MPI
    }
}

/// Parse a v2 or v3 signature packet
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-version-3-signature-packet-
fn v3_parser(
    packet_version: Version,
    version: SignatureVersion,
) -> impl Fn(&[u8]) -> IResult<&[u8], Signature> {
    move |i: &[u8]| {
        // One-octet length of following hashed material. MUST be 5.
        let (i, _tag) = tag(&[5])(i)?;
        // One-octet signature type.
        let (i, typ) = map_res(be_u8, SignatureType::try_from)(i)?;
        // Four-octet creation time.
        let (i, created) = map_opt(be_u32, |v| Utc.timestamp_opt(i64::from(v), 0).single())(i)?;
        // Eight-octet Key ID of signer.
        let (i, key_id_raw) = take(8usize)(i)?;
        let key_id_raw: [u8; 8] = key_id_raw.try_into().expect("took 8");
        let issuer = KeyId::from(key_id_raw);
        // One-octet public-key algorithm.
        let (i, pub_alg) = map(be_u8, PublicKeyAlgorithm::from)(i)?;
        // One-octet hash algorithm.
        let (i, hash_alg) = map(be_u8, HashAlgorithm::from)(i)?;
        // Two-octet field holding left 16 bits of signed hash value.
        let (i, ls_hash) = take(2usize)(i)?;

        // The SignatureBytes comprising the signature.
        let (i, sig) = actual_signature(&pub_alg)(i)?;

        match version {
            SignatureVersion::V2 => Ok((i, {
                Signature::v2(
                    packet_version,
                    typ,
                    pub_alg,
                    hash_alg,
                    created,
                    issuer,
                    clone_into_array(ls_hash),
                    sig,
                )
            })),
            SignatureVersion::V3 => Ok((i, {
                Signature::v3(
                    packet_version,
                    typ,
                    pub_alg,
                    hash_alg,
                    created,
                    issuer,
                    clone_into_array(ls_hash),
                    sig,
                )
            })),
            _ => Err(nom::Err::Error(crate::errors::Error::Message(
                "must only be called for V2/V3".to_string(),
            ))),
        }
    }
}

/// Parse a v4 signature packet
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-versions-4-and-6-signature-
fn v4_parser(
    packet_version: Version,
    version: SignatureVersion,
) -> impl Fn(&[u8]) -> IResult<&[u8], Signature> {
    move |i: &[u8]| {
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
        // The SignatureBytes comprising the signature.
        let (i, sig) = actual_signature(&pub_alg)(i)?;

        if version != SignatureVersion::V4 {
            return Err(nom::Err::Error(crate::errors::Error::Message(format!(
                "Unsupported version {:?}",
                version
            ))));
        }

        Ok((
            i,
            Signature::v4(
                packet_version,
                typ,
                pub_alg,
                hash_alg,
                clone_into_array(ls_hash),
                sig,
                hsub,
                usub,
            ),
        ))
    }
}

/// Parse a v6 signature packet
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-versions-4-and-6-signature-
fn v6_parser(packet_version: Version) -> impl Fn(&[u8]) -> IResult<&[u8], Signature> {
    move |i: &[u8]| {
        let (i, (typ, pub_alg, hash_alg, hsub, usub, ls_hash)) = tuple((
            // One-octet signature type.
            map_res(be_u8, SignatureType::try_from),
            // One-octet public-key algorithm.
            map(be_u8, PublicKeyAlgorithm::from),
            // One-octet hash algorithm.
            map(be_u8, HashAlgorithm::from),
            // Four-octet scalar octet count for following hashed subpacket data.
            // Hashed subpacket data set (zero or more subpackets).
            map_parser(length_data(be_u32), subpackets),
            // Four-octet scalar octet count for the following unhashed subpacket data.
            // Unhashed subpacket data set (zero or more subpackets).
            map_parser(length_data(be_u32), subpackets),
            // Two-octet field holding the left 16 bits of the signed hash value.
            take(2usize),
        ))(i)?;

        // A variable-length field containing:
        // A one-octet salt size. The value MUST match the value defined for the hash algorithm as specified in Table 23.
        // The salt; a random value of the specified size.
        let (i, len) = be_u8(i)?;
        let (i, salt) = take(len)(i)?;

        if hash_alg.salt_len() != Some(salt.len()) {
            return Err(nom::Err::Error(crate::errors::Error::Message(format!(
                "Illegal salt length {} found for {:?}",
                salt.len(),
                hash_alg
            ))));
        }

        // The SignatureBytes comprising the signature.
        let (i, sig) = actual_signature(&pub_alg)(i)?;
        Ok((
            i,
            Signature::v6(
                packet_version,
                typ,
                pub_alg,
                hash_alg,
                clone_into_array(ls_hash),
                sig,
                hsub,
                usub,
                salt.to_vec(),
            ),
        ))
    }
}

fn invalid_sig_version(version: SignatureVersion) -> nom::Err<crate::errors::Error> {
    nom::Err::Error(crate::errors::Error::Unsupported(format!(
        "invalid signature version {version:?}"
    )))
}

fn invalid_key_version(version: KeyVersion) -> nom::Err<crate::errors::Error> {
    nom::Err::Error(crate::errors::Error::Unsupported(format!(
        "invalid key version {version:?}"
    )))
}

/// Parse a signature packet (Tag 2)
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-signature-packet-type-id-2
fn parse(packet_version: Version) -> impl Fn(&[u8]) -> IResult<&[u8], Signature> {
    move |i: &[u8]| {
        let (i, version) = map(be_u8, SignatureVersion::from)(i)?;
        let (i, signature) = match &version {
            &SignatureVersion::V2 | &SignatureVersion::V3 => v3_parser(packet_version, version)(i),
            &SignatureVersion::V4 | &SignatureVersion::V5 => v4_parser(packet_version, version)(i),
            &SignatureVersion::V6 => v6_parser(packet_version)(i),
            _ => Err(invalid_sig_version(version)),
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
        let (_, res) = pref_sym_alg(input.as_slice()).unwrap();
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

use std::boxed::Box;
use std::iter::Peekable;
use std::str;

use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use nom::{be_u16, be_u32, be_u8, rest, IResult};
use num_traits::FromPrimitive;
use smallvec::SmallVec;
use try_from::TryInto;

use crate::composed::Deserializable;
use crate::crypto::aead::AeadAlgorithm;
use crate::crypto::hash::HashAlgorithm;
use crate::crypto::public_key::PublicKeyAlgorithm;
use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::de::Deserialize;
use crate::errors::Result;
use crate::packet::signature::types::*;
use crate::packet::Packet;
use crate::types::{
    mpi, CompressionAlgorithm, KeyId, KeyVersion, Mpi, MpiRef, RevocationKey, RevocationKeyClass,
    Tag, Version,
};
use crate::util::{clone_into_array, packet_length, read_string};

impl Deserialize for Signature {
    /// Parses a `Signature` packet from the given slice.
    fn from_slice(packet_version: Version, input: &[u8]) -> Result<Self> {
        let (_, pk) = parse(input, packet_version)?;

        Ok(pk)
    }
}

impl Deserializable for Signature {
    /// Parse a signature.
    fn from_packets<'a>(
        packets: impl Iterator<Item = Packet> + 'a,
    ) -> Box<dyn Iterator<Item = Result<Self>> + 'a> {
        Box::new(SignatureParser {
            source: packets.peekable(),
        })
    }
}

pub struct SignatureParser<I: Sized + Iterator<Item = Packet>> {
    source: Peekable<I>,
}

impl<I: Sized + Iterator<Item = Packet>> Iterator for SignatureParser<I> {
    type Item = Result<Signature>;

    fn next(&mut self) -> Option<Self::Item> {
        next(self.source.by_ref())
    }
}

fn next<I: Iterator<Item = Packet>>(packets: &mut Peekable<I>) -> Option<Result<Signature>> {
    if let Some(packet) = packets.by_ref().next() {
        match packet.tag() {
            Tag::Signature => return Some(packet.try_into()),
            _ => return Some(Err(format_err!("unexpected packet {:?}", packet.tag()))),
        }
    }
    None
}

/// Convert an epoch timestamp to a `DateTime`
fn dt_from_timestamp(ts: u32) -> DateTime<Utc> {
    DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(i64::from(ts), 0), Utc)
}

// Parse a signature creation time subpacket
// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.4
named!(
    signature_creation_time<Subpacket>,
    map!(
        // 4-octet time field
        be_u32,
        |date| Subpacket::SignatureCreationTime(dt_from_timestamp(date))
    )
);

// Parse an issuer subpacket
// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.5
#[rustfmt::skip]
named!(issuer<Subpacket>, map!(
    map_res!(complete!(take!(8)), KeyId::from_slice),
    Subpacket::Issuer
));

// Parse a key expiration time subpacket
// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.6
#[rustfmt::skip]
named!(key_expiration<Subpacket>, map!(
    // 4-octet time field
    be_u32,
    |date| Subpacket::KeyExpirationTime(dt_from_timestamp(date))
));

/// Parse a preferred symmetric algorithms subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.7
fn pref_sym_alg(body: &[u8]) -> IResult<&[u8], Subpacket> {
    let list: SmallVec<[SymmetricKeyAlgorithm; 8]> = body
        .iter()
        .map(|v| {
            SymmetricKeyAlgorithm::from_u8(*v)
                .ok_or_else(|| format_err!("Invalid SymmetricKeyAlgorithm"))
        })
        .collect::<Result<_>>()?;

    Ok((&b""[..], Subpacket::PreferredSymmetricAlgorithms(list)))
}

/// Parse a preferred hash algorithms subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.8
fn pref_hash_alg(body: &[u8]) -> IResult<&[u8], Subpacket> {
    let list: SmallVec<[HashAlgorithm; 8]> = body
        .iter()
        .map(|v| HashAlgorithm::from_u8(*v).ok_or_else(|| format_err!("Invalid HashAlgorithm")))
        .collect::<Result<_>>()?;

    Ok((&b""[..], Subpacket::PreferredHashAlgorithms(list)))
}

/// Parse a preferred compression algorithms subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.9
fn pref_com_alg(body: &[u8]) -> IResult<&[u8], Subpacket> {
    let list: SmallVec<[CompressionAlgorithm; 8]> = body
        .iter()
        .map(|v| {
            CompressionAlgorithm::from_u8(*v)
                .ok_or_else(|| format_err!("Invalid CompressionAlgorithm"))
        })
        .collect::<Result<_>>()?;

    Ok((&b""[..], Subpacket::PreferredCompressionAlgorithms(list)))
}

// Parse a signature expiration time subpacket
// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.10
#[rustfmt::skip]
named!(signature_expiration_time<Subpacket>, map!(
    // 4-octet time field
    be_u32,
    |date| Subpacket::SignatureExpirationTime(dt_from_timestamp(date))
));

// Parse a exportable certification subpacket.
// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.11
named!(
    exportable_certification<Subpacket>,
    map!(complete!(be_u8), |v| Subpacket::ExportableCertification(
        v == 1
    ))
);

// Parse a revocable subpacket
// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.12
named!(
    revocable<Subpacket>,
    map!(complete!(be_u8), |v| Subpacket::Revocable(v == 1))
);

// Parse a trust signature subpacket.
// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.13
#[rustfmt::skip]
named!(trust_signature<Subpacket>, do_parse!(
       depth: be_u8
    >> value: be_u8
    >> (Subpacket::TrustSignature(depth, value))
));

// Parse a regular expression subpacket.
// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.14
#[rustfmt::skip]
named!(regular_expression<Subpacket>, map!(
    map!(rest, read_string), Subpacket::RegularExpression
));

// Parse a revocation key subpacket
// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.15
#[rustfmt::skip]
named!(revocation_key<Subpacket>, do_parse!(
             class: map_opt!(be_u8, RevocationKeyClass::from_u8)
    >>   algorithm: map_opt!(be_u8, PublicKeyAlgorithm::from_u8)
    // TODO: V5 Keys have 32 octets here
    >>          fp: take!(20)
    >> (Subpacket::RevocationKey(RevocationKey::new(
        class,
        algorithm,
        fp,
    )))
));

// Parse a notation data subpacket
// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.16
#[rustfmt::skip]
named!(notation_data<Subpacket>, do_parse!(
                  // Flags
        readable: map!(be_u8, |v| v == 0x80)
    >>            tag!(&[0, 0, 0])
    >>  name_len: be_u16
    >> value_len: be_u16
    >>      name: map!(take!(name_len), read_string)
    >>     value: map!(take!(value_len), read_string)
    >> (Subpacket::Notation(Notation { readable, name, value }))
));

/// Parse a key server preferences subpacket
/// https://tools.ietf.org/html/rfc4880.html#section-5.2.3.17
fn key_server_prefs(body: &[u8]) -> IResult<&[u8], Subpacket> {
    Ok((
        &b""[..],
        Subpacket::KeyServerPreferences(SmallVec::from_slice(body)),
    ))
}

// Parse a preferred key server subpacket
// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.18
#[rustfmt::skip]
named!(preferred_key_server<Subpacket>,do_parse!(
       body: map_res!(rest, str::from_utf8)
    >> ({ Subpacket::PreferredKeyServer(body.to_string()) })
));

// Parse a primary user id subpacket
// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.19
named!(
    primary_userid<Subpacket>,
    map!(be_u8, |a| Subpacket::IsPrimary(a == 1))
);

// Parse a policy URI subpacket.
// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.20
#[rustfmt::skip]
named!(policy_uri<Subpacket>, map!(
    map!(rest, read_string), Subpacket::PolicyURI
));

/// Parse a key flags subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.21
fn key_flags(body: &[u8]) -> IResult<&[u8], Subpacket> {
    Ok((&b""[..], Subpacket::KeyFlags(SmallVec::from_slice(body))))
}

// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.22
#[rustfmt::skip]
named!(signers_userid<Subpacket>, do_parse!(
       body: map_res!(rest, str::from_utf8)
    >> (Subpacket::SignersUserID(body.to_string())))
);

/// Parse a features subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.24
fn features(body: &[u8]) -> IResult<&[u8], Subpacket> {
    Ok((&b""[..], Subpacket::Features(SmallVec::from_slice(body))))
}

// Parse a revocation reason subpacket
// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.23
#[rustfmt::skip]
named!(rev_reason<Subpacket>, do_parse!(
         code: map_opt!(be_u8, RevocationCode::from_u8)
    >> reason: map!(rest, read_string)
    >> (Subpacket::RevocationReason(code, reason))
));

// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.25
#[rustfmt::skip]
named!(sig_target<Subpacket>, do_parse!(
        pub_alg: map_opt!(be_u8, PublicKeyAlgorithm::from_u8)
    >> hash_alg: map_opt!(be_u8, HashAlgorithm::from_u8)
    >>     hash: rest
    >> (Subpacket::SignatureTarget(pub_alg, hash_alg, hash.to_vec()))
));

// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.26
#[rustfmt::skip]
named!(embedded_sig<Subpacket>, map!(call!(parse, Version::New), |sig| {
    Subpacket::EmbeddedSignature(Box::new(sig))
}));

// Parse an issuer subpacket
// Ref: https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-05#section-5.2.3.28
#[rustfmt::skip]
named!(issuer_fingerprint<Subpacket>, do_parse!(
           version: map_opt!(be_u8, KeyVersion::from_u8)
    >> fingerprint: rest
    >> (Subpacket::IssuerFingerprint(version, SmallVec::from_slice(fingerprint)))
));

/// Parse a preferred aead subpacket
fn pref_aead_alg(body: &[u8]) -> IResult<&[u8], Subpacket> {
    let list: SmallVec<[AeadAlgorithm; 2]> = body
        .iter()
        .map(|v| AeadAlgorithm::from_u8(*v).ok_or_else(|| format_err!("Invalid AeadAlgorithm")))
        .collect::<Result<_>>()?;

    Ok((&b""[..], Subpacket::PreferredAeadAlgorithms(list)))
}

fn subpacket<'a>(typ: SubpacketType, body: &'a [u8]) -> IResult<&'a [u8], Subpacket> {
    use self::SubpacketType::*;
    info!("parsing subpacket: {:?} {}", typ, hex::encode(body));

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
        Experimental(n) => Ok((
            &body[..],
            Subpacket::Experimental(n, SmallVec::from_slice(body)),
        )),
        Other(n) => Ok((&body[..], Subpacket::Other(n, body.to_vec()))),
    };

    if res.is_err() {
        warn!("invalid subpacket: {:?} {:?}", typ, res);
    }

    res
}

#[rustfmt::skip]
named!(subpackets(&[u8]) -> Vec<Subpacket>, many0!(complete!(do_parse!(
    // the subpacket length (1, 2, or 5 octets)
        len: packet_length
    // the subpacket type (1 octet)
    >> typ: map_opt!(be_u8, SubpacketType::from_u8)
    >>   p: flat_map!(take!(len - 1), |b| subpacket(typ, b))
    >> (p)
))));

named_args!(actual_signature<'a>(typ: &PublicKeyAlgorithm) <&'a [u8], Vec<Mpi>>, switch!(
    value!(typ),
    &PublicKeyAlgorithm::RSA |
    &PublicKeyAlgorithm::RSASign => map!(call!(mpi), |v| vec![v.to_owned()]) |
    &PublicKeyAlgorithm::DSA   |
    &PublicKeyAlgorithm::ECDSA |
    &PublicKeyAlgorithm::EdDSA     => fold_many_m_n!(2, 2, mpi, Vec::new(), |mut acc: Vec<Mpi>, item: MpiRef<'_> | {
        acc.push(item.to_owned());
        acc
    }) |
    &PublicKeyAlgorithm::Private100 |
    &PublicKeyAlgorithm::Private101 |
    &PublicKeyAlgorithm::Private102 |
    &PublicKeyAlgorithm::Private103 |
    &PublicKeyAlgorithm::Private104 |
    &PublicKeyAlgorithm::Private105 |
    &PublicKeyAlgorithm::Private106 |
    &PublicKeyAlgorithm::Private107 |
    &PublicKeyAlgorithm::Private108 |
    &PublicKeyAlgorithm::Private109 |
    &PublicKeyAlgorithm::Private110  => map!(call!(mpi), |v| vec![v.to_owned()]) |
    _ => map!(call!(mpi), |v| vec![v.to_owned()])
));

// Parse a v2 or v3 signature packet
// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.2
#[rustfmt::skip]
named_args!(v3_parser(packet_version: Version, version: SignatureVersion) <Signature>, do_parse!(
    // One-octet length of following hashed material. MUST be 5.
                 tag!(&[5])
    // One-octet signature type.
    >>      typ: map_opt!(be_u8, SignatureType::from_u8)
    // Four-octet creation time.
    >>  created: map!(be_u32, |v| Utc.timestamp(i64::from(v), 0))
    // Eight-octet Key ID of signer.
    >>   issuer: map_res!(take!(8), KeyId::from_slice)
    // One-octet public-key algorithm.
    >>  pub_alg: map_opt!(be_u8, PublicKeyAlgorithm::from_u8)
    // One-octet hash algorithm.
    >> hash_alg: map_opt!(be_u8, HashAlgorithm::from_u8)
    // Two-octet field holding left 16 bits of signed hash value.
    >>  ls_hash: take!(2)
    // One or more multiprecision integers comprising the signature.
    >>      sig: call!(actual_signature, &pub_alg)
    >> ({
        let mut s = Signature::new(
            packet_version,
            version,
            typ,
            pub_alg,
            hash_alg,
            clone_into_array(ls_hash),
            sig,
            vec![],
            vec![],
        );

        s.config.created = Some(created);
        s.config.issuer = Some(issuer);

        s
    })
));

// Parse a v4 or v5 signature packet
// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3
#[rustfmt::skip]
named_args!(v4_parser(packet_version: Version, version: SignatureVersion) <Signature>, do_parse!(
    // One-octet signature type.
            typ: map_opt!(be_u8, SignatureType::from_u8)
    // One-octet public-key algorithm.
    >>  pub_alg: map_opt!(be_u8, PublicKeyAlgorithm::from_u8)
    // One-octet hash algorithm.
    >> hash_alg: map_opt!(be_u8, HashAlgorithm::from_u8)
    // Two-octet scalar octet count for following hashed subpacket data.
    >> hsub_len: be_u16
    // Hashed subpacket data set (zero or more subpackets).
    >>     hsub: flat_map!(take!(hsub_len), subpackets)
    // Two-octet scalar octet count for the following unhashed subpacket data.
    >> usub_len: be_u16
    // Unhashed subpacket data set (zero or more subpackets).
    >>     usub: flat_map!(take!(usub_len), subpackets)
    // Two-octet field holding the left 16 bits of the signed hash value.
    >>  ls_hash: take!(2)
    // One or more multiprecision integers comprising the signature.
    >>      sig: call!(actual_signature, &pub_alg)
    >> (Signature::new(
        packet_version,
        version,
        typ,
        pub_alg,
        hash_alg,
        clone_into_array(ls_hash),
        sig,
        hsub,
        usub,
    ))
));

fn invalid_version<'a>(_body: &'a [u8], version: SignatureVersion) -> IResult<&'a [u8], Signature> {
    unimplemented!("unknown signature version {:?}", version);
}

// Parse a signature packet (Tag 2)
// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2
#[rustfmt::skip]
named_args!(parse(packet_version: Version) <Signature>, do_parse!(
         version: map_opt!(be_u8, SignatureVersion::from_u8)
    >> signature: switch!(value!(&version),
                      &SignatureVersion::V2 => call!(v3_parser, packet_version, version) |
                      &SignatureVersion::V3 => call!(v3_parser, packet_version, version) |
                      &SignatureVersion::V4 => call!(v4_parser, packet_version, version) |
                      &SignatureVersion::V5 => call!(v4_parser, packet_version, version) |
                      _ => call!(invalid_version, version)
    )
    >> (signature)
));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subpacket_pref_sym_alg() {
        let input = vec![9, 8, 7, 3, 2];
        let (_, res) = pref_sym_alg(input.as_slice()).unwrap();
        assert_eq!(
            res,
            Subpacket::PreferredSymmetricAlgorithms(
                input
                    .iter()
                    .map(|i| SymmetricKeyAlgorithm::from_u8(*i).unwrap())
                    .collect()
            )
        );
    }
}

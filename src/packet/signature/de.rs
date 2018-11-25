use std::str;

use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use nom::{be_u16, be_u32, be_u8, rest, IResult};
use num_traits::FromPrimitive;

use crypto::hash::HashAlgorithm;
use crypto::public_key::PublicKeyAlgorithm;
use crypto::sym::SymmetricKeyAlgorithm;
use de::Deserialize;
use errors::Result;
use packet::signature::types::*;
use types::{CompressionAlgorithm, KeyId, RevocationKey};
use util::{clone_into_array, mpi, packet_length, read_string_lossy};

impl Deserialize for Signature {
    /// Parses a `Signature` packet from the given slice.
    fn from_slice(input: &[u8]) -> Result<Self> {
        let (_, pk) = parse(input)?;

        Ok(pk)
    }
}

/// Convert an epoch timestamp to a `DateTime`
fn dt_from_timestamp(ts: u32) -> DateTime<Utc> {
    DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(i64::from(ts), 0), Utc)
}

/// Parse a signature creation time subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.4
named!(
    signature_creation_time<Subpacket>,
    map!(
        // 4-octet time field
        be_u32,
        |date| Subpacket::SignatureCreationTime(dt_from_timestamp(date))
    )
);

/// Parse an issuer subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.5
named!(
    issuer<Subpacket>,
    map!(
        map_res!(complete!(take!(8)), KeyId::from_slice),
        Subpacket::Issuer
    )
);

/// Parse a key expiration time subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.6
named!(
    key_expiration<Subpacket>,
    map!(
        // 4-octet time field
        be_u32,
        |date| Subpacket::KeyExpirationTime(dt_from_timestamp(date))
    )
);

/// Parse a preferred symmetric algorithms subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.7
#[rustfmt::skip]
named!(pref_sym_alg<Subpacket>, do_parse!(
       algs: many0!(complete!(map_opt!(be_u8, SymmetricKeyAlgorithm::from_u8)))
    >> (Subpacket::PreferredSymmetricAlgorithms(algs))
));

/// Parse a preferred hash algorithms subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.8
#[rustfmt::skip]
named!(pref_hash_alg<Subpacket>, do_parse!(
        algs: many0!(complete!(map_opt!(be_u8, HashAlgorithm::from_u8)))
    >> (Subpacket::PreferredHashAlgorithms(algs))
));

/// Parse a preferred compression algorithms subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.9
#[rustfmt::skip]
named!(pref_com_alg<Subpacket>,do_parse!(
        algs: many0!(complete!(map_opt!(be_u8, CompressionAlgorithm::from_u8)))
    >> (Subpacket::PreferredCompressionAlgorithms(algs))
));

/// Parse a signature expiration time subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.10
named!(
    signature_expiration_time<Subpacket>,
    map!(
        // 4-octet time field
        be_u32,
        |date| Subpacket::SignatureExpirationTime(dt_from_timestamp(date))
    )
);

/// Parse a exportable certification subpacket.
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.11
named!(
    exportable_certification<Subpacket>,
    map!(complete!(be_u8), |v| Subpacket::ExportableCertification(
        v == 1
    ))
);

/// Parse a revocable subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.12
named!(
    revocable<Subpacket>,
    map!(complete!(be_u8), |v| Subpacket::Revocable(v == 1))
);

/// Parse a trust signature subpacket.
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.13
#[rustfmt::skip]
named!(trust_signature<Subpacket>, do_parse!(
       depth: be_u8
    >> value: be_u8
    >> (Subpacket::TrustSignature(depth, value))
));

/// Parse a regular expression subpacket.
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.14
named!(
    regular_expression<Subpacket>,
    map!(map_res!(rest, str::from_utf8), |v| {
        Subpacket::RegularExpression(v.to_string())
    })
);

/// Parse a revocation key subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.15
#[rustfmt::skip]
named!(revocation_key<Subpacket>, do_parse!(
             class: be_u8
    >>   algorithm: map_opt!(be_u8, PublicKeyAlgorithm::from_u8)
    >>          fp: take!(20)
    >> (Subpacket::RevocationKey(RevocationKey {
        class,
        algorithm,
        fingerprint: clone_into_array(fp)
    }))
));

/// Parse a notation data subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.16
#[rustfmt::skip]
named!(notation_data<Subpacket>, do_parse!(
                  // Flags
        readable: map!(be_u8, |v| v == 0x80)
    >>            tag!(&[0, 0, 0])
    >>  name_len: be_u16
    >> value_len: be_u16
    >>      name: map!(take!(name_len), read_string_lossy)
    >>     value: map!(take!(value_len), read_string_lossy)
    >> (Subpacket::Notation(Notation { readable, name, value }))
));

/// Parse a key server preferences subpacket
/// https://tools.ietf.org/html/rfc4880.html#section-5.2.3.17
fn key_server_prefs(body: &[u8]) -> IResult<&[u8], Subpacket> {
    Ok((&b""[..], Subpacket::KeyServerPreferences(body.to_vec())))
}

/// Parse a preferred key server subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.18
#[rustfmt::skip]
named!(preferred_key_server<Subpacket>,do_parse!(
       body: map_res!(rest, str::from_utf8)
    >> ({ Subpacket::PreferredKeyServer(body.to_string()) })
));

/// Parse a primary user id subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.19
named!(
    primary_userid<Subpacket>,
    map!(be_u8, |a| Subpacket::IsPrimary(a == 1))
);

/// Parse a policy URI subpacket.
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.20
named!(
    policy_uri<Subpacket>,
    map!(map_res!(rest, str::from_utf8), |v| Subpacket::PolicyURI(
        v.to_string()
    ))
);

/// Parse a key flags subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.21
fn key_flags(body: &[u8]) -> IResult<&[u8], Subpacket> {
    Ok((&b""[..], Subpacket::KeyFlags(body.to_vec())))
}

/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.22
#[rustfmt::skip]
named!(signers_userid<Subpacket>, do_parse!(
       body: map_res!(rest, str::from_utf8)
    >> (Subpacket::SignersUserID(body.to_string())))
);

/// Parse a features subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.24
fn features(body: &[u8]) -> IResult<&[u8], Subpacket> {
    Ok((&b""[..], Subpacket::Features(body.to_vec())))
}

/// Parse a revocation reason subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.23
#[rustfmt::skip]
named!(rev_reason<Subpacket>, do_parse!(
         code: map_opt!(be_u8, RevocationCode::from_u8)
    >> reason: map!(rest, read_string_lossy)
    >> (Subpacket::RevocationReason(code, reason))
));

/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.26
named!(
    embedded_sig<Subpacket>,
    map!(parse, |sig| Subpacket::EmbeddedSignature(Box::new(sig)))
);

fn subpacket<'a>(typ: &SubpacketType, body: &'a [u8]) -> IResult<&'a [u8], Subpacket> {
    use self::SubpacketType::*;

    let res = match *typ {
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
        NotationData => notation_data(body),
        PreferredHashAlgorithms => pref_hash_alg(body),
        PreferredCompressionAlgorithms => pref_com_alg(body),
        KeyServerPreferences => key_server_prefs(body),
        PreferredKeyServer => preferred_key_server(body),
        PrimaryUserID => primary_userid(body),
        PolicyURI => policy_uri(body),
        KeyFlags => key_flags(body),
        SignersUserID => signers_userid(body),
        RevocationReason => rev_reason(body),
        Features => features(body),
        SignatureTarget => unimplemented!("{:?}", typ),
        EmbeddedSignature => embedded_sig(body),
        Experimental => Ok((&body[..], Subpacket::Experimental(body.to_vec()))),
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
    >>   p: flat_map!(take!(len - 1), |b| subpacket(&typ, b))
    >> (p)
))));

named_args!(actual_signature<'a>(typ: &PublicKeyAlgorithm) <&'a [u8], Vec<u8>>, switch!(
    value!(typ),
    &PublicKeyAlgorithm::RSA |
    &PublicKeyAlgorithm::RSASign => map!(call!(mpi), |v| v.to_vec()) |
    &PublicKeyAlgorithm::DSA   |
    &PublicKeyAlgorithm::ECDSA |
    // TODO: Handle EdDSA signature parameters being encoded in little-endian format
    // Rref https://tools.ietf.org/html/rfc8032#section-5.1.2
    &PublicKeyAlgorithm::EdDSA     => fold_many_m_n!(2, 2, mpi, Vec::new(), |mut acc: Vec<_>, item| {
        acc.extend(item);
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
    &PublicKeyAlgorithm::Private110  => value!(Vec::new()) |
    // everybody else gets nothing
    // TODO: handle this better
    _ => value!(Vec::new())
));

/// Parse a v2 or v3 signature packet
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.2
#[rustfmt::skip]
named_args!(v3_parser(version: SignatureVersion) <Signature>, do_parse!(
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
            version,
            typ,
            pub_alg,
            hash_alg,
            ls_hash.to_vec(),
            sig.to_vec(),
            vec![],
            vec![],
        );
        s.created = Some(created);
        s.issuer = Some(issuer);

        s
    })
));

/// Parse a v4 or v5 signature packet
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3
#[rustfmt::skip]
named_args!(v4_parser(version: SignatureVersion) <Signature>, do_parse!(
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
        version,
        typ,
        pub_alg,
        hash_alg,
        ls_hash.to_vec(),
        sig.to_vec(),
        hsub,
        usub,
    ))
));

fn invalid_version<'a>(_body: &'a [u8], version: SignatureVersion) -> IResult<&'a [u8], Signature> {
    unimplemented!("unknown signature version {:?}", version);
}

/// Parse a signature packet (Tag 2)
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2
#[rustfmt::skip]
named!(parse<Signature>, do_parse!(
         version: map_opt!(be_u8, SignatureVersion::from_u8)
    >> signature: switch!(value!(&version),
                      &SignatureVersion::V2 => call!(v3_parser, version) |
                      &SignatureVersion::V3 => call!(v3_parser, version) |
                      &SignatureVersion::V4 => call!(v4_parser, version) |
                      &SignatureVersion::V5 => call!(v4_parser, version) |
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

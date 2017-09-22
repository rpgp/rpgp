use enum_primitive::FromPrimitive;
use nom::{be_u8, be_u16, be_u32, rest, IResult};
use chrono::{DateTime, NaiveDateTime, Utc};
use std::str;

use packet::types::{Signature, SignatureVersion, SignatureType, PublicKeyAlgorithm, HashAlgorithm,
                    Subpacket, SubpacketType, SymmetricKeyAlgorithm, CompressionAlgorithm,
                    RevocationCode};
use util::{clone_into_array, packet_length};

enum_from_primitive!{
#[derive(Debug, PartialEq, Eq, Clone)]
/// Available key flags
pub enum KeyFlag {
    /// This key may be used to certify other keys.
    CertifyKeys = 0x01,
    /// This key may be used to sign data.
    SignData = 0x02,
    /// This key may be used to encrypt communications.
    EncryptCommunication = 0x04,
    /// This key may be used to encrypt storage.
    EncryptStorage = 0x08,
    /// The private component of this key may have been split by a secret-sharing mechanism.
    SplitPrivateKey = 0x10,
    /// This key may be used for authentication.
    Authentication = 0x20,
    /// The private component of this key may be in the possession of more than one person.
    SharedPrivateKey = 0x80,
}
}

/// Convert an epoch timestamp to a `DateTime`
fn dt_from_timestamp(ts: u32) -> DateTime<Utc> {
    DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(ts as i64, 0), Utc)
}

/// Parse a signature creation time subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.4
named!(signature_creation_time<Subpacket>, map!(
    // 4-octet time field
    be_u32, 
    |date| {
        Subpacket::SignatureCreationTime(dt_from_timestamp(date))
    }
));

/// Parse an issuer subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.5
named!(issuer<Subpacket>, map!(
    // 8-octet Key ID
    take!(8),
    |id| Subpacket::Issuer(clone_into_array(id))
));

/// Parse a preferred symmetric algorithms subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.7
named!(pref_sym_alg<Subpacket>, map!(
    many1!(
        map_opt!(
            be_u8,
            SymmetricKeyAlgorithm::from_u8
        )
    ),
    |algs| Subpacket::PreferredSymmetricAlgorithms(algs)
));

/// Parse a preferred hash algorithms subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.8
named!(pref_hash_alg<Subpacket>, map!(
    many1!(
        map_opt!(
            be_u8,
            HashAlgorithm::from_u8
        )
    ),
    |algs| Subpacket::PreferredHashAlgorithms(algs)
));

/// Parse a preferred compression algorithms subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.9
named!(pref_com_alg<Subpacket>, map!(
    many1!(
        map_opt!(
            be_u8,
            CompressionAlgorithm::from_u8
        )
    ),
    |algs| Subpacket::PreferredCompressionAlgorithms(algs)
));

/// Parse a key server preferences subpacket
/// https://tools.ietf.org/html/rfc4880.html#section-5.2.3.17
fn key_server_prefs(body: &[u8]) -> IResult<&[u8], Subpacket> {
    IResult::Done(&b""[..], Subpacket::KeyServerPreferences(body.to_vec()))
}

/// Parse a key flags subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.21
fn key_flags(body: &[u8]) -> IResult<&[u8], Subpacket> {
    IResult::Done(&b""[..], Subpacket::KeyFlags(body.to_vec()))
}

/// Parse a features subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.24
fn features(body: &[u8]) -> IResult<&[u8], Subpacket> {
    IResult::Done(&b""[..], Subpacket::Features(body.to_vec()))
}

named!(rev_reason<Subpacket>, do_parse!(
         code: map_opt!(be_u8, RevocationCode::from_u8)
    >> reason: rest
    >> (Subpacket::RevocationReason(code, reason.to_vec()))
));

named!(primary_userid<Subpacket>, map!(be_u8, |a| Subpacket::IsPrimary(a == 1)));

fn subpacket<'a>(typ: SubpacketType, body: &'a [u8]) -> IResult<&'a [u8], Subpacket> {
    use self::SubpacketType::*;
    match typ {
        SignatureCreationTime => signature_creation_time(body),
        Issuer => issuer(body),
        PreferredSymmetricAlgorithms => pref_sym_alg(body),
        PreferredHashAlgorithms => pref_hash_alg(body),
        PreferredCompressionAlgorithms => pref_com_alg(body),
        KeyServerPreferences => key_server_prefs(body),
        KeyFlags => key_flags(body),
        Features => features(body),
        RevocationReason => rev_reason(body),
        PrimaryUserID => primary_userid(body),
        _ => unimplemented!("{:?}", typ),
    }
}

named!(subpackets<Vec<Subpacket>>, many0!(do_parse!(
    // the subpacket length (1, 2, or 5 octets)
       len: packet_length
    // the subpacket type (1 octet)
    >> typ: map_opt!(be_u8, SubpacketType::from_u8)
    >>   p: flat_map!(take!(len - 1), |b| subpacket(typ, b))
    >> (p)
)));

/// Parse a v3 signature packet
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.2
named!(v3_parser<Signature>, do_parse!(
    // One-octet length of following hashed material. MUST be 5.
            tag!(&[5])
    // One-octet signature type.
    >> typ: map_opt!(be_u8, SignatureType::from_u8)
    >> (Signature::new(SignatureVersion::V3, typ,
        PublicKeyAlgorithm::RSA,
        HashAlgorithm::SHA1
    ))
    // TODO
    // - 
    //   - 
    //   - Four-octet creation time.
    //   - Eight-octet Key ID of signer.
    //  - One-octet public-key algorithm.
    //      - One-octet hash algorithm.
    //      - Two-octet field holding left 16 bits of signed hash value.
    //      - One or more multiprecision integers comprising the signature.
    //        This portion is algorithm specific, as described below.)
));

/// Parse a v4 signature packet
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3
named!(v4_parser<Signature>, do_parse!(
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
    // One or more multiprecision integers comprising the signature.
   >> ({
       let mut sig = Signature::new(SignatureVersion::V4, typ, pub_alg, hash_alg);

       for p in hsub {
           use self::Subpacket::*;
           match p {
               SignatureCreationTime(d)             => sig.created = Some(d),
               Issuer(a)                            => sig.issuer = Some(a),               
               PreferredSymmetricAlgorithms(list)   => sig.preferred_symmetric_algs = list,
               PreferredHashAlgorithms(list)        => sig.preferred_hash_algs = list,
               PreferredCompressionAlgorithms(list) => sig.preferred_compression_algs = list,
               KeyServerPreferences(f)              => sig.key_server_prefs = f,
               KeyFlags(f)                          => sig.key_flags = f,
               Features(f)                          => sig.features = f,
               RevocationReason(code, body)         => {
                   sig.revocation_reason_code = Some(code);
                   sig.revocation_reason_string = Some(str::from_utf8(body.as_slice()).unwrap().to_string());
               },
               IsPrimary(b)                         => sig.is_primary = b,
           }
       }
       
       sig.unhashed_subpackets = usub;
       sig
   })
));

/// Parse a signature packet (Tag 2)
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2
named!(pub parser<Signature>, do_parse!(
    // Version
       ver: map_opt!(be_u8, SignatureVersion::from_u8)
    >> sig: switch!(value!(&ver),
                &SignatureVersion::V3 => call!(v3_parser) |
                &SignatureVersion::V4 => call!(v4_parser)
            )
    >> (sig)
));

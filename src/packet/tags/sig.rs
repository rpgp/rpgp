use enum_primitive::FromPrimitive;
use nom::{be_u8, be_u16};

use packet::types::{Signature, SignatureVersion, SignatureType, PublicKeyAlgorithm, HashAlgorithm};
use util::u16_as_usize;

enum_from_primitive!{
#[derive(Debug, PartialEq, Eq, Clone)]
/// Available signature subpacket types
pub enum SubpacketType {
    SignatureCreationTime = 2,
    SignatureExpirationTime = 3,
    ExportableCertification = 4,
    TrustSignature = 5,
    RegularExpression = 6,
    Revocable = 7,
    Reserved = 8,
    KeyExpirationTime = 9,
    PreferredSymmetricAlgorithms = 11,
    RevocationKey = 12,
    Issuer = 16,
    NotationData = 20,
    PreferredHashAlgorithms = 21,
    PreferredCompressionAlgorithms = 22,
    KeyServerPreferences = 23,
    PreferredKeyServer = 24,
    PrimaryUserID = 25,
    PolicyURI = 26,
    KeyFlags = 27,
    SignerUserID = 28,
    RevocationReason = 29,
    Features = 30,
    SignatureTarget = 31,
    EmbeddedSignature = 32,
}    
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Subpacket {
    typ: SubpacketType,
}

named!(subpackets<Vec<Subpacket>>, many0!(do_parse!(
    // the subpacket length (1, 2, or 5 octets)
       olen: be_u8
    >>  len: switch!(value!(olen),
        // One-Octet Lengths
            0...191   => value!(olen as usize) |
        // Two-Octet Lengths
            192...223 => map!(be_u8, |a| {
                ((olen as usize - 192) << 8) + 192 + a as usize
            }) |
        // Five-Octet Lengths
            255       => map!(be_u16, u16_as_usize)
        )
    // the subpacket type (1 octet)
    >>  typ: map_opt!(be_u8, SubpacketType::from_u8)
    // actual data
    >> body: take!(len - 1)
    >> (Subpacket{typ: typ})
)));

/// Parse a v3 signature packet
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.2
named!(v3_parser<Signature>, do_parse!(
    // One-octet length of following hashed material. MUST be 5.
            tag!(&[5])
    // One-octet signature type.
    >> typ: map_opt!(be_u8, SignatureType::from_u8)
    >> (Signature{
        version: SignatureVersion::V3,
        typ: typ,
        pub_alg: PublicKeyAlgorithm::RSA,
        hash_alg: HashAlgorithm::SHA1,
    })
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
    >>     hsub: map!(take!(hsub_len), subpackets)
    // Two-octet scalar octet count for the following unhashed subpacket data.
    >> usub_len: be_u16
    // Unhashed subpacket data set (zero or more subpackets).
    >>     usub: map!(take!(usub_len), subpackets)
    // Two-octet field holding the left 16 bits of the signed hash value.
    // One or more multiprecision integers comprising the signature.
        
   >> ({
       println!("{:?}", hsub);
       println!("{:?}", usub);
       Signature{
       version: SignatureVersion::V4,
       typ: typ,
       pub_alg: pub_alg,
       hash_alg: hash_alg,
       }
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

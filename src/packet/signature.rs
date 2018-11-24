use std::collections::HashMap;
use std::str;

use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use digest::Digest;
use nom::{be_u16, be_u32, be_u8, rest, IResult};
use num_traits::FromPrimitive;

use crypto::hash::{HashAlgorithm, Hasher};
use crypto::public_key::PublicKeyAlgorithm;
use crypto::sym::SymmetricKeyAlgorithm;
use errors::Result;
use types::{self, CompressionAlgorithm, KeyId, PublicKeyTrait};
use util::{clone_into_array, mpi, packet_length, read_string_lossy};

/// Signature Packet
/// https://tools.ietf.org/html/rfc4880.html#section-5.2
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Signature {
    pub version: SignatureVersion,
    pub typ: SignatureType,
    pub pub_alg: PublicKeyAlgorithm,
    pub hash_alg: HashAlgorithm,
    pub key_expiration_time: Option<DateTime<Utc>>,
    pub signature_expiration_time: Option<DateTime<Utc>>,
    pub unhashed_subpackets: Vec<Subpacket>,
    pub created: Option<DateTime<Utc>>,
    pub issuer: Option<KeyId>,
    pub preferred_symmetric_algs: Vec<SymmetricKeyAlgorithm>,
    pub preferred_hash_algs: Vec<HashAlgorithm>,
    pub preferred_compression_algs: Vec<CompressionAlgorithm>,
    pub key_server_prefs: Vec<u8>,
    pub key_flags: Vec<u8>,
    pub features: Vec<u8>,
    pub revocation_reason_code: Option<RevocationCode>,
    pub revocation_reason_string: Option<String>,
    pub is_primary: bool,
    pub is_revocable: bool,
    pub embedded_signature: Option<Box<Signature>>,
    pub preferred_key_server: Option<String>,
    pub notations: HashMap<String, (bool, String)>,
    pub revocation_key: Option<types::RevocationKey>,
    pub signers_userid: Option<String>,
    pub signed_hash_value: Vec<u8>,
    pub signature: Vec<u8>,
    pub policy_uri: Option<String>,
    pub trust_signature: Option<u8>,
    pub regular_expression: Option<String>,
    pub exportable_certification: bool,
}

impl Signature {
    /// Parses a `Signature` packet from the given slice.
    pub fn from_slice(input: &[u8]) -> Result<Self> {
        let (_, pk) = parse(input)?;

        Ok(pk)
    }

    pub fn new(
        version: SignatureVersion,
        typ: SignatureType,
        pub_alg: PublicKeyAlgorithm,
        hash_alg: HashAlgorithm,
        signed_hash_value: Vec<u8>,
        signature: Vec<u8>,
    ) -> Self {
        Signature {
            version,
            typ,
            pub_alg,
            hash_alg,
            key_expiration_time: None,
            signature_expiration_time: None,
            unhashed_subpackets: Vec::new(),
            created: None,
            issuer: None,
            preferred_symmetric_algs: Vec::new(),
            preferred_hash_algs: Vec::new(),
            preferred_compression_algs: Vec::new(),
            key_server_prefs: vec![0],
            key_flags: vec![0],
            features: vec![0],
            revocation_reason_code: None,
            revocation_reason_string: None,
            is_primary: false,
            is_revocable: true,
            embedded_signature: None,
            preferred_key_server: None,
            notations: HashMap::new(),
            revocation_key: None,
            signers_userid: None,
            signed_hash_value,
            signature,
            policy_uri: None,
            trust_signature: None,
            regular_expression: None,
            exportable_certification: true,
        }
    }

    /// Returns what kind of signature this is.
    pub fn typ(&self) -> SignatureType {
        self.typ
    }

    /// Verify this signature.
    pub fn verify(&self, key: &impl PublicKeyTrait, data: &[u8]) -> Result<()> {
        let mut hasher = self.hash_alg.new_hasher()?;
        self.hash_data_to_sign(&mut hasher, data);
        hasher.update(&self.signature);
        hasher.update(&self.trailer());

        key.verify(self.hash_alg, &hasher.finish()[..], &self.signature)
    }

    /// Verifies a certificate siganture type.
    pub fn verify_certificate(&self) -> Result<()> {
        unimplemented!();
    }

    fn hash_data_to_sign(&self, hasher: &mut Box<dyn Hasher>, data: &[u8]) {
        unimplemented!();
    }

    fn trailer(&self) -> Vec<u8> {
        unimplemented!();
    }

    /// Returns if the signature is a certificate or not.
    pub fn is_certificate(&self) -> bool {
        match self.typ {
            SignatureType::CertGeneric
            | SignatureType::CertPersona
            | SignatureType::CertCasual
            | SignatureType::CertPositive => true,
            _ => false,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, FromPrimitive)]
#[repr(u8)]
pub enum SignatureVersion {
    /// Deprecated
    V2 = 2,
    V3 = 3,
    V4 = 4,
}

#[derive(Debug, PartialEq, Eq, Copy, Clone, FromPrimitive)]
#[repr(u8)]
pub enum SignatureType {
    /// Signature of a binary document.
    /// This means the signer owns it, created it, or certifies that ithas not been modified.
    Binary = 0x00,
    /// Signature of a canonical text document.
    /// This means the signer owns it, created it, or certifies that it
    /// has not been modified.  The signature is calculated over the text
    /// data with its line endings converted to <CR><LF>.
    Text = 0x01,
    /// Standalone signature.
    /// This signature is a signature of only its own subpacket contents.
    /// It is calculated identically to a signature over a zero-length
    /// binary document.  Note that it doesn't make sense to have a V3 standalone signature.
    Standalone = 0x02,
    /// Generic certification of a User ID and Public-Key packet.
    /// The issuer of this certification does not make any particular
    /// assertion as to how well the certifier has checked that the owner
    /// of the key is in fact the person described by the User ID.
    CertGeneric = 0x10,
    /// Persona certification of a User ID and Public-Key packet.
    /// The issuer of this certification has not done any verification of
    /// the claim that the owner of this key is the User ID specified.
    CertPersona = 0x11,
    /// Casual certification of a User ID and Public-Key packet.
    /// The issuer of this certification has done some casual
    /// verification of the claim of identity.
    CertCasual = 0x12,
    /// Positive certification of a User ID and Public-Key packet.
    /// The issuer of this certification has done substantial
    /// verification of the claim of identity.
    ///
    /// Most OpenPGP implementations make their "key signatures" as 0x10
    /// certifications.  Some implementations can issue 0x11-0x13
    /// certifications, but few differentiate between the types.
    CertPositive = 0x13,
    /// Subkey Binding Signature
    /// This signature is a statement by the top-level signing key that
    /// indicates that it owns the subkey.  This signature is calculated
    /// directly on the primary key and subkey, and not on any User ID or
    /// other packets.  A signature that binds a signing subkey MUST have
    /// an Embedded Signature subpacket in this binding signature that
    /// contains a 0x19 signature made by the signing subkey on the
    /// primary key and subkey.
    SubkeyBinding = 0x18,
    /// Primary Key Binding Signature
    /// This signature is a statement by a signing subkey, indicating
    /// that it is owned by the primary key and subkey.  This signature
    /// is calculated the same way as a 0x18 signature: directly on the
    /// primary key and subkey, and not on any User ID or other packets.
    KeyBinding = 0x19,
    /// Signature directly on a key
    /// This signature is calculated directly on a key.  It binds the
    /// information in the Signature subpackets to the key, and is
    /// appropriate to be used for subpackets that provide information
    /// about the key, such as the Revocation Key subpacket.  It is also
    /// appropriate for statements that non-self certifiers want to make
    /// about the key itself, rather than the binding between a key and a name.
    Key = 0x1F,
    /// Key revocation signature
    /// The signature is calculated directly on the key being revoked.  A
    /// revoked key is not to be used.  Only revocation signatures by the
    /// key being revoked, or by an authorized revocation key, should be
    /// considered valid revocation signatures.
    KeyRevocation = 0x20,
    /// Subkey revocation signature
    /// The signature is calculated directly on the subkey being revoked.
    /// A revoked subkey is not to be used.  Only revocation signatures
    /// by the top-level signature key that is bound to this subkey, or
    /// by an authorized revocation key, should be considered valid
    /// revocation signatures.
    SubkeyRevocation = 0x28,
    /// Certification revocation signature
    /// This signature revokes an earlier User ID certification signature
    /// (signature class 0x10 through 0x13) or direct-key signature
    /// (0x1F).  It should be issued by the same key that issued the
    /// revoked signature or an authorized revocation key.  The signature
    /// is computed over the same data as the certificate that it
    /// revokes, and should have a later creation date than that
    /// certificate.
    CertRevocation = 0x30,
    /// Timestamp signature.
    /// This signature is only meaningful for the timestamp contained in
    /// it.
    Timestamp = 0x40,
    /// Third-Party Confirmation signature.
    /// This signature is a signature over some other OpenPGP Signature
    /// packet(s).  It is analogous to a notary seal on the signed data.
    /// A third-party signature SHOULD include Signature Target
    /// subpacket(s) to give easy identification.  Note that we really do
    /// mean SHOULD.  There are plausible uses for this (such as a blind
    /// party that only sees the signature, not the key or source
    /// document) that cannot include a target subpacket.
    ThirdParty = 0x50,
}

#[derive(Debug, PartialEq, Eq, Clone, FromPrimitive)]
/// Available signature subpacket types
pub enum SubpacketType {
    SignatureCreationTime = 2,
    SignatureExpirationTime = 3,
    ExportableCertification = 4,
    TrustSignature = 5,
    RegularExpression = 6,
    Revocable = 7,
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
    SignersUserID = 28,
    RevocationReason = 29,
    Features = 30,
    SignatureTarget = 31,
    EmbeddedSignature = 32,
    Experimental = 100,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Subpacket {
    /// The time the signature was made.
    SignatureCreationTime(DateTime<Utc>),
    /// The time the signature will expire.
    SignatureExpirationTime(DateTime<Utc>),
    /// When the key is going to expire
    KeyExpirationTime(DateTime<Utc>),
    Issuer(KeyId),
    /// List of symmetric algorithms that indicate which algorithms the key holder prefers to use.
    PreferredSymmetricAlgorithms(Vec<SymmetricKeyAlgorithm>),
    /// List of hash algorithms that indicate which algorithms the key holder prefers to use.
    PreferredHashAlgorithms(Vec<HashAlgorithm>),
    /// List of compression algorithms that indicate which algorithms the key holder prefers to use.
    PreferredCompressionAlgorithms(Vec<CompressionAlgorithm>),
    KeyServerPreferences(Vec<u8>),
    KeyFlags(Vec<u8>),
    Features(Vec<u8>),
    RevocationReason(RevocationCode, Vec<u8>),
    IsPrimary(bool),
    Revocable(bool),
    EmbeddedSignature(Box<Signature>),
    PreferredKeyServer(String),
    Notation(bool, String, String),
    RevocationKey(u8, PublicKeyAlgorithm, [u8; 20]),
    SignersUserID(String),
    PolicyURI(String),
    TrustSignature(u8),
    RegularExpression(String),
    ExportableCertification(bool),
    Experimental(Vec<u8>),
}

/// Codes for revocation reasons
#[derive(Debug, PartialEq, Eq, Copy, Clone, FromPrimitive)]
#[repr(u8)]
pub enum RevocationCode {
    /// No reason specified (key revocations or cert revocations)
    NoReason = 0,
    /// Key is superseded (key revocations)
    KeySuperseded = 1,
    /// Key material has been compromised (key revocations)
    KeyCompromised = 2,
    /// Key is retired and no longer used (key revocations)
    KeyRetired = 3,
    /// User ID information is no longer valid (cert revocations)
    CertUserIdInvalid = 32,
}

#[derive(FromPrimitive)]
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
named!(
    trust_signature<Subpacket>,
    map!(be_u8, Subpacket::TrustSignature)
);

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
    >>   alg: map_opt!(be_u8, PublicKeyAlgorithm::from_u8)
    >>    fp: take!(20)
    >> (Subpacket::RevocationKey(class, alg, clone_into_array(fp)))
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
    >> (Subpacket::Notation(readable, name, value))
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
named!(
    rev_reason<Subpacket>,
    do_parse!(
        code: map_opt!(be_u8, RevocationCode::from_u8)
            >> reason: rest
            >> (Subpacket::RevocationReason(code, reason.to_vec()))
    )
);

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

/// Parse a v2 signature packet
/// > OBSOLETE FORMAT, ONLY HERE FOR COMPATABILITY
/// Ref: https://tools.ietf.org/html/rfc1991#section-6.2
#[rustfmt::skip]
named!(v2_parser<Signature>, do_parse!(
    // One-octet length of following hashed material. MUST be 5.
            tag!(&[5])
    // One-octet signature type.
    >> typ: map_opt!(be_u8, SignatureType::from_u8)
    // TODO:
    // (d2) signature time stamp (4 bytes);
    // (e) key ID for key used for singing (8 bytes);
    // (f) public-key-cryptosystem (PKC) type (1 byte);
    // (g) message digest algorithm type (1 byte);
    // (h) first two bytes of the MD output, used as a checksum
    //     (2 bytes);
    // (i) a byte string of encrypted data holding the RSA-signed digest.
    >> (Signature::new(
        SignatureVersion::V2, typ,
        PublicKeyAlgorithm::RSA,
        HashAlgorithm::SHA1,
        vec![],
        vec![],
    ))
));

/// Parse a v3 signature packet
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.2
#[rustfmt::skip]
named!(v3_parser<Signature>, do_parse!(
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
            SignatureVersion::V3,
            typ,
            pub_alg,
            hash_alg,
            ls_hash.to_vec(),
            sig.to_vec(),
        );
        s.created = Some(created);
        s.issuer = Some(issuer);

        s
    })
));

/// Parse a v4 signature packet
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3
#[rustfmt::skip]
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
    >>  ls_hash: take!(2)
    // One or more multiprecision integers comprising the signature.
    >>      sig: call!(actual_signature, &pub_alg)
    >> ({
        let mut sig = Signature::new(
            SignatureVersion::V4,
            typ,
            pub_alg,
            hash_alg,
            ls_hash.to_vec(),
            sig.to_vec(),
        );

        for p in hsub {
            use self::Subpacket::*;
            match p {
                SignatureCreationTime(d) => sig.created = Some(d),
                Issuer(a) => sig.issuer = Some(a),
                PreferredSymmetricAlgorithms(list) => sig.preferred_symmetric_algs = list,
                PreferredHashAlgorithms(list) => sig.preferred_hash_algs = list,
                PreferredCompressionAlgorithms(list) => sig.preferred_compression_algs = list,
                KeyServerPreferences(f) => sig.key_server_prefs = f,
                KeyFlags(f) => sig.key_flags = f,
                Features(f) => sig.features = f,
                RevocationReason(code, body) => {
                    sig.revocation_reason_code = Some(code);
                    sig.revocation_reason_string =
                        Some(String::from_utf8_lossy(body.as_slice()).to_string());
                }
                IsPrimary(b) => sig.is_primary = b,
                KeyExpirationTime(d) => sig.key_expiration_time = Some(d),
                Revocable(b) => sig.is_revocable = b,
                EmbeddedSignature(mut inner_sig) => sig.embedded_signature = Some(inner_sig),
                PreferredKeyServer(server) => sig.preferred_key_server = Some(server),
                SignatureExpirationTime(d) => sig.signature_expiration_time = Some(d),
                Notation(readable, name, value) => {
                    sig.notations.insert(name, (readable, value));
                }
                RevocationKey(class, algorithm, fingerprint) => {
                    sig.revocation_key = Some(types::RevocationKey {
                        class,
                        algorithm,
                        fingerprint,
                    });
                }
                SignersUserID(u) => sig.signers_userid = Some(u),
                PolicyURI(s) => sig.policy_uri = Some(s),
                TrustSignature(v) => sig.trust_signature = Some(v),
                RegularExpression(v) => sig.regular_expression = Some(v),
                ExportableCertification(v) => sig.exportable_certification = v,
                Experimental(_) => {} // ignoring these
            }
        }

        sig.unhashed_subpackets = usub;
        sig
    })
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
                      &SignatureVersion::V2 => call!(v2_parser) |
                      &SignatureVersion::V3 => call!(v3_parser) |
                      &SignatureVersion::V4 => call!(v4_parser) |
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

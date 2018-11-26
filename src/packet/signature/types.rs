use chrono::{DateTime, Utc};

use crypto::hash::{HashAlgorithm, Hasher};
use crypto::public_key::PublicKeyAlgorithm;
use crypto::sym::SymmetricKeyAlgorithm;
use errors::Result;
use types::{self, CompressionAlgorithm, KeyId, PublicKeyTrait, Version};

/// Signature Packet
/// https://tools.ietf.org/html/rfc4880.html#section-5.2
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Signature {
    packet_version: Version,
    pub version: SignatureVersion,
    pub typ: SignatureType,
    pub pub_alg: PublicKeyAlgorithm,
    pub hash_alg: HashAlgorithm,
    pub signed_hash_value: Vec<u8>,
    pub signature: Vec<Vec<u8>>,

    // only set on V2 and V3 keys
    pub created: Option<DateTime<Utc>>,
    pub issuer: Option<KeyId>,

    pub unhashed_subpackets: Vec<Subpacket>,
    pub hashed_subpackets: Vec<Subpacket>,
}

impl Signature {
    pub fn new(
        packet_version: Version,
        version: SignatureVersion,
        typ: SignatureType,
        pub_alg: PublicKeyAlgorithm,
        hash_alg: HashAlgorithm,
        signed_hash_value: Vec<u8>,
        signature: Vec<Vec<u8>>,
        hashed_subpackets: Vec<Subpacket>,
        unhashed_subpackets: Vec<Subpacket>,
    ) -> Self {
        Signature {
            packet_version,
            version,
            typ,
            pub_alg,
            hash_alg,
            signed_hash_value,
            signature,
            hashed_subpackets,
            unhashed_subpackets,
            issuer: None,
            created: None,
        }
    }

    /// Returns what kind of signature this is.
    pub fn typ(&self) -> SignatureType {
        self.typ
    }

    pub fn packet_version(&self) -> Version {
        self.packet_version
    }

    /// Verify this signature.
    pub fn verify(&self, key: &impl PublicKeyTrait, data: &[u8]) -> Result<()> {
        let mut hasher = self.hash_alg.new_hasher()?;
        self.hash_data_to_sign(&mut *hasher, data);
        hasher.update(&self.signature.concat());
        hasher.update(&self.trailer());

        key.verify(
            self.hash_alg,
            &hasher.finish()[..],
            &self.signature.concat(),
        )
    }

    /// Verifies a certificate siganture type.
    pub fn verify_certificate(&self) -> Result<()> {
        unimplemented!();
    }

    fn hash_data_to_sign(&self, hasher: &mut dyn Hasher, data: &[u8]) {
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

    /// Returns an iterator over all subpackets of this signature.
    fn subpackets(&self) -> impl Iterator<Item = &Subpacket> {
        self.hashed_subpackets
            .iter()
            .chain(self.unhashed_subpackets.iter())
    }

    pub fn key_expiration_time(&self) -> Option<&DateTime<Utc>> {
        self.subpackets().find_map(|p| match p {
            Subpacket::KeyExpirationTime(d) => Some(d),
            _ => None,
        })
    }

    pub fn signature_expiration_time(&self) -> Option<&DateTime<Utc>> {
        self.subpackets().find_map(|p| match p {
            Subpacket::SignatureExpirationTime(d) => Some(d),
            _ => None,
        })
    }

    pub fn created(&self) -> Option<&DateTime<Utc>> {
        if self.created.is_some() {
            return self.created.as_ref();
        }

        self.subpackets().find_map(|p| match p {
            Subpacket::SignatureCreationTime(d) => Some(d),
            _ => None,
        })
    }

    pub fn issuer(&self) -> Option<&KeyId> {
        self.subpackets().find_map(|p| match p {
            Subpacket::Issuer(id) => Some(id),
            _ => None,
        })
    }

    pub fn preferred_symmetric_algs(&self) -> &[SymmetricKeyAlgorithm] {
        self.subpackets()
            .find_map(|p| match p {
                Subpacket::PreferredSymmetricAlgorithms(d) => Some(&d[..]),
                _ => None,
            })
            .unwrap_or_else(|| &[][..])
    }

    pub fn preferred_hash_algs(&self) -> &[HashAlgorithm] {
        self.subpackets()
            .find_map(|p| match p {
                Subpacket::PreferredHashAlgorithms(d) => Some(&d[..]),
                _ => None,
            })
            .unwrap_or_else(|| &[][..])
    }

    pub fn preferred_compression_algs(&self) -> &[CompressionAlgorithm] {
        self.subpackets()
            .find_map(|p| match p {
                Subpacket::PreferredCompressionAlgorithms(d) => Some(&d[..]),
                _ => None,
            })
            .unwrap_or_else(|| &[][..])
    }

    pub fn key_server_prefs(&self) -> &[u8] {
        self.subpackets()
            .find_map(|p| match p {
                Subpacket::KeyServerPreferences(d) => Some(&d[..]),
                _ => None,
            })
            .unwrap_or_else(|| &[][..])
    }

    pub fn key_flags(&self) -> &[u8] {
        self.subpackets()
            .find_map(|p| match p {
                Subpacket::KeyFlags(d) => Some(&d[..]),
                _ => None,
            })
            .unwrap_or_else(|| &[][..])
    }

    pub fn features(&self) -> &[u8] {
        self.subpackets()
            .find_map(|p| match p {
                Subpacket::Features(d) => Some(&d[..]),
                _ => None,
            })
            .unwrap_or_else(|| &[][..])
    }

    pub fn revocation_reason_code(&self) -> Option<&RevocationCode> {
        self.subpackets().find_map(|p| match p {
            Subpacket::RevocationReason(code, _) => Some(code),
            _ => None,
        })
    }

    pub fn revocation_reason_string(&self) -> Option<&str> {
        self.subpackets().find_map(|p| match p {
            Subpacket::RevocationReason(_, reason) => Some(reason.as_str()),
            _ => None,
        })
    }

    pub fn is_primary(&self) -> bool {
        self.subpackets()
            .find_map(|p| match p {
                Subpacket::IsPrimary(d) => Some(*d),
                _ => None,
            })
            .unwrap_or_else(|| false)
    }

    pub fn is_revocable(&self) -> bool {
        self.subpackets()
            .find_map(|p| match p {
                Subpacket::Revocable(d) => Some(*d),
                _ => None,
            })
            .unwrap_or_else(|| true)
    }

    pub fn embedded_signature(&self) -> Option<&Signature> {
        self.subpackets().find_map(|p| match p {
            Subpacket::EmbeddedSignature(d) => Some(&**d),
            _ => None,
        })
    }

    pub fn preferred_key_server(&self) -> Option<&str> {
        self.subpackets().find_map(|p| match p {
            Subpacket::PreferredKeyServer(d) => Some(d.as_str()),
            _ => None,
        })
    }

    pub fn notations(&self) -> Vec<&Notation> {
        self.subpackets()
            .filter_map(|p| match p {
                Subpacket::Notation(d) => Some(d),
                _ => None,
            })
            .collect()
    }

    pub fn revocation_key(&self) -> Option<&types::RevocationKey> {
        self.subpackets().find_map(|p| match p {
            Subpacket::RevocationKey(d) => Some(d),
            _ => None,
        })
    }

    pub fn signers_userid(&self) -> Option<&str> {
        self.subpackets().find_map(|p| match p {
            Subpacket::SignersUserID(d) => Some(d.as_str()),
            _ => None,
        })
    }

    pub fn policy_uri(&self) -> Option<&str> {
        self.subpackets().find_map(|p| match p {
            Subpacket::PolicyURI(d) => Some(d.as_str()),
            _ => None,
        })
    }

    pub fn trust_signature(&self) -> Option<(u8, u8)> {
        self.subpackets().find_map(|p| match p {
            Subpacket::TrustSignature(depth, value) => Some((*depth, *value)),
            _ => None,
        })
    }

    pub fn regular_expression(&self) -> Option<&str> {
        self.subpackets().find_map(|p| match p {
            Subpacket::RegularExpression(d) => Some(d.as_str()),
            _ => None,
        })
    }

    pub fn exportable_certification(&self) -> bool {
        self.subpackets()
            .find_map(|p| match p {
                Subpacket::ExportableCertification(d) => Some(*d),
                _ => None,
            })
            .unwrap_or_else(|| true)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, FromPrimitive)]
#[repr(u8)]
pub enum SignatureVersion {
    /// Deprecated
    V2 = 2,
    V3 = 3,
    V4 = 4,
    V5 = 5,
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

#[derive(Debug, PartialEq, Eq, Copy, Clone, FromPrimitive)]
/// Available signature subpacket types
#[repr(u8)]
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
    Notation = 20,
    PreferredHashAlgorithms = 21,
    PreferredCompressionAlgorithms = 22,
    KeyServerPreferences = 23,
    PreferredKeyServer = 24,
    PrimaryUserId = 25,
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
    RevocationReason(RevocationCode, String),
    IsPrimary(bool),
    Revocable(bool),
    EmbeddedSignature(Box<Signature>),
    PreferredKeyServer(String),
    Notation(Notation),
    RevocationKey(types::RevocationKey),
    SignersUserID(String),
    PolicyURI(String),
    TrustSignature(u8, u8),
    RegularExpression(String),
    ExportableCertification(bool),
    Experimental(Vec<u8>),
    SignatureTarget(PublicKeyAlgorithm, HashAlgorithm, Vec<u8>),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Notation {
    pub readable: bool,
    pub name: String,
    pub value: String,
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

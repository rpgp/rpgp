use nom::IResult;
use armor;

mod pubkey;

enum_from_primitive!{
#[derive(Debug, PartialEq, Eq, Clone)]
/// Available hash algorithms.
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-9.4
pub enum HashAlgorithm {
    MD5 = 1,
    SHA1 = 2,
    RIPEMD160 = 3,
    SHA256 = 8,
    SHA384 = 9,
    SHA512 = 10,
    SHA224 = 11,
}
}

enum_from_primitive!{
#[derive(Debug, PartialEq, Eq, Clone)]
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
}

enum_from_primitive!{
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SignatureVersion {
    V3 = 3,
    V4 = 4,
}
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Signature {
    pub version: SignatureVersion,
    pub typ: SignatureType,
    pub pub_alg: PublicKeyAlgorithm,
    pub hash_alg: HashAlgorithm,
}

impl Signature {
    pub fn new(
        version: SignatureVersion,
        typ: SignatureType,
        pub_alg: PublicKeyAlgorithm,
        hash_alg: HashAlgorithm,
    ) -> Self {
        Signature {
            version: version,
            typ: typ,
            pub_alg: pub_alg,
            hash_alg: hash_alg,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct User {
    pub id: String,
    pub signatures: Vec<Signature>,
}

impl User {
    pub fn new<S: Into<String>>(id: S, signatures: Vec<Signature>) -> Self {
        User {
            id: id.into(),
            signatures: signatures,
        }
    }
}

enum_from_primitive!{
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum KeyVersion {
    V2 = 2,
    V3 = 3,
    V4 = 4,
}
}

enum_from_primitive!{
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PublicKeyAlgorithm {
    /// RSA (Encrypt and Sign) [HAC]
    RSA = 1,
    /// DEPRECATED: RSA (Encrypt-Only) [HAC]
    RSAEncrypt = 2,
    /// DEPRECATED: RSA (Sign-Only) [HAC]
    RSASign = 3,
    /// Elgamal (Encrypt-Only) [ELGAMAL] [HAC]
    ELSign = 16,
    /// DSA (Digital Signature Algorithm) [FIPS186] [HAC]
    DSA = 17,
    /// RESERVED: Elliptic Curve
    EC = 18,
    /// RESERVED: ECDSA
    ECDSA = 19,
    /// DEPRECATED: Elgamal (Encrypt and Sign)
    EL = 20,
    /// Reserved for Diffie-Hellman (X9.42, as defined for IETF-S/MIME)
    DiffieHellman = 21,
}
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PublicKey {
    RSAPublicKey {
        version: KeyVersion,
        algorithm: PublicKeyAlgorithm,
        n: Vec<u8>,
        e: Vec<u8>,
    },
}

impl PublicKey {
    /// Create a new RSA key.
    pub fn new_rsa(ver: KeyVersion, alg: PublicKeyAlgorithm, n: Vec<u8>, e: Vec<u8>) -> Self {
        PublicKey::RSAPublicKey {
            version: ver,
            algorithm: alg,
            n: n,
            e: e,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SecretKey {
    RSASecretKey {
        version: KeyVersion,
        algorithm: PublicKeyAlgorithm,
    },
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PrimaryKey {
    PublicKey(PublicKey),
    SecretKey(SecretKey),
}

impl PrimaryKey {
    /// Wrap a `PublicKey` as `PrimaryKey`.
    pub fn from_public_key(pk: PublicKey) -> Self {
        PrimaryKey::PublicKey(pk)
    }

    /// Wrap a `SecretKey` as `PrimaryKey`.
    pub fn from_secret_key(sk: SecretKey) -> Self {
        PrimaryKey::SecretKey(sk)
    }

    /// Create a new RSA public key.
    pub fn new_public_rsa(
        ver: KeyVersion,
        alg: PublicKeyAlgorithm,
        n: Vec<u8>,
        e: Vec<u8>,
    ) -> Self {
        Self::from_public_key(PublicKey::new_rsa(ver, alg, n, e))
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Key {
    pub primary_key: PrimaryKey,
    // pub revocation_signature:
    // pub direct_signatures: Vec<>
    pub users: Vec<User>,
    // pub subkeys: Vec<>
}

impl Key {
    /// Parse a raw armor block
    pub fn from_block(block: armor::Block) -> IResult<&[u8], Self> {
        match block.typ {
            armor::BlockType::PublicKey => pubkey::parse(block.packets),
            _ => unimplemented!(),
        }
    }
}

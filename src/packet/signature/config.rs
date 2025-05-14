use std::io::Read;

use byteorder::{BigEndian, ByteOrder};
use chrono::{DateTime, Utc};
use digest::DynDigest;
use log::debug;
use rand::{CryptoRng, RngCore};

use crate::{
    crypto::{
        hash::{HashAlgorithm, WriteHasher},
        public_key::PublicKeyAlgorithm,
    },
    errors::{bail, ensure, unimplemented_err, unsupported_err, Result},
    packet::{
        types::serialize_for_hashing, Signature, SignatureType, SignatureVersion, Subpacket,
        SubpacketData, SubpacketType,
    },
    ser::Serialize,
    types::{Fingerprint, KeyId, KeyVersion, Password, PublicKeyTrait, SecretKeyTrait, Tag},
    util::NormalizingHasher,
};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SignatureConfig {
    pub typ: SignatureType,
    pub pub_alg: PublicKeyAlgorithm,
    pub hash_alg: HashAlgorithm,

    pub unhashed_subpackets: Vec<Subpacket>,
    pub hashed_subpackets: Vec<Subpacket>,

    pub version_specific: SignatureVersionSpecific,
}

#[derive(Clone, PartialEq, Eq, derive_more::Debug)]
pub enum SignatureVersionSpecific {
    V2 {
        created: DateTime<Utc>,
        issuer: KeyId,
    },
    V3 {
        created: DateTime<Utc>,
        issuer: KeyId,
    },
    V4,
    V6 {
        #[debug("{}", hex::encode(salt))]
        salt: Vec<u8>,
    },
}

impl From<&SignatureVersionSpecific> for SignatureVersion {
    fn from(value: &SignatureVersionSpecific) -> Self {
        match value {
            SignatureVersionSpecific::V2 { .. } => SignatureVersion::V2,
            SignatureVersionSpecific::V3 { .. } => SignatureVersion::V3,
            SignatureVersionSpecific::V4 => SignatureVersion::V4,
            SignatureVersionSpecific::V6 { .. } => SignatureVersion::V6,
        }
    }
}

impl SignatureConfig {
    pub fn from_key<R: CryptoRng + ?Sized, K: SecretKeyTrait>(
        rng: &mut R,
        key: &K,
        typ: SignatureType,
    ) -> Result<Self> {
        match key.version() {
            KeyVersion::V4 => Ok(SignatureConfig::v4(typ, key.algorithm(), key.hash_alg())),
            KeyVersion::V6 => SignatureConfig::v6(rng, typ, key.algorithm(), key.hash_alg()),
            v => unsupported_err!("unsupported key version: {:?}", v),
        }
    }

    /// Constructor for a v2 SignatureConfig (which represents the data of a v2 OpenPGP signature packet)
    ///
    /// OpenPGP v2 Signatures are historical and not used anymore.
    pub fn v2(
        typ: SignatureType,
        pub_alg: PublicKeyAlgorithm,
        hash_alg: HashAlgorithm,
        created: DateTime<Utc>,
        issuer: KeyId,
    ) -> Self {
        Self {
            typ,
            pub_alg,
            hash_alg,
            hashed_subpackets: Vec::new(),
            unhashed_subpackets: Vec::new(),
            version_specific: SignatureVersionSpecific::V2 { created, issuer },
        }
    }

    /// Constructor for a v3 SignatureConfig (which represents the data of a v3 OpenPGP signature packet)
    ///
    /// OpenPGP v3 Signatures are historical and not used anymore.
    pub fn v3(
        typ: SignatureType,
        pub_alg: PublicKeyAlgorithm,
        hash_alg: HashAlgorithm,
        created: DateTime<Utc>,
        issuer: KeyId,
    ) -> Self {
        Self {
            typ,
            pub_alg,
            hash_alg,
            hashed_subpackets: Vec::new(),
            unhashed_subpackets: Vec::new(),
            version_specific: SignatureVersionSpecific::V3 { created, issuer },
        }
    }

    /// Constructor for a v4 SignatureConfig (which represents the data of a v4 OpenPGP signature packet)
    ///
    /// OpenPGP v4 signatures were first specified in RFC 2440, and are commonly produced by
    /// OpenPGP v4 keys.
    pub fn v4(typ: SignatureType, pub_alg: PublicKeyAlgorithm, hash_alg: HashAlgorithm) -> Self {
        Self {
            typ,
            pub_alg,
            hash_alg,
            unhashed_subpackets: vec![],
            hashed_subpackets: vec![],
            version_specific: SignatureVersionSpecific::V4,
        }
    }

    /// Generate v6 signature salt with the appropriate length for `hash_alg`
    /// https://www.rfc-editor.org/rfc/rfc9580.html#name-hash-algorithms
    fn v6_salt_for<R: CryptoRng + RngCore + ?Sized>(
        rng: &mut R,
        hash_alg: HashAlgorithm,
    ) -> Result<Vec<u8>> {
        let Some(salt_len) = hash_alg.salt_len() else {
            bail!("Unknown v6 signature salt length for hash algorithm {hash_alg:?}");
        };

        let mut salt = vec![0; salt_len];
        rng.fill_bytes(&mut salt);

        Ok(salt)
    }

    /// Constructor for a v6 SignatureConfig (which represents the data of a v6 OpenPGP signature packet).
    /// Generates a new salt via `rng`.
    ///
    /// OpenPGP v6 signatures are specified in RFC 9580, they are produced by OpenPGP v6 keys.
    pub fn v6<R: CryptoRng + RngCore + ?Sized>(
        rng: &mut R,
        typ: SignatureType,
        pub_alg: PublicKeyAlgorithm,
        hash_alg: HashAlgorithm,
    ) -> Result<Self> {
        Ok(Self::v6_with_salt(
            typ,
            pub_alg,
            hash_alg,
            Self::v6_salt_for(rng, hash_alg)?,
        ))
    }

    /// Constructor for a v6 SignatureConfig (which represents the data of a v6 OpenPGP signature packet).
    ///
    /// OpenPGP v6 signatures are specified in RFC 9580, they are produced by OpenPGP v6 keys.
    pub fn v6_with_salt(
        typ: SignatureType,
        pub_alg: PublicKeyAlgorithm,
        hash_alg: HashAlgorithm,
        salt: Vec<u8>,
    ) -> Self {
        Self {
            typ,
            pub_alg,
            hash_alg,
            unhashed_subpackets: Vec::new(),
            hashed_subpackets: Vec::new(),
            version_specific: SignatureVersionSpecific::V6 { salt },
        }
    }

    pub fn version(&self) -> SignatureVersion {
        (&self.version_specific).into()
    }

    /// Sign the given data.
    pub fn sign<R>(
        self,
        key: &impl SecretKeyTrait,
        key_pw: &Password,
        mut data: R,
    ) -> Result<Signature>
    where
        R: Read,
    {
        let mut hasher = self.into_hasher()?;
        std::io::copy(&mut data, &mut hasher)?;

        hasher.sign(key, key_pw)
    }

    pub fn into_hasher(self) -> Result<SignatureHasher> {
        let mut hasher = self.hash_alg.new_hasher()?;

        if let SignatureVersionSpecific::V6 { salt } = &self.version_specific {
            hasher.update(salt.as_ref())
        }

        let text_mode = self.typ == SignatureType::Text;
        let norm_hasher = NormalizingHasher::new(hasher, text_mode);

        Ok(SignatureHasher {
            norm_hasher,
            config: self,
        })
    }

    /// Create a certification self-signature.
    pub fn sign_certification<K, P>(
        self,
        key: &K,
        pub_key: &P,
        key_pw: &Password,
        tag: Tag,
        id: &impl Serialize,
    ) -> Result<Signature>
    where
        K: SecretKeyTrait,
        P: PublicKeyTrait + Serialize,
    {
        self.sign_certification_third_party(key, key_pw, pub_key, tag, id)
    }

    /// Create a certification third-party signature.
    pub fn sign_certification_third_party<P>(
        self,
        signer: &impl SecretKeyTrait,
        signer_pw: &Password,
        signee: &P,
        tag: Tag,
        id: &impl Serialize,
    ) -> Result<Signature>
    where
        P: PublicKeyTrait + Serialize,
    {
        ensure!(
            (self.version() == SignatureVersion::V4 && signer.version() == KeyVersion::V4)
                || (self.version() == SignatureVersion::V6 && signer.version() == KeyVersion::V6),
            "signature version {:?} not allowed for signer key version {:?}",
            self.version(),
            signer.version()
        );
        ensure!(
            self.is_certification(),
            "can not sign non certification as certification"
        );

        debug!("signing certification {:#?}", self.typ);

        let mut hasher = self.hash_alg.new_hasher()?;

        if let SignatureVersionSpecific::V6 { salt } = &self.version_specific {
            hasher.update(salt.as_ref())
        }

        serialize_for_hashing(signee, &mut hasher)?;

        let mut packet_buf = Vec::new();
        id.to_writer(&mut packet_buf)?;

        match self.version() {
            SignatureVersion::V2 | SignatureVersion::V3 => {
                // Nothing to do
            }
            SignatureVersion::V4 | SignatureVersion::V6 => {
                let prefix = match tag {
                    Tag::UserId => 0xB4,
                    Tag::UserAttribute => 0xD1,
                    _ => bail!("invalid tag for certification signature: {:?}", tag),
                };

                let mut prefix_buf = [prefix, 0u8, 0u8, 0u8, 0u8];
                BigEndian::write_u32(&mut prefix_buf[1..], packet_buf.len().try_into()?);

                // prefixes
                hasher.update(&prefix_buf);
            }
            SignatureVersion::V5 => {
                bail!("v5 signature unsupported sign tps")
            }
            SignatureVersion::Other(version) => {
                bail!("unsupported signature version {}", version)
            }
        }

        // the packet content
        hasher.update(&packet_buf);

        let len = self.hash_signature_data(&mut hasher)?;
        hasher.update(&self.trailer(len)?);

        let hash = &hasher.finalize()[..];

        let signed_hash_value = [hash[0], hash[1]];
        let signature = signer.create_signature(signer_pw, self.hash_alg, hash)?;

        Signature::from_config(self, signed_hash_value, signature)
    }

    /// Sign a subkey binding that associates a subkey with a primary key.
    ///
    /// The primary key is expected as `signer`, the subkey as `signee`.
    ///
    /// Produces a "Subkey Binding Signature (type ID 0x18)"
    pub fn sign_subkey_binding<K, P, L>(
        self,
        signer: &K,
        signer_pub: &P,
        signer_pw: &Password,
        signee: &L,
    ) -> Result<Signature>
    where
        K: SecretKeyTrait,
        P: PublicKeyTrait + Serialize,
        L: PublicKeyTrait + Serialize,
    {
        ensure!(
            (self.version() == SignatureVersion::V4 && signer.version() == KeyVersion::V4)
                || (self.version() == SignatureVersion::V6 && signer.version() == KeyVersion::V6),
            "signature version {:?} not allowed for signer key version {:?}",
            self.version(),
            signer.version()
        );
        debug!(
            "signing subkey binding: {:#?} - {:#?} - {:#?}",
            self, signer, signee
        );

        let mut hasher = self.hash_alg.new_hasher()?;

        if let SignatureVersionSpecific::V6 { salt } = &self.version_specific {
            hasher.update(salt.as_ref())
        }

        serialize_for_hashing(signer_pub, &mut hasher)?; // primary
        serialize_for_hashing(signee, &mut hasher)?; // subkey

        let len = self.hash_signature_data(&mut hasher)?;
        hasher.update(&self.trailer(len)?);

        let hash = &hasher.finalize()[..];
        let signed_hash_value = [hash[0], hash[1]];
        let signature = signer.create_signature(signer_pw, self.hash_alg, hash)?;

        Signature::from_config(self, signed_hash_value, signature)
    }

    /// Sign a primary key binding, or "back signature"
    /// (with this signature, the subkey signals that it wants to be associated with the primary).
    ///
    /// The subkey is expected as `signer`, the primary key as `signee`.
    ///
    /// Produces a "Primary Key Binding Signature (type ID 0x19)"
    pub fn sign_primary_key_binding<K, P, L>(
        self,
        signer: &K,
        signer_pub: &P,
        signer_pw: &Password,
        signee: &L,
    ) -> Result<Signature>
    where
        K: SecretKeyTrait,
        P: PublicKeyTrait + Serialize,
        L: PublicKeyTrait + Serialize,
    {
        ensure!(
            (self.version() == SignatureVersion::V4 && signer.version() == KeyVersion::V4)
                || (self.version() == SignatureVersion::V6 && signer.version() == KeyVersion::V6),
            "signature version {:?} not allowed for signer key version {:?}",
            self.version(),
            signer.version()
        );
        debug!(
            "signing primary key binding: {:#?} - {:#?} - {:#?}",
            self, signer, signee
        );

        let mut hasher = self.hash_alg.new_hasher()?;

        if let SignatureVersionSpecific::V6 { salt } = &self.version_specific {
            hasher.update(salt.as_ref())
        }

        serialize_for_hashing(signee, &mut hasher)?; // primary
        serialize_for_hashing(signer_pub, &mut hasher)?; // subkey

        let len = self.hash_signature_data(&mut hasher)?;
        hasher.update(&self.trailer(len)?);

        let hash = &hasher.finalize()[..];
        let signed_hash_value = [hash[0], hash[1]];
        let signature = signer.create_signature(signer_pw, self.hash_alg, hash)?;

        Signature::from_config(self, signed_hash_value, signature)
    }

    /// Signs a direct key signature or a revocation.
    pub fn sign_key<K, P>(self, signing_key: &K, key_pw: &Password, key: &P) -> Result<Signature>
    where
        K: SecretKeyTrait,
        P: PublicKeyTrait + Serialize,
    {
        ensure!(
            (self.version() == SignatureVersion::V4 && signing_key.version() == KeyVersion::V4)
                || (self.version() == SignatureVersion::V6
                    && signing_key.version() == KeyVersion::V6),
            "signature version {:?} not allowed for signer key version {:?}",
            self.version(),
            signing_key.version()
        );
        debug!("signing key (revocation): {:#?} - {:#?}", self, key);

        let mut hasher = self.hash_alg.new_hasher()?;

        if let SignatureVersionSpecific::V6 { salt } = &self.version_specific {
            hasher.update(salt.as_ref())
        }

        serialize_for_hashing(key, &mut hasher)?;

        let len = self.hash_signature_data(&mut hasher)?;
        hasher.update(&self.trailer(len)?);

        let hash = &hasher.finalize()[..];
        let signed_hash_value = [hash[0], hash[1]];
        let signature = signing_key.create_signature(key_pw, self.hash_alg, hash)?;

        Signature::from_config(self, signed_hash_value, signature)
    }

    /// Returns what kind of signature this is.
    pub fn typ(&self) -> SignatureType {
        self.typ
    }

    /// Calculate the serialized version of this packet, but only the part relevant for hashing.
    pub fn hash_signature_data(&self, hasher: &mut Box<dyn DynDigest + Send>) -> Result<usize> {
        match self.version() {
            SignatureVersion::V2 | SignatureVersion::V3 => {
                let created = {
                    if let SignatureVersionSpecific::V2 { created, .. }
                    | SignatureVersionSpecific::V3 { created, .. } = self.version_specific
                    {
                        created
                    } else {
                        bail!("must exist for a v2/3 signature")
                    }
                };

                let mut buf = [0u8; 5];
                buf[0] = self.typ.into();
                BigEndian::write_u32(&mut buf[1..], created.timestamp().try_into()?);

                hasher.update(&buf);

                // no trailer
                Ok(0)
            }
            SignatureVersion::V4 | SignatureVersion::V6 => {
                // TODO: reduce duplication with serialization code

                let mut res = vec![
                    // the signature version
                    self.version().into(),
                    // the signature type
                    self.typ.into(),
                    // the public-key algorithm
                    self.pub_alg.into(),
                    // the hash algorithm
                    self.hash_alg.into(),
                ];

                // hashed subpackets
                let mut hashed_subpackets = Vec::new();
                for packet in &self.hashed_subpackets {
                    debug!("hashing {:#?}", packet);

                    // If a subpacket is encountered that is marked critical but is unknown to the
                    // evaluating implementation, the evaluator SHOULD consider the signature to be
                    // in error.
                    //
                    // (See https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.7-6)
                    if packet.is_critical && matches!(packet.typ(), SubpacketType::Other(_)) {
                        // "[..] The purpose of the critical bit is to allow the signer to tell an
                        // evaluator that it would prefer a new, unknown feature to generate an
                        // error rather than being ignored."
                        //
                        // (See https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.7-8:)

                        bail!("Unknown critical subpacket {:?}", packet);
                    }

                    // If the version octet does not match the signature version, the receiving
                    // implementation MUST treat it as a malformed signature
                    //
                    // (See https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.35-3)
                    if let SubpacketData::IssuerFingerprint(fp) = &packet.data {
                        match (self.version(), fp.version()) {
                            (SignatureVersion::V6, Some(KeyVersion::V6)) => {},
                            (SignatureVersion::V4, Some(KeyVersion::V4)) => {},
                            _ => bail!("IntendedRecipientFingerprint {:?} doesn't match signature version {:?}", fp, self.version())
                        }
                    }

                    packet.to_writer(&mut hashed_subpackets)?;
                }

                // append hashed area length, as u16 for v4, and u32 for v6
                if self.version() == SignatureVersion::V4 {
                    res.extend(u16::try_from(hashed_subpackets.len())?.to_be_bytes());
                } else if self.version() == SignatureVersion::V6 {
                    res.extend(u32::try_from(hashed_subpackets.len())?.to_be_bytes());
                }

                res.extend(hashed_subpackets);

                hasher.update(&res);

                Ok(res.len())
            }
            SignatureVersion::V5 => {
                bail!("v5 signature unsupported hash data")
            }
            SignatureVersion::Other(version) => {
                bail!("unsupported signature version {}", version)
            }
        }
    }

    pub fn hash_data_to_sign<R>(
        &self,
        hasher: &mut Box<dyn DynDigest + Send>,
        mut data: R,
    ) -> Result<usize>
    where
        R: Read,
    {
        match self.typ {
            SignatureType::Text |
                // assumes that the passed in text was already valid utf8 and normalized
            SignatureType::Binary => {
                let written = std::io::copy(&mut data, &mut WriteHasher(hasher))?;
                Ok(written.try_into()?)
            }
            SignatureType::Timestamp |
            SignatureType::Standalone => {
                let mut val = [0u8;1];
                data.read_exact(&mut val[..])?;
                hasher.update(&val[..]);
                Ok(1)
            }
            SignatureType::CertGeneric
            | SignatureType::CertPersona
            | SignatureType::CertCasual
            | SignatureType::CertPositive
            | SignatureType::CertRevocation => {
                unimplemented_err!("{:?}", self.typ);
            }
            SignatureType::SubkeyBinding
            | SignatureType::SubkeyRevocation
            | SignatureType::KeyBinding
            | SignatureType::Key => {
                unimplemented_err!("{:?}", self.typ);
            }
            SignatureType::KeyRevocation => unimplemented_err!("KeyRevocation"),
            SignatureType::ThirdParty => unimplemented_err!("signing ThirdParty"),

            SignatureType::Other(id) => unimplemented_err!("Other ({})", id),
        }
    }

    pub fn trailer(&self, len: usize) -> Result<Vec<u8>> {
        match self.version() {
            SignatureVersion::V2 | SignatureVersion::V3 => {
                // Nothing to do
                Ok(Vec::new())
            }
            SignatureVersion::V4 | SignatureVersion::V6 => {
                let mut trailer = vec![self.version().into(), 0xFF, 0, 0, 0, 0];
                BigEndian::write_u32(&mut trailer[2..], len.try_into()?);
                Ok(trailer)
            }
            SignatureVersion::V5 => {
                bail!("v5 signature unsupported")
            }
            SignatureVersion::Other(version) => {
                bail!("unsupported signature version {}", version)
            }
        }
    }

    /// Returns an iterator of all subpackets in the signature: all subpackets in the hashed area
    /// followed by all subpackets in the unhashed area.
    #[deprecated(
        note = "Usually only hashed_subpackets should be used. unhashed_subpackets are only safe and useful to access in rare circumstances. When they are needed, unhashed_subpackets should be explicitly called."
    )]
    pub fn subpackets(&self) -> impl Iterator<Item = &Subpacket> {
        self.hashed_subpackets().chain(self.unhashed_subpackets())
    }

    /// Returns an iterator over the hashed subpackets of this signature.
    pub fn hashed_subpackets(&self) -> impl Iterator<Item = &Subpacket> {
        self.hashed_subpackets.iter()
    }

    /// Returns an iterator over the unhashed subpackets of this signature.
    pub fn unhashed_subpackets(&self) -> impl Iterator<Item = &Subpacket> {
        self.unhashed_subpackets.iter()
    }

    /// Returns if the signature is a certification or not.
    pub fn is_certification(&self) -> bool {
        matches!(
            self.typ,
            SignatureType::CertGeneric
                | SignatureType::CertPersona
                | SignatureType::CertCasual
                | SignatureType::CertPositive
                | SignatureType::CertRevocation
        )
    }

    /// Signature Creation Time.
    ///
    /// The time the signature was made.
    /// MUST be present in the hashed area.
    ///
    /// <https://www.rfc-editor.org/rfc/rfc9580.html#name-signature-creation-time>
    ///
    /// Returns the first Signature Creation Time subpacket, only from the hashed area.
    pub fn created(&self) -> Option<&DateTime<Utc>> {
        if let SignatureVersionSpecific::V2 { created, .. }
        | SignatureVersionSpecific::V3 { created, .. } = &self.version_specific
        {
            return Some(created);
        }

        self.hashed_subpackets().find_map(|p| match p.data {
            SubpacketData::SignatureCreationTime(ref d) => Some(d),
            _ => None,
        })
    }

    /// Issuer Key ID.
    ///
    /// The OpenPGP Key ID of the key issuing the signature.
    ///
    /// <https://www.rfc-editor.org/rfc/rfc9580.html#name-issuer-key-id>
    ///
    /// Returns Issuer subpacket data from both the hashed and unhashed area.
    pub fn issuer(&self) -> Vec<&KeyId> {
        // legacy v2/v3 signatures have an explicit "issuer" field
        if let SignatureVersionSpecific::V2 { issuer, .. }
        | SignatureVersionSpecific::V3 { issuer, .. } = &self.version_specific
        {
            return vec![issuer];
        }

        // v4+ signatures use subpackets
        //
        // We consider data from both the hashed and unhashed area here, because the issuer Key ID
        // only acts as a hint. The signature will be cryptographically checked using the purported
        // issuer's key material. An attacker cannot successfully claim an issuer Key ID that they
        // can't produce a cryptographically valid signature for.
        self.hashed_subpackets()
            .chain(self.unhashed_subpackets())
            .filter_map(|sp| match sp.data {
                SubpacketData::Issuer(ref id) => Some(id),
                _ => None,
            })
            .collect()
    }

    /// Issuer Fingerprint.
    ///
    /// The OpenPGP Key fingerprint of the key issuing the signature.
    ///
    /// <https://www.rfc-editor.org/rfc/rfc9580.html#name-issuer-fingerprint>
    ///
    /// Returns Issuer Fingerprint subpacket data from both the hashed and unhashed area.
    pub fn issuer_fingerprint(&self) -> Vec<&Fingerprint> {
        self.hashed_subpackets()
            .chain(self.unhashed_subpackets())
            .filter_map(|sp| match &sp.data {
                SubpacketData::IssuerFingerprint(fp) => Some(fp),
                _ => None,
            })
            .collect()
    }
}

pub struct SignatureHasher {
    norm_hasher: NormalizingHasher,
    config: SignatureConfig,
}

impl SignatureHasher {
    /// Finalizes the signature.
    pub fn sign<K>(self, key: &K, key_pw: &Password) -> Result<Signature>
    where
        K: SecretKeyTrait + ?Sized,
    {
        let Self {
            config,
            norm_hasher,
        } = self;

        let mut hasher = norm_hasher.done();

        ensure!(
            (config.version() == SignatureVersion::V4 && key.version() == KeyVersion::V4)
                || (config.version() == SignatureVersion::V6 && key.version() == KeyVersion::V6),
            "signature version {:?} not allowed for signer key version {:?}",
            config.version(),
            key.version()
        );
        ensure!(
            matches!(config.typ, SignatureType::Binary | SignatureType::Text),
            "incompatible signature type {:?}",
            config.typ
        );

        Signature::check_signature_hash_strength(&config)?;

        let len = config.hash_signature_data(&mut hasher)?;
        let trailer = config.trailer(len)?;
        hasher.update(&trailer);

        let hash = &hasher.finalize()[..];

        let signed_hash_value = [hash[0], hash[1]];
        let signature = key.create_signature(key_pw, config.hash_alg, hash)?;

        Signature::from_config(config, signed_hash_value, signature)
    }

    /// Update the internal hasher.
    ///
    /// Normalize line-endings on the fly for SignatureType::Text
    pub(crate) fn update(&mut self, buf: &[u8]) {
        self.norm_hasher.hash_buf(buf);
    }
}

impl std::io::Write for SignatureHasher {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.norm_hasher.hash_buf(buf); // FIXME: when is this used?
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

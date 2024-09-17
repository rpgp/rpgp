use std::io::Read;

use byteorder::{BigEndian, ByteOrder};
use chrono::{DateTime, Utc};
use log::debug;
use rand::{CryptoRng, Rng};

use crate::crypto::hash::{HashAlgorithm, Hasher};
use crate::crypto::public_key::PublicKeyAlgorithm;
use crate::errors::Result;
use crate::packet::{Signature, SignatureType, SignatureVersion, Subpacket, SubpacketData};
use crate::ser::Serialize;
use crate::types::{Fingerprint, KeyId, KeyVersion, PublicKeyTrait, SecretKeyTrait, Tag};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SignatureConfig {
    pub typ: SignatureType,
    pub pub_alg: PublicKeyAlgorithm,
    pub hash_alg: HashAlgorithm,

    pub unhashed_subpackets: Vec<Subpacket>,
    pub hashed_subpackets: Vec<Subpacket>,

    pub version_specific: SignatureVersionSpecific,
}

#[derive(Clone, PartialEq, Eq, Debug)]
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
    fn v6_salt_for<R: CryptoRng + Rng>(mut rng: R, hash_alg: HashAlgorithm) -> Result<Vec<u8>> {
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
    pub fn v6<R: CryptoRng + Rng>(
        rng: R,
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
    pub fn sign<F, R>(self, key: &impl SecretKeyTrait, key_pw: F, data: R) -> Result<Signature>
    where
        F: FnOnce() -> String,
        R: Read,
    {
        ensure!(
            (self.version() == SignatureVersion::V4 && key.version() == KeyVersion::V4)
                || (self.version() == SignatureVersion::V6 && key.version() == KeyVersion::V6),
            "signature version {:?} not allowed for signer key version {:?}",
            self.version(),
            key.version()
        );

        let mut hasher = self.hash_alg.new_hasher()?;

        if let SignatureVersionSpecific::V6 { salt } = &self.version_specific {
            hasher.update(salt.as_ref())
        }

        self.hash_data_to_sign(&mut *hasher, data)?;
        let len = self.hash_signature_data(&mut hasher)?;
        hasher.update(&self.trailer(len)?);

        let hash = &hasher.finish()[..];

        let signed_hash_value = [hash[0], hash[1]];
        let signature = key.create_signature(key_pw, self.hash_alg, hash)?;

        Ok(Signature::from_config(self, signed_hash_value, signature))
    }

    /// Create a certification self-signature.
    pub fn sign_certification<F>(
        self,
        key: &impl SecretKeyTrait,
        key_pw: F,
        tag: Tag,
        id: &impl Serialize,
    ) -> Result<Signature>
    where
        F: FnOnce() -> String,
    {
        self.sign_certification_third_party(key, key_pw, key, tag, id)
    }

    /// Create a certification third-party signature.
    pub fn sign_certification_third_party<F>(
        self,
        signer: &impl SecretKeyTrait,
        signer_pw: F,
        signee: &impl PublicKeyTrait,
        tag: Tag,
        id: &impl Serialize,
    ) -> Result<Signature>
    where
        F: FnOnce() -> String,
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

        signee.serialize_for_hashing(&mut hasher)?;

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

        let hash = &hasher.finish()[..];

        let signed_hash_value = [hash[0], hash[1]];
        let signature = signer.create_signature(signer_pw, self.hash_alg, hash)?;

        Ok(Signature::from_config(self, signed_hash_value, signature))
    }

    /// Sign a key binding.
    pub fn sign_key_binding<F>(
        self,
        signing_key: &impl SecretKeyTrait,
        key_pw: F,
        key: &impl PublicKeyTrait,
    ) -> Result<Signature>
    where
        F: FnOnce() -> String,
    {
        ensure!(
            (self.version() == SignatureVersion::V4 && signing_key.version() == KeyVersion::V4)
                || (self.version() == SignatureVersion::V6
                    && signing_key.version() == KeyVersion::V6),
            "signature version {:?} not allowed for signer key version {:?}",
            self.version(),
            signing_key.version()
        );
        debug!(
            "signing key binding: {:#?} - {:#?} - {:#?}",
            self, signing_key, key
        );

        let mut hasher = self.hash_alg.new_hasher()?;

        if let SignatureVersionSpecific::V6 { salt } = &self.version_specific {
            hasher.update(salt.as_ref())
        }

        // Signing Key
        signing_key.serialize_for_hashing(&mut hasher)?;

        // Key being bound
        key.serialize_for_hashing(&mut hasher)?;

        let len = self.hash_signature_data(&mut hasher)?;
        hasher.update(&self.trailer(len)?);

        let hash = &hasher.finish()[..];
        let signed_hash_value = [hash[0], hash[1]];
        let signature = signing_key.create_signature(key_pw, self.hash_alg, hash)?;

        Ok(Signature::from_config(self, signed_hash_value, signature))
    }

    /// Signs a direct key signature or a revocation.
    pub fn sign_key<F>(
        self,
        signing_key: &impl SecretKeyTrait,
        key_pw: F,
        key: &impl PublicKeyTrait,
    ) -> Result<Signature>
    where
        F: FnOnce() -> String,
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

        key.serialize_for_hashing(&mut hasher)?;

        let len = self.hash_signature_data(&mut hasher)?;
        hasher.update(&self.trailer(len)?);

        let hash = &hasher.finish()[..];
        let signed_hash_value = [hash[0], hash[1]];
        let signature = signing_key.create_signature(key_pw, self.hash_alg, hash)?;

        Ok(Signature::from_config(self, signed_hash_value, signature))
    }

    /// Returns what kind of signature this is.
    pub fn typ(&self) -> SignatureType {
        self.typ
    }

    /// Calculate the serialized version of this packet, but only the part relevant for hashing.
    pub fn hash_signature_data(&self, hasher: &mut dyn std::io::Write) -> Result<usize> {
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

                hasher.write_all(&buf)?;

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
                    packet.to_writer(&mut hashed_subpackets)?;
                }

                // append hashed area length, as u16 for v4, and u32 for v6
                if self.version() == SignatureVersion::V4 {
                    res.extend(u16::try_from(hashed_subpackets.len())?.to_be_bytes());
                } else if self.version() == SignatureVersion::V6 {
                    res.extend(u32::try_from(hashed_subpackets.len())?.to_be_bytes());
                }

                res.extend(hashed_subpackets);

                hasher.write_all(&res)?;

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

    pub fn hash_data_to_sign<R>(&self, hasher: &mut dyn Hasher, mut data: R) -> Result<usize>
    where
        R: Read,
    {
        match self.typ {
            SignatureType::Text |
                // assumes that the passed in text was already valid utf8 and normalized
            SignatureType::Binary => {
                Ok(std::io::copy(&mut data, hasher)? as usize)
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

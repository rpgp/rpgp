use std::io::BufRead;

use hybrid_array::Array;
use log::debug;
use rand::CryptoRng;

use super::public::PubKeyInner;
use crate::{
    crypto::{
        hash::{HashAlgorithm, KnownDigest},
        public_key::PublicKeyAlgorithm,
    },
    errors::{bail, ensure_eq, unsupported_err, Result},
    packet::{
        KeyFlags, PacketHeader, PacketTrait, Signature, SignatureConfig, SignatureType, Subpacket,
        SubpacketData,
    },
    ser::Serialize,
    types::{
        EddsaLegacyPublicParams, Fingerprint, Imprint, KeyDetails, KeyId, KeyVersion, Password,
        PlainSecretParams, PublicParams, SecretParams, SignatureBytes, SigningKey, Tag, Timestamp,
    },
};

#[derive(Debug, PartialEq, Eq, Clone, zeroize::ZeroizeOnDrop)]
pub struct SecretKey {
    #[zeroize(skip)]
    packet_header: PacketHeader,
    #[zeroize(skip)]
    details: super::PublicKey,
    secret_params: SecretParams,
}

#[derive(Debug, PartialEq, Eq, Clone, zeroize::ZeroizeOnDrop)]
pub struct SecretSubkey {
    #[zeroize(skip)]
    packet_header: PacketHeader,
    #[zeroize(skip)]
    details: super::PublicSubkey,
    secret_params: SecretParams,
}

impl SecretKey {
    pub fn new(details: super::PublicKey, secret_params: SecretParams) -> Result<Self> {
        let len =
            crate::ser::Serialize::write_len(&details) + secret_params.write_len(details.version());
        let packet_header = PacketHeader::new_fixed(Tag::SecretKey, len.try_into()?);

        Ok(Self {
            packet_header,
            details,
            secret_params,
        })
    }

    /// Parses a `SecretKey` packet from the given buffer.
    pub fn try_from_reader<B: BufRead>(packet_header: PacketHeader, input: B) -> Result<Self> {
        ensure_eq!(Tag::SecretKey, packet_header.tag(), "invalid tag");

        let details = crate::packet::secret_key_parser::parse(input)?;
        let (version, algorithm, created_at, expiration, public_params, secret_params) = details;

        let inner = PubKeyInner::new(version, algorithm, created_at, expiration, public_params)?;
        let len = inner.write_len();

        let pub_packet_header = PacketHeader::from_parts(
            packet_header.version(),
            Tag::PublicKey,
            crate::types::PacketLength::Fixed(len.try_into()?),
        )?;

        let details = super::PublicKey::from_inner_with_header(pub_packet_header, inner);

        Ok(Self {
            packet_header,
            details,
            secret_params,
        })
    }

    pub fn secret_params(&self) -> &SecretParams {
        &self.secret_params
    }

    /// Checks if we should expect a SHA1 checksum in the encrypted part.
    pub fn has_sha1_checksum(&self) -> bool {
        self.secret_params.has_sha1_checksum()
    }

    pub fn unlock<G, T>(&self, pw: &Password, work: G) -> Result<Result<T>>
    where
        G: FnOnce(&PublicParams, &PlainSecretParams) -> Result<T>,
    {
        let pub_params = self.details.public_params();
        match self.secret_params {
            SecretParams::Plain(ref k) => Ok(work(pub_params, k)),
            SecretParams::Encrypted(ref k) => {
                let plain = k.unlock(pw, &self.details, Some(self.packet_header.tag()))?;
                Ok(work(pub_params, &plain))
            }
        }
    }

    pub fn public_key(&self) -> &super::PublicKey {
        &self.details
    }
}

impl SecretSubkey {
    pub fn new(details: super::PublicSubkey, secret_params: SecretParams) -> Result<Self> {
        let len =
            crate::ser::Serialize::write_len(&details) + secret_params.write_len(details.version());
        let packet_header = PacketHeader::new_fixed(Tag::SecretSubkey, len.try_into()?);

        Ok(Self {
            packet_header,
            details,
            secret_params,
        })
    }

    /// Parses a `SecretSubkey` packet from the given slice.
    pub fn try_from_reader<B: BufRead>(packet_header: PacketHeader, input: B) -> Result<Self> {
        ensure_eq!(Tag::SecretSubkey, packet_header.tag(), "invalid tag");

        let details = crate::packet::secret_key_parser::parse(input)?;
        let (version, algorithm, created_at, expiration, public_params, secret_params) = details;
        let inner = PubKeyInner::new(version, algorithm, created_at, expiration, public_params)?;
        let len = inner.write_len();

        let pub_packet_header = PacketHeader::from_parts(
            packet_header.version(),
            Tag::PublicSubkey,
            crate::types::PacketLength::Fixed(len.try_into()?),
        )?;

        let details = super::PublicSubkey::from_inner_with_header(pub_packet_header, inner)?;

        Ok(Self {
            packet_header,
            details,
            secret_params,
        })
    }

    pub fn secret_params(&self) -> &SecretParams {
        &self.secret_params
    }

    /// Checks if we should expect a SHA1 checksum in the encrypted part.
    pub fn has_sha1_checksum(&self) -> bool {
        self.secret_params.has_sha1_checksum()
    }

    /// Produce a Primary Key Binding Signature over the primary `pub_key`.
    ///
    /// This signature is used in an embedded signature subpacket to show that the subkey is
    /// willing to be associated with the primary.
    pub fn sign_primary_key_binding<R: CryptoRng + ?Sized, K>(
        &self,
        rng: &mut R,
        pub_key: &K,
        key_pw: &Password,
    ) -> Result<Signature>
    where
        K: KeyDetails + Serialize,
    {
        let mut config = SignatureConfig::from_key(rng, self, SignatureType::KeyBinding)?;

        config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now()))?,
            Subpacket::regular(SubpacketData::IssuerFingerprint(self.fingerprint()))?,
        ];

        // If the version of the issuer is greater than 4, this subpacket MUST NOT be included in
        // the signature.
        if self.version() <= KeyVersion::V4 {
            config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::IssuerKeyId(
                self.legacy_key_id(),
            ))?];
        }

        config.sign_primary_key_binding(self, &self.public_key(), key_pw, &pub_key)
    }

    pub fn unlock<G, T>(&self, pw: &Password, work: G) -> Result<Result<T>>
    where
        G: FnOnce(&PublicParams, &PlainSecretParams) -> Result<T>,
    {
        let pub_params = self.details.public_params();
        match self.secret_params {
            SecretParams::Plain(ref k) => Ok(work(pub_params, k)),
            SecretParams::Encrypted(ref k) => {
                let plain = k.unlock(pw, &self.details, Some(self.packet_header.tag()))?;
                Ok(work(pub_params, &plain))
            }
        }
    }

    pub fn public_key(&self) -> &super::PublicSubkey {
        &self.details
    }
}

impl SigningKey for SecretKey {
    fn sign(&self, key_pw: &Password, hash: HashAlgorithm, data: &[u8]) -> Result<SignatureBytes> {
        let mut signature: Option<SignatureBytes> = None;
        self.unlock(key_pw, |pub_params, priv_key| {
            let sig = create_signature(pub_params, priv_key, hash, data)?;
            signature.replace(sig);
            Ok(())
        })??;

        signature.ok_or_else(|| unreachable!())
    }

    fn hash_alg(&self) -> HashAlgorithm {
        self.details.public_params().hash_alg()
    }
}

impl KeyDetails for SecretKey {
    fn version(&self) -> KeyVersion {
        self.details.version()
    }
    fn fingerprint(&self) -> Fingerprint {
        self.details.fingerprint()
    }

    fn legacy_key_id(&self) -> KeyId {
        self.details.legacy_key_id()
    }
    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.details.algorithm()
    }

    fn expiration(&self) -> Option<u16> {
        self.details.expiration()
    }

    fn created_at(&self) -> Timestamp {
        self.details.created_at()
    }

    fn public_params(&self) -> &PublicParams {
        self.details.public_params()
    }
}

impl Imprint for SecretKey {
    fn imprint<D: KnownDigest>(&self) -> Result<Array<u8, D::OutputSize>> {
        self.details.imprint::<D>()
    }
}

impl KeyDetails for SecretSubkey {
    fn version(&self) -> KeyVersion {
        self.details.version()
    }
    fn fingerprint(&self) -> Fingerprint {
        self.details.fingerprint()
    }

    fn legacy_key_id(&self) -> KeyId {
        self.details.legacy_key_id()
    }
    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.details.algorithm()
    }
    fn expiration(&self) -> Option<u16> {
        self.details.expiration()
    }

    fn created_at(&self) -> Timestamp {
        self.details.created_at()
    }

    fn public_params(&self) -> &PublicParams {
        self.details.public_params()
    }
}

impl Imprint for SecretSubkey {
    fn imprint<D: KnownDigest>(&self) -> Result<Array<u8, D::OutputSize>> {
        self.details.imprint::<D>()
    }
}

impl SigningKey for SecretSubkey {
    fn sign(&self, key_pw: &Password, hash: HashAlgorithm, data: &[u8]) -> Result<SignatureBytes> {
        let mut signature: Option<SignatureBytes> = None;
        self.unlock(key_pw, |pub_params, priv_key| {
            let sig = create_signature(pub_params, priv_key, hash, data)?;
            signature.replace(sig);
            Ok(())
        })??;

        signature.ok_or_else(|| unreachable!())
    }
    fn hash_alg(&self) -> HashAlgorithm {
        self.details.public_params().hash_alg()
    }
}

impl crate::ser::Serialize for SecretKey {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        // writes version and public part
        crate::ser::Serialize::to_writer(&self.details, writer)?;
        self.secret_params.to_writer(writer, self.version())?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        let details_len = crate::ser::Serialize::write_len(&self.details);
        let secret_params_len = self.secret_params.write_len(self.version());

        details_len + secret_params_len
    }
}

impl crate::ser::Serialize for SecretSubkey {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        // writes version and public part
        crate::ser::Serialize::to_writer(&self.details, writer)?;
        self.secret_params.to_writer(writer, self.version())?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        let details_len = crate::ser::Serialize::write_len(&self.details);
        let secret_params_len = self.secret_params.write_len(self.version());

        details_len + secret_params_len
    }
}

impl PacketTrait for SecretKey {
    fn packet_header(&self) -> &PacketHeader {
        &self.packet_header
    }
}

impl PacketTrait for SecretSubkey {
    fn packet_header(&self) -> &PacketHeader {
        &self.packet_header
    }
}

impl SecretKey {
    /// Remove the password protection of the private key material in this secret key packet.
    /// This permanently "unlocks" the secret key material.
    ///
    /// If the Secret Key material in the packet is not locked, it is left unchanged.
    ///
    /// The current locking password for this key must be provided in `password`.
    pub fn remove_password(&mut self, password: &Password) -> Result<()> {
        if let SecretParams::Encrypted(enc) = &self.secret_params {
            let unlocked = enc.unlock(password, &self.details, Some(self.packet_header.tag()))?;
            self.secret_params = SecretParams::Plain(unlocked);
        }

        Ok(())
    }

    /// Set a `password` that "locks" the private key material in this Secret Key packet.
    ///
    /// This function uses the default S2K locking mechanism for the key version:
    ///
    /// - for V6 keys: `Aead` with `Argon2` derivation,
    /// - for V4 keys: `Cfb` with iterated and salted derivation of the password.
    ///
    /// To change the password on a locked Secret Key packet, it needs to be unlocked
    /// using [Self::remove_password] before calling this function.
    pub fn set_password<R>(&mut self, rng: &mut R, password: &Password) -> Result<()>
    where
        R: rand::RngCore + rand::CryptoRng + ?Sized,
    {
        let s2k = crate::types::S2kParams::new_default(rng, self.version());
        Self::set_password_with_s2k(self, password, s2k)
    }

    /// Set a `password` that "locks" the private key material in this Secret Key packet
    /// using the mechanisms specified in `s2k_params`.
    ///
    /// To change the password on a locked Secret Key packet, it needs to be unlocked
    /// using [Self::remove_password] before calling this function.
    pub fn set_password_with_s2k(
        &mut self,
        password: &Password,
        s2k_params: crate::types::S2kParams,
    ) -> Result<()> {
        let plain = match &self.secret_params {
            SecretParams::Plain(plain) => plain,
            SecretParams::Encrypted(_) => {
                bail!("Secret Key packet must be unlocked")
            }
        };

        self.secret_params = SecretParams::Encrypted(plain.clone().encrypt(
            &password.read(),
            s2k_params,
            &self.details,
            Some(self.packet_header.tag()),
        )?);

        Ok(())
    }
}

impl SecretSubkey {
    /// Remove the password protection of the private key material in this secret key packet.
    /// This permanently "unlocks" the secret key material.
    ///
    /// If the Secret Key material in the packet is not locked, it is left unchanged.
    ///
    /// The current locking password for this key must be provided in `password`.
    pub fn remove_password(&mut self, password: &Password) -> Result<()> {
        if let SecretParams::Encrypted(enc) = &self.secret_params {
            let unlocked = enc.unlock(password, &self.details, Some(self.packet_header.tag()))?;
            self.secret_params = SecretParams::Plain(unlocked);
        }

        Ok(())
    }

    /// Set a `password` that "locks" the private key material in this Secret Key packet.
    ///
    /// This function uses the default S2K locking mechanism
    /// (`Cfb` with iterated and salted derivation of the password).
    ///
    /// To change the password on a locked Secret Key packet, it needs to be unlocked
    /// using [Self::remove_password] before calling this function.
    pub fn set_password<R>(&mut self, rng: &mut R, password: &Password) -> Result<()>
    where
        R: rand::RngCore + rand::CryptoRng + ?Sized,
    {
        let s2k = crate::types::S2kParams::new_default(rng, self.version());
        Self::set_password_with_s2k(self, password, s2k)
    }

    /// Set a `password` that "locks" the private key material in this Secret Key packet
    /// using the mechanisms specified in `s2k_params`.
    ///
    /// To change the password on a locked Secret Key packet, it needs to be unlocked
    /// using [Self::remove_password] before calling this function.
    pub fn set_password_with_s2k(
        &mut self,
        password: &Password,
        s2k_params: crate::types::S2kParams,
    ) -> Result<()> {
        let plain = match &self.secret_params {
            SecretParams::Plain(plain) => plain,
            SecretParams::Encrypted(_) => {
                bail!("Secret Key packet must be unlocked")
            }
        };

        self.secret_params = SecretParams::Encrypted(plain.clone().encrypt(
            &password.read(),
            s2k_params,
            &self.details,
            Some(self.packet_header.tag()),
        )?);

        Ok(())
    }

    /// Produce a Subkey Binding Signature (Type ID 0x18), to bind this subkey to a primary key
    pub fn sign<R: CryptoRng + ?Sized, S, K>(
        &self,
        rng: &mut R,
        primary_sec_key: &S,
        primary_pub_key: &K,
        key_pw: &Password,
        keyflags: KeyFlags,
        embedded: Option<Signature>,
    ) -> Result<Signature>
    where
        S: SigningKey,
        K: KeyDetails + Serialize,
    {
        self.details.sign(
            rng,
            primary_sec_key,
            primary_pub_key,
            key_pw,
            keyflags,
            embedded,
        )
    }
}

fn create_signature(
    pub_params: &PublicParams,
    priv_key: &PlainSecretParams,
    hash: HashAlgorithm,
    data: &[u8],
) -> Result<SignatureBytes> {
    use crate::crypto::Signer;

    debug!("unlocked key");
    match *priv_key {
        PlainSecretParams::RSA(ref priv_key) => {
            let PublicParams::RSA(_) = pub_params else {
                bail!("inconsistent key");
            };
            priv_key.sign(hash, data)
        }
        PlainSecretParams::ECDSA(ref priv_key) => {
            let PublicParams::ECDSA(_) = pub_params else {
                bail!("inconsistent key");
            };
            priv_key.sign(hash, data)
        }
        PlainSecretParams::DSA(ref priv_key) => {
            let PublicParams::DSA(_) = pub_params else {
                bail!("inconsistent key");
            };
            priv_key.sign(hash, data)
        }
        PlainSecretParams::ECDH(_) => {
            bail!("ECDH can not be used for signing operations")
        }
        PlainSecretParams::X25519(_) => {
            bail!("X25519 can not be used for signing operations")
        }
        #[cfg(feature = "draft-pqc")]
        PlainSecretParams::MlKem768X25519 { .. } => {
            bail!("ML KEM 768 X25519 can not be used for signing operations")
        }
        #[cfg(feature = "draft-pqc")]
        PlainSecretParams::MlKem1024X448 { .. } => {
            bail!("ML KEM 1024 X448 can not be used for signing operations")
        }
        PlainSecretParams::X448(_) => {
            bail!("X448 can not be used for signing operations")
        }
        PlainSecretParams::Ed25519(ref priv_key) => {
            let PublicParams::Ed25519(_) = pub_params else {
                bail!("invalid inconsistent key");
            };
            priv_key.sign(hash, data)
        }
        #[cfg(feature = "draft-pqc")]
        PlainSecretParams::MlDsa65Ed25519(ref priv_key) => {
            let PublicParams::MlDsa65Ed25519(_) = pub_params else {
                bail!("invalid inconsistent key");
            };
            priv_key.sign(hash, data)
        }
        #[cfg(feature = "draft-pqc")]
        PlainSecretParams::MlDsa87Ed448(ref priv_key) => {
            let PublicParams::MlDsa87Ed448(_) = pub_params else {
                bail!("invalid inconsistent key");
            };
            priv_key.sign(hash, data)
        }
        PlainSecretParams::Ed448(ref priv_key) => {
            let PublicParams::Ed448(_) = pub_params else {
                bail!("invalid inconsistent key");
            };
            priv_key.sign(hash, data)
        }
        PlainSecretParams::Ed25519Legacy(ref priv_key) => {
            match pub_params {
                PublicParams::EdDSALegacy(EddsaLegacyPublicParams::Ed25519 { .. }) => {}
                PublicParams::EdDSALegacy(EddsaLegacyPublicParams::Unsupported {
                    curve, ..
                }) => {
                    unsupported_err!("curve {} for EdDSA", curve);
                }
                _ => {
                    bail!("invalid inconsistent key");
                }
            }
            priv_key.sign(hash, data)
        }
        PlainSecretParams::Elgamal(_) => {
            unsupported_err!("Elgamal signing");
        }
        #[cfg(feature = "draft-pqc")]
        PlainSecretParams::SlhDsaShake128s(ref priv_key) => {
            let PublicParams::SlhDsaShake128s(_) = pub_params else {
                bail!("invalid inconsistent key");
            };
            priv_key.sign(hash, data)
        }
        #[cfg(feature = "draft-pqc")]
        PlainSecretParams::SlhDsaShake128f(ref priv_key) => {
            let PublicParams::SlhDsaShake128f(_) = pub_params else {
                bail!("invalid inconsistent key");
            };
            priv_key.sign(hash, data)
        }
        #[cfg(feature = "draft-pqc")]
        PlainSecretParams::SlhDsaShake256s(ref priv_key) => {
            let PublicParams::SlhDsaShake256s(_) = pub_params else {
                bail!("invalid inconsistent key");
            };
            priv_key.sign(hash, data)
        }
        PlainSecretParams::Unknown { alg, .. } => {
            unsupported_err!("{:?} signing", alg);
        }
    }
}

/// Signs a direct key signature or a revocation.
#[allow(dead_code)]
// TODO: Expose in public API
fn sign<R: CryptoRng + ?Sized, S, K>(
    rng: &mut R,
    key: &S,
    key_pw: &Password,
    sig_typ: SignatureType,
    pub_key: &K,
) -> Result<Signature>
where
    S: SigningKey,
    K: KeyDetails + Serialize,
{
    let mut config = SignatureConfig::from_key(rng, key, sig_typ)?;
    config.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now()))?,
        Subpacket::regular(SubpacketData::IssuerFingerprint(key.fingerprint()))?,
    ];
    if key.version() <= KeyVersion::V4 {
        config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::IssuerKeyId(
            key.legacy_key_id(),
        ))?];
    }

    config.sign_key(key, key_pw, pub_key)
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use chacha20::ChaCha8Rng;
    use rand::SeedableRng;

    use crate::{
        crypto::hash::HashAlgorithm,
        packet::{PubKeyInner, SecretKey},
        types::{KeyVersion, S2kParams, SigningKey, Timestamp},
    };

    #[test]
    #[ignore] // slow in debug mode (argon2)
    fn secret_key_protection_v4() {
        let _ = pretty_env_logger::try_init();

        let hash_algo = HashAlgorithm::Sha256;
        const DATA: &[u8] = &[0x23; 32];

        let key_type = crate::composed::KeyType::Ed25519Legacy;
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        let (public_params, secret_params) = key_type.generate(&mut rng).unwrap();

        let pub_key = PubKeyInner::new(
            KeyVersion::V4,
            key_type.to_alg(),
            Timestamp::now(),
            None,
            public_params,
        )
        .unwrap();
        let pub_key = crate::packet::PublicKey::from_inner(pub_key).unwrap();
        let mut alice_sec = SecretKey::new(pub_key, secret_params).unwrap();

        alice_sec
            .set_password_with_s2k(
                &"password".into(),
                crate::types::S2kParams::new_default(&mut rng, KeyVersion::V4),
            )
            .unwrap();

        // signing with a wrong password should fail
        assert!(alice_sec.sign(&"wrong".into(), hash_algo, DATA).is_err());

        // signing with the right password should succeed
        assert!(alice_sec.sign(&"password".into(), hash_algo, DATA).is_ok());

        // remove the password protection
        alice_sec.remove_password(&"password".into()).unwrap();

        // signing without a password should succeed now
        assert!(alice_sec.sign(&"".into(), hash_algo, DATA).is_ok());

        // set different password protection
        alice_sec.set_password(&mut rng, &"foo".into()).unwrap();

        // signing without a password should fail now
        assert!(alice_sec.sign(&"".into(), hash_algo, DATA).is_err());

        // signing with the right password should succeed
        assert!(alice_sec.sign(&"foo".into(), hash_algo, DATA).is_ok());

        // remove the password protection again
        alice_sec.remove_password(&"foo".into()).unwrap();

        // set password protection with v6 s2k defaults (AEAD+Argon2)
        alice_sec
            .set_password_with_s2k(
                &"bar".into(),
                S2kParams::new_default(&mut rng, KeyVersion::V6),
            )
            .unwrap();

        // signing with the right password should succeed
        alice_sec
            .sign(&"bar".into(), hash_algo, DATA)
            .expect("failed to sign");
    }
}

use bytes::Buf;
use log::debug;
use rand::{CryptoRng, Rng};

use crate::{
    crypto::{hash::HashAlgorithm, public_key::PublicKeyAlgorithm},
    errors::Result,
    packet::{
        PacketHeader, PacketTrait, PublicKey, PublicSubkey, Signature, SignatureConfig,
        SignatureType, Subpacket, SubpacketData,
    },
    types::{
        EddsaLegacyPublicParams, EskType, Fingerprint, KeyId, KeyVersion, MpiBytes, PkeskBytes,
        PlainSecretParams, PublicKeyTrait, PublicParams, SecretKeyTrait, SecretParams,
        SignatureBytes, Tag,
    },
};

use super::public::PubKeyInner;

#[derive(Debug, PartialEq, Eq, Clone, zeroize::ZeroizeOnDrop)]
pub struct SecretKey(SecretKeyInner<PubKeyInner>);

#[derive(Debug, PartialEq, Eq, Clone, zeroize::ZeroizeOnDrop)]
pub struct SecretSubkey(SecretKeyInner<PubKeyInner>);

#[derive(Debug, PartialEq, Eq, Clone, zeroize::ZeroizeOnDrop)]
struct SecretKeyInner<D> {
    #[zeroize(skip)]
    packet_header: PacketHeader,
    #[zeroize(skip)]
    details: D,
    secret_params: SecretParams,
}

impl<D: PublicKeyTrait + crate::ser::Serialize> SecretKeyInner<D> {
    fn remove_password<P>(&mut self, password: P) -> Result<()>
    where
        P: FnOnce() -> String,
    {
        if let SecretParams::Encrypted(enc) = &self.secret_params {
            let unlocked = enc.unlock(password, &self.details, Some(self.packet_header.tag()))?;
            self.secret_params = SecretParams::Plain(unlocked);
        }

        Ok(())
    }

    fn set_password<R, P>(&mut self, rng: R, password: P) -> Result<()>
    where
        R: rand::Rng + rand::CryptoRng,
        P: FnOnce() -> String,
    {
        let s2k = crate::types::S2kParams::new_default(rng, self.version());
        Self::set_password_with_s2k(self, password, s2k)
    }

    fn set_password_with_s2k<P>(
        &mut self,
        password: P,
        s2k_params: crate::types::S2kParams,
    ) -> Result<()>
    where
        P: FnOnce() -> String,
    {
        let plain = match &self.secret_params {
            SecretParams::Plain(plain) => plain,
            SecretParams::Encrypted(_) => {
                bail!("Secret Key packet must be unlocked")
            }
        };

        self.secret_params = SecretParams::Encrypted(plain.clone().encrypt(
            &password(),
            s2k_params,
            &self.details,
            Some(self.packet_header.tag()),
        )?);

        Ok(())
    }
}

impl SecretKey {
    pub fn new(details: PubKeyInner, secret_params: SecretParams) -> Self {
        let len =
            crate::ser::Serialize::write_len(&details) + secret_params.write_len(details.version());
        let packet_header = PacketHeader::new_fixed(Tag::SecretKey, len);

        Self(SecretKeyInner {
            packet_header,
            details,
            secret_params,
        })
    }

    /// Parses a `SecretKey` packet from the given buffer.
    pub fn from_buf<B: Buf>(packet_header: PacketHeader, input: B) -> Result<Self> {
        ensure_eq!(Tag::SecretKey, packet_header.tag(), "invalid tag");

        let details = crate::packet::secret_key_parser::parse(input)?;
        let (version, algorithm, created_at, expiration, public_params, secret_params) = details;

        Ok(Self(SecretKeyInner {
            packet_header,
            details: PubKeyInner::new(version, algorithm, created_at, expiration, public_params)?,
            secret_params,
        }))
    }

    pub fn secret_params(&self) -> &SecretParams {
        self.0.secret_params()
    }

    /// Checks if we should expect a SHA1 checksum in the encrypted part.
    pub fn has_sha1_checksum(&self) -> bool {
        self.0.has_sha1_checksum()
    }

    pub fn sign<R: CryptoRng + Rng, F>(
        &self,
        mut rng: R,
        key: &impl SecretKeyTrait,
        key_pw: F,
    ) -> Result<Signature>
    where
        F: FnOnce() -> String,
    {
        self.0
            .sign(&mut rng, key, key_pw, SignatureType::KeyBinding)
    }
}

impl SecretSubkey {
    pub fn new(details: PubKeyInner, secret_params: SecretParams) -> Self {
        let len =
            crate::ser::Serialize::write_len(&details) + secret_params.write_len(details.version());
        let packet_header = PacketHeader::new_fixed(Tag::SecretSubkey, len);

        Self(SecretKeyInner {
            packet_header,
            details,
            secret_params,
        })
    }

    /// Parses a `SecretSubkey` packet from the given slice.
    pub fn from_buf<B: Buf>(packet_header: PacketHeader, input: B) -> Result<Self> {
        ensure_eq!(Tag::SecretSubkey, packet_header.tag(), "invalid tag");

        let details = crate::packet::secret_key_parser::parse(input)?;
        let (version, algorithm, created_at, expiration, public_params, secret_params) = details;

        Ok(Self(SecretKeyInner {
            packet_header,
            details: PubKeyInner::new(version, algorithm, created_at, expiration, public_params)?,
            secret_params,
        }))
    }

    pub fn secret_params(&self) -> &SecretParams {
        self.0.secret_params()
    }

    /// Checks if we should expect a SHA1 checksum in the encrypted part.
    pub fn has_sha1_checksum(&self) -> bool {
        self.0.has_sha1_checksum()
    }

    pub fn sign<R: CryptoRng + Rng, F>(
        &self,
        mut rng: R,
        key: &impl SecretKeyTrait,
        key_pw: F,
    ) -> Result<Signature>
    where
        F: FnOnce() -> String,
    {
        self.0
            .sign(&mut rng, key, key_pw, SignatureType::SubkeyBinding)
    }
}

impl<D: PublicKeyTrait + crate::ser::Serialize> SecretKeyInner<D> {
    fn secret_params(&self) -> &SecretParams {
        &self.secret_params
    }

    fn has_sha1_checksum(&self) -> bool {
        self.secret_params.string_to_key_id() == 254
    }

    fn sign<R: CryptoRng + Rng, F>(
        &self,
        mut rng: R,
        key: &impl SecretKeyTrait,
        key_pw: F,
        sig_typ: SignatureType,
    ) -> Result<Signature>
    where
        F: FnOnce() -> String,
    {
        use chrono::SubsecRound;

        let mut config = match key.version() {
            KeyVersion::V4 => SignatureConfig::v4(sig_typ, key.algorithm(), key.hash_alg()),
            KeyVersion::V6 => {
                SignatureConfig::v6(&mut rng, sig_typ, key.algorithm(), key.hash_alg())?
            }
            v => unsupported_err!("unsupported key version: {:?}", v),
        };

        config.hashed_subpackets = vec![Subpacket::regular(SubpacketData::SignatureCreationTime(
            chrono::Utc::now().trunc_subsecs(0),
        ))?];
        config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::Issuer(key.key_id()))?];

        config.sign_key(key, key_pw, &self)
    }
}

impl<D: PublicKeyTrait + Clone + crate::ser::Serialize> SecretKeyTrait for SecretKeyInner<D> {
    type PublicKey = D;
    type Unlocked = PlainSecretParams;

    fn unlock<F, G, T>(&self, pw: F, work: G) -> Result<T>
    where
        F: FnOnce() -> String,
        G: FnOnce(&PublicParams, &Self::Unlocked) -> Result<T>,
    {
        let pub_params = self.details.public_params();
        match self.secret_params {
            SecretParams::Plain(ref k) => work(pub_params, k),
            SecretParams::Encrypted(ref k) => {
                let plain = k.unlock(pw, &self.details, Some(self.packet_header.tag()))?;
                work(pub_params, &plain)
            }
        }
    }

    fn create_signature<F>(
        &self,
        key_pw: F,
        hash: HashAlgorithm,
        data: &[u8],
    ) -> Result<SignatureBytes>
    where
        F: FnOnce() -> String,
    {
        use crate::crypto::Signer;

        let mut signature: Option<SignatureBytes> = None;
        self.unlock(key_pw, |pub_params, priv_key| {
            debug!("unlocked key");
            let sig = match *priv_key {
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
                #[cfg(feature = "unstable-curve448")]
                PlainSecretParams::X448(_) => {
                    bail!("X448 can not be used for signing operations")
                }
                PlainSecretParams::EdDSA(ref priv_key) => {
                    let PublicParams::Ed25519(_) = pub_params else {
                        bail!("invalid inconsistent key");
                    };
                    priv_key.sign(hash, data)
                }
                PlainSecretParams::EdDSALegacy(ref priv_key) => {
                    match pub_params {
                        PublicParams::EdDSALegacy(EddsaLegacyPublicParams::Ed25519 { .. }) => {}
                        PublicParams::EdDSALegacy(EddsaLegacyPublicParams::Unsupported {
                            curve,
                            ..
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
            }?;

            match pub_params {
                PublicParams::Ed25519 { .. } => {
                    // native format

                    ensure_eq!(sig.len(), 2, "expect two signature parts");

                    let mut native = sig[0].clone();
                    native.extend_from_slice(&sig[1]);

                    ensure_eq!(native.len(), 64, "expect 64 byte signature");

                    signature = Some(SignatureBytes::Native(native.into()));
                }
                _ => {
                    // MPI format:
                    // strip leading zeros, to match parse results from MPIs
                    let mpis = sig
                        .iter()
                        .map(|v| MpiBytes::from_slice(&v[..]))
                        .collect::<Vec<_>>();

                    signature = Some(SignatureBytes::Mpis(mpis));
                }
            }
            Ok(())
        })?;

        signature.ok_or_else(|| unreachable!())
    }

    fn public_key(&self) -> D {
        self.details.clone()
    }
}

impl SecretKeyTrait for SecretKey {
    type PublicKey = PublicKey;
    type Unlocked = PlainSecretParams;

    fn unlock<F, G, T>(&self, pw: F, work: G) -> Result<T>
    where
        F: FnOnce() -> String,
        G: FnOnce(&PublicParams, &Self::Unlocked) -> Result<T>,
    {
        SecretKeyTrait::unlock(&self.0, pw, work)
    }

    fn create_signature<F>(
        &self,
        key_pw: F,
        hash: HashAlgorithm,
        data: &[u8],
    ) -> Result<SignatureBytes>
    where
        F: FnOnce() -> String,
    {
        SecretKeyTrait::create_signature(&self.0, key_pw, hash, data)
    }

    fn public_key(&self) -> PublicKey {
        PublicKey::from_inner(self.0.details.clone())
    }
}

impl SecretKeyTrait for SecretSubkey {
    type PublicKey = PublicSubkey;
    type Unlocked = PlainSecretParams;

    fn unlock<F, G, T>(&self, pw: F, work: G) -> Result<T>
    where
        F: FnOnce() -> String,
        G: FnOnce(&PublicParams, &Self::Unlocked) -> Result<T>,
    {
        SecretKeyTrait::unlock(&self.0, pw, work)
    }

    fn create_signature<F>(
        &self,
        key_pw: F,
        hash: HashAlgorithm,
        data: &[u8],
    ) -> Result<SignatureBytes>
    where
        F: FnOnce() -> String,
    {
        SecretKeyTrait::create_signature(&self.0, key_pw, hash, data)
    }

    fn public_key(&self) -> PublicSubkey {
        PublicSubkey::from_inner(self.0.details.clone())
    }
}

impl<D: PublicKeyTrait + crate::ser::Serialize> crate::ser::Serialize for SecretKeyInner<D> {
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

impl crate::ser::Serialize for SecretKey {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        crate::ser::Serialize::to_writer(&self.0, writer)
    }

    fn write_len(&self) -> usize {
        crate::ser::Serialize::write_len(&self.0)
    }
}

impl crate::ser::Serialize for SecretSubkey {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        crate::ser::Serialize::to_writer(&self.0, writer)
    }

    fn write_len(&self) -> usize {
        crate::ser::Serialize::write_len(&self.0)
    }
}

impl PacketTrait for SecretKey {
    fn packet_header(&self) -> &PacketHeader {
        &self.0.packet_header
    }
}

impl PacketTrait for SecretSubkey {
    fn packet_header(&self) -> &PacketHeader {
        &self.0.packet_header
    }
}

impl PublicKeyTrait for SecretKey {
    fn verify_signature(
        &self,
        hash: HashAlgorithm,
        hashed: &[u8],
        sig: &SignatureBytes,
    ) -> Result<()> {
        PublicKeyTrait::verify_signature(&self.0, hash, hashed, sig)
    }

    fn encrypt<R: rand::Rng + rand::CryptoRng>(
        &self,
        rng: R,
        plain: &[u8],
        typ: EskType,
    ) -> Result<PkeskBytes> {
        PublicKeyTrait::encrypt(&self.0, rng, plain, typ)
    }

    fn serialize_for_hashing(&self, writer: &mut impl std::io::Write) -> Result<()> {
        PublicKeyTrait::serialize_for_hashing(&self.0, writer)
    }

    fn public_params(&self) -> &PublicParams {
        PublicKeyTrait::public_params(&self.0)
    }

    fn version(&self) -> KeyVersion {
        PublicKeyTrait::version(&self.0)
    }

    fn fingerprint(&self) -> Fingerprint {
        PublicKeyTrait::fingerprint(&self.0)
    }

    fn key_id(&self) -> KeyId {
        PublicKeyTrait::key_id(&self.0)
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        PublicKeyTrait::algorithm(&self.0)
    }

    fn created_at(&self) -> &chrono::DateTime<chrono::Utc> {
        PublicKeyTrait::created_at(&self.0)
    }

    fn expiration(&self) -> Option<u16> {
        PublicKeyTrait::expiration(&self.0)
    }
}

impl PublicKeyTrait for SecretSubkey {
    fn verify_signature(
        &self,
        hash: HashAlgorithm,
        hashed: &[u8],
        sig: &SignatureBytes,
    ) -> Result<()> {
        PublicKeyTrait::verify_signature(&self.0, hash, hashed, sig)
    }

    fn encrypt<R: rand::Rng + rand::CryptoRng>(
        &self,
        rng: R,
        plain: &[u8],
        typ: EskType,
    ) -> Result<PkeskBytes> {
        PublicKeyTrait::encrypt(&self.0, rng, plain, typ)
    }

    fn serialize_for_hashing(&self, writer: &mut impl std::io::Write) -> Result<()> {
        PublicKeyTrait::serialize_for_hashing(&self.0, writer)
    }

    fn public_params(&self) -> &PublicParams {
        PublicKeyTrait::public_params(&self.0)
    }

    fn version(&self) -> KeyVersion {
        PublicKeyTrait::version(&self.0)
    }

    fn fingerprint(&self) -> Fingerprint {
        PublicKeyTrait::fingerprint(&self.0)
    }

    fn key_id(&self) -> KeyId {
        PublicKeyTrait::key_id(&self.0)
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        PublicKeyTrait::algorithm(&self.0)
    }

    fn created_at(&self) -> &chrono::DateTime<chrono::Utc> {
        PublicKeyTrait::created_at(&self.0)
    }

    fn expiration(&self) -> Option<u16> {
        PublicKeyTrait::expiration(&self.0)
    }
}

impl<D: PublicKeyTrait + crate::ser::Serialize> PublicKeyTrait for SecretKeyInner<D> {
    fn verify_signature(
        &self,
        hash: HashAlgorithm,
        hashed: &[u8],
        sig: &SignatureBytes,
    ) -> Result<()> {
        self.details.verify_signature(hash, hashed, sig)
    }

    fn encrypt<R: rand::Rng + rand::CryptoRng>(
        &self,
        rng: R,
        plain: &[u8],
        typ: EskType,
    ) -> Result<PkeskBytes> {
        self.details.encrypt(rng, plain, typ)
    }

    fn serialize_for_hashing(&self, writer: &mut impl std::io::Write) -> Result<()> {
        self.details.serialize_for_hashing(writer)
    }
    fn public_params(&self) -> &PublicParams {
        self.details.public_params()
    }

    fn version(&self) -> KeyVersion {
        self.details.version()
    }

    fn fingerprint(&self) -> Fingerprint {
        self.details.fingerprint()
    }

    fn key_id(&self) -> KeyId {
        self.details.key_id()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.details.algorithm()
    }

    fn created_at(&self) -> &chrono::DateTime<chrono::Utc> {
        self.details.created_at()
    }

    fn expiration(&self) -> Option<u16> {
        self.details.expiration()
    }
}

impl SecretKey {
    /// Remove the password protection of the private key material in this secret key packet.
    /// This permanently "unlocks" the secret key material.
    ///
    /// If the Secret Key material in the packet is not locked, it is left unchanged.
    ///
    /// The current locking password for this key must be provided in `password`.
    pub fn remove_password<P>(&mut self, password: P) -> Result<()>
    where
        P: FnOnce() -> String,
    {
        self.0.remove_password(password)
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
    pub fn set_password<R, P>(&mut self, rng: R, password: P) -> Result<()>
    where
        R: rand::Rng + rand::CryptoRng,
        P: FnOnce() -> String,
    {
        self.0.set_password(rng, password)
    }

    /// Set a `password` that "locks" the private key material in this Secret Key packet
    /// using the mechanisms specified in `s2k_params`.
    ///
    /// To change the password on a locked Secret Key packet, it needs to be unlocked
    /// using [Self::remove_password] before calling this function.
    pub fn set_password_with_s2k<P>(
        &mut self,
        password: P,
        s2k_params: crate::types::S2kParams,
    ) -> Result<()>
    where
        P: FnOnce() -> String,
    {
        self.0.set_password_with_s2k(password, s2k_params)
    }
}

impl SecretSubkey {
    /// Remove the password protection of the private key material in this secret key packet.
    /// This permanently "unlocks" the secret key material.
    ///
    /// If the Secret Key material in the packet is not locked, it is left unchanged.
    ///
    /// The current locking password for this key must be provided in `password`.
    pub fn remove_password<P>(&mut self, password: P) -> Result<()>
    where
        P: FnOnce() -> String,
    {
        self.0.remove_password(password)
    }

    /// Set a `password` that "locks" the private key material in this Secret Key packet.
    ///
    /// This function uses the default S2K locking mechanism
    /// (`Cfb` with iterated and salted derivation of the password).
    ///
    /// To change the password on a locked Secret Key packet, it needs to be unlocked
    /// using [Self::remove_password] before calling this function.
    pub fn set_password<R, P>(&mut self, rng: R, password: P) -> Result<()>
    where
        R: rand::Rng + rand::CryptoRng,
        P: FnOnce() -> String,
    {
        self.0.set_password(rng, password)
    }

    /// Set a `password` that "locks" the private key material in this Secret Key packet
    /// using the mechanisms specified in `s2k_params`.
    ///
    /// To change the password on a locked Secret Key packet, it needs to be unlocked
    /// using [Self::remove_password] before calling this function.
    pub fn set_password_with_s2k<P>(
        &mut self,
        password: P,
        s2k_params: crate::types::S2kParams,
    ) -> Result<()>
    where
        P: FnOnce() -> String,
    {
        self.0.set_password_with_s2k(password, s2k_params)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use chrono::{SubsecRound, Utc};
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    use crate::crypto::hash::HashAlgorithm;
    use crate::packet::{PubKeyInner, SecretKey};
    use crate::types::{KeyVersion, S2kParams, SecretKeyTrait};

    #[test]
    #[ignore] // slow in debug mode (argon2)
    fn secret_key_protection_v4() {
        let _ = pretty_env_logger::try_init();

        const DATA: &[u8] = &[0x23, 0x05];
        let key_type = crate::KeyType::EdDSALegacy;
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        let (public_params, secret_params) = key_type.generate(&mut rng).unwrap();

        let mut alice_sec = SecretKey::new(
            PubKeyInner::new(
                KeyVersion::V4,
                key_type.to_alg(),
                Utc::now().trunc_subsecs(0),
                None,
                public_params,
            )
            .unwrap(),
            secret_params,
        );

        alice_sec
            .set_password_with_s2k(
                || "password".to_string(),
                crate::types::S2kParams::new_default(&mut rng, KeyVersion::V4),
            )
            .unwrap();

        // signing with a wrong password should fail
        assert!(alice_sec
            .create_signature(|| "wrong".to_string(), HashAlgorithm::default(), DATA)
            .is_err());

        // signing with the right password should succeed
        assert!(alice_sec
            .create_signature(|| "password".to_string(), HashAlgorithm::default(), DATA)
            .is_ok());

        // remove the password protection
        alice_sec
            .remove_password(|| "password".to_string())
            .unwrap();

        // signing without a password should succeed now
        assert!(alice_sec
            .create_signature(String::default, HashAlgorithm::default(), DATA)
            .is_ok());

        // set different password protection
        alice_sec
            .set_password(&mut rng, || "foo".to_string())
            .unwrap();

        // signing without a password should fail now
        assert!(alice_sec
            .create_signature(String::default, HashAlgorithm::default(), DATA)
            .is_err());

        // signing with the right password should succeed
        assert!(alice_sec
            .create_signature(|| "foo".to_string(), HashAlgorithm::default(), DATA)
            .is_ok());

        // remove the password protection again
        alice_sec.remove_password(|| "foo".to_string()).unwrap();

        // set password protection with v6 s2k defaults (AEAD+Argon2)
        alice_sec
            .set_password_with_s2k(
                || "bar".to_string(),
                S2kParams::new_default(&mut rng, KeyVersion::V6),
            )
            .unwrap();

        // signing with the right password should succeed
        alice_sec
            .create_signature(|| "bar".to_string(), HashAlgorithm::default(), DATA)
            .expect("failed to sign");
    }
}

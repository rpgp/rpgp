use std::io::BufRead;

use log::debug;
use rand::{CryptoRng, Rng};

use super::public::{encrypt, PubKeyInner};
use crate::{
    crypto::{hash::HashAlgorithm, public_key::PublicKeyAlgorithm},
    errors::{bail, ensure_eq, unsupported_err, Result},
    packet::{
        PacketHeader, PacketTrait, Signature, SignatureConfig, SignatureType, Subpacket,
        SubpacketData,
    },
    ser::Serialize,
    types::{
        EddsaLegacyPublicParams, EskType, Fingerprint, KeyDetails, KeyId, KeyVersion, Mpi,
        Password, PkeskBytes, PlainSecretParams, PublicKeyTrait, PublicParams, SecretKeyTrait,
        SecretParams, SignatureBytes, Tag,
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

    pub fn sign<R: CryptoRng + Rng, K, P>(
        &self,
        rng: R,
        key: &K,
        pub_key: &P,
        key_pw: Password,
    ) -> Result<Signature>
    where
        K: SecretKeyTrait,
        P: PublicKeyTrait + Serialize,
    {
        sign(rng, key, key_pw, SignatureType::KeyBinding, pub_key)
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

    pub fn sign<R: CryptoRng + Rng, K, P>(
        &self,
        rng: R,
        key: &K,
        pub_key: &P,
        key_pw: Password,
    ) -> Result<Signature>
    where
        K: SecretKeyTrait,
        P: PublicKeyTrait + Serialize,
    {
        sign(rng, key, key_pw, SignatureType::SubkeyBinding, pub_key)
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

impl SecretKeyTrait for SecretKey {
    fn create_signature(
        &self,
        key_pw: &Password,
        hash: HashAlgorithm,
        data: &[u8],
    ) -> Result<SignatureBytes> {
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

    fn key_id(&self) -> KeyId {
        self.details.key_id()
    }
    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.details.algorithm()
    }
}

impl KeyDetails for SecretSubkey {
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
}

impl SecretKeyTrait for SecretSubkey {
    fn create_signature(
        &self,
        key_pw: &Password,
        hash: HashAlgorithm,
        data: &[u8],
    ) -> Result<SignatureBytes> {
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
    pub fn set_password<R>(&mut self, rng: R, password: &Password) -> Result<()>
    where
        R: rand::Rng + rand::CryptoRng,
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

    pub fn encrypt<R: rand::Rng + rand::CryptoRng>(
        &self,
        rng: R,
        plain: &[u8],
        typ: EskType,
    ) -> Result<PkeskBytes> {
        encrypt(&self.details, rng, plain, typ)
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
    pub fn set_password<R>(&mut self, rng: R, password: &Password) -> Result<()>
    where
        R: rand::Rng + rand::CryptoRng,
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

    pub fn encrypt<R: rand::Rng + rand::CryptoRng>(
        &self,
        rng: R,
        plain: &[u8],
        typ: EskType,
    ) -> Result<PkeskBytes> {
        encrypt(&self.details, rng, plain, typ)
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
        PlainSecretParams::X448(_) => {
            bail!("X448 can not be used for signing operations")
        }
        PlainSecretParams::Ed25519(ref priv_key) => {
            let PublicParams::Ed25519(_) = pub_params else {
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
        PlainSecretParams::Unknown { alg, .. } => {
            unsupported_err!("{:?} signing", alg);
        }
    }?;

    match pub_params {
        PublicParams::Ed25519 { .. } => {
            // native format
            ensure_eq!(sig.len(), 2, "expect two signature parts");

            let mut native = sig[0].clone();
            native.extend_from_slice(&sig[1]);

            ensure_eq!(native.len(), 64, "expect 64 byte signature");

            Ok(SignatureBytes::Native(native.into()))
        }
        PublicParams::Ed448 { .. } => {
            // native format
            ensure_eq!(sig.len(), 2, "expect two signature parts");

            let mut native = sig[0].clone();
            native.extend_from_slice(&sig[1]);

            ensure_eq!(native.len(), 114, "expect 114 byte signature");

            Ok(SignatureBytes::Native(native.into()))
        }
        _ => {
            // MPI format:
            // strip leading zeros, to match parse results from MPIs
            let mpis = sig
                .iter()
                .map(|v| Mpi::from_slice(&v[..]))
                .collect::<Vec<_>>();

            Ok(SignatureBytes::Mpis(mpis))
        }
    }
}

fn sign<R: CryptoRng + Rng, K, P>(
    mut rng: R,
    key: &K,
    key_pw: Password,
    sig_typ: SignatureType,
    pub_key: &P,
) -> Result<Signature>
where
    K: SecretKeyTrait,
    P: PublicKeyTrait + Serialize,
{
    use chrono::SubsecRound;

    let mut config = match key.version() {
        KeyVersion::V4 => SignatureConfig::v4(sig_typ, key.algorithm(), key.hash_alg()),
        KeyVersion::V6 => SignatureConfig::v6(&mut rng, sig_typ, key.algorithm(), key.hash_alg())?,
        v => unsupported_err!("unsupported key version: {:?}", v),
    };

    config.hashed_subpackets = vec![Subpacket::regular(SubpacketData::SignatureCreationTime(
        chrono::Utc::now().trunc_subsecs(0),
    ))?];
    config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::Issuer(key.key_id()))?];

    config.sign_key(key, key_pw, pub_key)
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use chrono::{SubsecRound, Utc};
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    use crate::{
        crypto::hash::HashAlgorithm,
        packet::{PubKeyInner, SecretKey},
        types::{KeyVersion, S2kParams, SecretKeyTrait},
    };

    #[test]
    #[ignore] // slow in debug mode (argon2)
    fn secret_key_protection_v4() {
        let _ = pretty_env_logger::try_init();

        const DATA: &[u8] = &[0x23, 0x05];
        let key_type = crate::composed::KeyType::Ed25519Legacy;
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        let (public_params, secret_params) = key_type.generate(&mut rng).unwrap();

        let pub_key = PubKeyInner::new(
            KeyVersion::V4,
            key_type.to_alg(),
            Utc::now().trunc_subsecs(0),
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
        assert!(alice_sec
            .create_signature(&"wrong".into(), HashAlgorithm::default(), DATA)
            .is_err());

        // signing with the right password should succeed
        assert!(alice_sec
            .create_signature(&"password".into(), HashAlgorithm::default(), DATA)
            .is_ok());

        // remove the password protection
        alice_sec.remove_password(&"password".into()).unwrap();

        // signing without a password should succeed now
        assert!(alice_sec
            .create_signature(&"".into(), HashAlgorithm::default(), DATA)
            .is_ok());

        // set different password protection
        alice_sec.set_password(&mut rng, &"foo".into()).unwrap();

        // signing without a password should fail now
        assert!(alice_sec
            .create_signature(&"".into(), HashAlgorithm::default(), DATA)
            .is_err());

        // signing with the right password should succeed
        assert!(alice_sec
            .create_signature(&"foo".into(), HashAlgorithm::default(), DATA)
            .is_ok());

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
            .create_signature(&"bar".into(), HashAlgorithm::default(), DATA)
            .expect("failed to sign");
    }
}

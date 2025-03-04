use std::time::Duration;

use chrono::SubsecRound;
use derive_builder::Builder;
use rand::{CryptoRng, Rng};
use smallvec::SmallVec;

use crate::composed::{KeyDetails, SecretKey, SecretSubkey};
use crate::crypto::aead::AeadAlgorithm;
use crate::crypto::ecc_curve::ECCCurve;
use crate::crypto::hash::HashAlgorithm;
use crate::crypto::public_key::PublicKeyAlgorithm;
use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::crypto::{dsa, ecdh, ecdsa, eddsa, rsa, x25519};
use crate::errors::Result;
use crate::packet::{self, KeyFlags, PubKeyInner, UserAttribute, UserId};
use crate::types::{
    self, CompressionAlgorithm, PlainSecretParams, PublicParams, RevocationKey, S2kParams,
};

#[derive(Debug, PartialEq, Eq, Builder)]
#[builder(build_fn(validate = "Self::validate"))]
pub struct SecretKeyParams {
    key_type: KeyType,

    // -- Keyflags
    #[builder(default)]
    can_sign: bool,
    #[builder(default)]
    can_certify: bool,
    #[builder(default)]
    can_encrypt: bool,

    // -- Preferences
    /// List of symmetric algorithms that indicate which algorithms the key holder prefers to use.
    #[builder(default)]
    preferred_symmetric_algorithms: SmallVec<[SymmetricKeyAlgorithm; 8]>,
    /// List of hash algorithms that indicate which algorithms the key holder prefers to use.
    #[builder(default)]
    preferred_hash_algorithms: SmallVec<[HashAlgorithm; 8]>,
    /// List of compression algorithms that indicate which algorithms the key holder prefers to use.
    #[builder(default)]
    preferred_compression_algorithms: SmallVec<[CompressionAlgorithm; 8]>,
    #[builder(default)]
    preferred_aead_algorithms: SmallVec<[(SymmetricKeyAlgorithm, AeadAlgorithm); 4]>,
    #[builder(default)]
    revocation_key: Option<RevocationKey>,

    #[builder]
    primary_user_id: String,

    #[builder(default)]
    user_ids: Vec<String>,
    #[builder(default)]
    user_attributes: Vec<UserAttribute>,
    #[builder(default)]
    passphrase: Option<String>,
    #[builder(default)]
    s2k: Option<S2kParams>,
    #[builder(default = "chrono::Utc::now().trunc_subsecs(0)")]
    created_at: chrono::DateTime<chrono::Utc>,
    #[builder(default)]
    packet_version: types::PacketHeaderVersion,
    #[builder(default)]
    version: types::KeyVersion,
    #[builder(default)]
    expiration: Option<Duration>,

    #[builder(default)]
    subkeys: Vec<SubkeyParams>,
}

#[derive(Debug, Clone, PartialEq, Eq, Builder)]
pub struct SubkeyParams {
    key_type: KeyType,

    #[builder(default)]
    can_sign: bool,
    #[builder(default)]
    can_certify: bool,
    #[builder(default)]
    can_encrypt: bool,
    #[builder(default)]
    can_authenticate: bool,

    #[builder(default)]
    user_ids: Vec<UserId>,
    #[builder(default)]
    user_attributes: Vec<UserAttribute>,
    #[builder(default)]
    passphrase: Option<String>,
    #[builder(default)]
    s2k: Option<S2kParams>,
    #[builder(default = "chrono::Utc::now().trunc_subsecs(0)")]
    created_at: chrono::DateTime<chrono::Utc>,
    #[builder(default)]
    packet_version: types::PacketHeaderVersion,
    #[builder(default)]
    version: types::KeyVersion,
    #[builder(default)]
    expiration: Option<Duration>,
}

impl SecretKeyParamsBuilder {
    fn validate(&self) -> std::result::Result<(), String> {
        match &self.key_type {
            Some(KeyType::Rsa(size)) => {
                if *size < 2048 {
                    return Err("Keys with less than 2048bits are considered insecure".into());
                }
            }
            Some(KeyType::EdDSALegacy) => {
                if let Some(can_encrypt) = self.can_encrypt {
                    if can_encrypt {
                        return Err("EdDSA can only be used for signing keys".into());
                    }
                }
            }
            Some(KeyType::ECDSA(curve)) => {
                if let Some(can_encrypt) = self.can_encrypt {
                    if can_encrypt {
                        return Err("ECDSA can only be used for signing keys".into());
                    }
                };
                match curve {
                    ECCCurve::P256 | ECCCurve::P384 | ECCCurve::P521 | ECCCurve::Secp256k1 => {}
                    _ => return Err(format!("Curve {} is not supported for ECDSA", curve.name())),
                }
            }
            Some(KeyType::ECDH(_)) => {
                if let Some(can_sign) = self.can_sign {
                    if can_sign {
                        return Err("ECDH can only be used for encryption keys".into());
                    }
                }
            }
            Some(KeyType::Dsa(_)) => {
                if let Some(can_encrypt) = self.can_encrypt {
                    if can_encrypt {
                        return Err("DSA can only be used for signing keys".into());
                    }
                }
            }
            _ => {}
        }

        Ok(())
    }

    pub fn user_id<VALUE: Into<String>>(&mut self, value: VALUE) -> &mut Self {
        if let Some(ref mut user_ids) = self.user_ids {
            user_ids.push(value.into());
        } else {
            self.user_ids = Some(vec![value.into()]);
        }
        self
    }

    pub fn subkey<VALUE: Into<SubkeyParams>>(&mut self, value: VALUE) -> &mut Self {
        if let Some(ref mut subkeys) = self.subkeys {
            subkeys.push(value.into());
        } else {
            self.subkeys = Some(vec![value.into()]);
        }
        self
    }
}

impl SecretKeyParams {
    pub fn generate_with_rng<R: Rng + CryptoRng>(self, mut rng: R) -> Result<SecretKey> {
        let passphrase = self.passphrase;
        let s2k = self
            .s2k
            .unwrap_or_else(|| S2kParams::new_default_with_rng(&mut rng, self.version));
        let (public_params, secret_params) = self.key_type.generate(&mut rng)?;
        let pub_key = PubKeyInner::new(
            self.version,
            self.key_type.to_alg(),
            self.created_at,
            self.expiration.map(|v| v.as_secs() as u16),
            public_params,
        )?;
        let pub_key = crate::packet::PublicKey::from_inner(pub_key)?;
        let mut primary_key = packet::SecretKey::new(pub_key, secret_params)?;
        if let Some(passphrase) = passphrase {
            primary_key.set_password_with_s2k(&passphrase.into(), s2k)?;
        }

        let mut keyflags = KeyFlags::default();
        keyflags.set_certify(self.can_certify);
        keyflags.set_encrypt_comms(self.can_encrypt);
        keyflags.set_encrypt_storage(self.can_encrypt);
        keyflags.set_sign(self.can_sign);

        Ok(SecretKey::new(
            primary_key,
            KeyDetails::new(
                UserId::from_str(Default::default(), &self.primary_user_id)?,
                self.user_ids
                    .iter()
                    .map(|m| UserId::from_str(Default::default(), m))
                    .collect::<Result<Vec<_>, _>>()?,
                self.user_attributes,
                keyflags,
                self.preferred_symmetric_algorithms,
                self.preferred_hash_algorithms,
                self.preferred_compression_algorithms,
                self.preferred_aead_algorithms,
                self.revocation_key,
            ),
            Default::default(),
            self.subkeys
                .into_iter()
                .map(|subkey| {
                    let passphrase = subkey.passphrase;
                    let s2k = subkey.s2k.unwrap_or_else(|| {
                        S2kParams::new_default_with_rng(&mut rng, subkey.version)
                    });
                    let (public_params, secret_params) = subkey.key_type.generate(&mut rng)?;
                    let mut keyflags = KeyFlags::default();
                    keyflags.set_certify(subkey.can_certify);
                    keyflags.set_encrypt_comms(subkey.can_encrypt);
                    keyflags.set_encrypt_storage(subkey.can_encrypt);
                    keyflags.set_sign(subkey.can_sign);
                    keyflags.set_authentication(subkey.can_authenticate);

                    let pub_key = PubKeyInner::new(
                        subkey.version,
                        subkey.key_type.to_alg(),
                        subkey.created_at,
                        subkey.expiration.map(|v| v.as_secs() as u16),
                        public_params,
                    )?;
                    let pub_key = packet::PublicSubkey::from_inner(pub_key)?;
                    let mut sub = packet::SecretSubkey::new(pub_key, secret_params)?;

                    if let Some(passphrase) = passphrase {
                        sub.set_password_with_s2k(&passphrase.as_str().into(), s2k)?;
                    }

                    Ok(SecretSubkey::new(sub, keyflags))
                })
                .collect::<Result<Vec<_>>>()?,
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyType {
    /// Encryption & Signing with RSA and the given bitsize.
    Rsa(u32),
    /// Encrypting with ECDH
    ECDH(ECCCurve),
    /// Signing with Curve25519, legacy format (deprecated in RFC 9580)
    EdDSALegacy,
    /// Signing with ECDSA
    ECDSA(ECCCurve),
    /// Signing with DSA for the given bitsize.
    Dsa(DsaKeySize),
    /// Signing with Ed25519
    Ed25519,
    /// Encrypting with X25519
    X25519,
    /// Encrypting with X448
    #[cfg(feature = "unstable-curve448")]
    X448,
}

#[derive(Clone, Debug, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DsaKeySize {
    /// DSA parameter size constant: L = 1024, N = 160
    B1024 = 1024,
    /// DSA parameter size constant: L = 2048, N = 256
    B2048 = 2048,
    /// DSA parameter size constant: L = 3072, N = 256
    B3072 = 3072,
}

impl From<DsaKeySize> for dsa::KeySize {
    fn from(value: DsaKeySize) -> Self {
        match value {
            #[allow(deprecated)]
            DsaKeySize::B1024 => dsa::KeySize::DSA_1024_160,
            DsaKeySize::B2048 => dsa::KeySize::DSA_2048_256,
            DsaKeySize::B3072 => dsa::KeySize::DSA_3072_256,
        }
    }
}

impl KeyType {
    pub fn to_alg(&self) -> PublicKeyAlgorithm {
        match self {
            KeyType::Rsa(_) => PublicKeyAlgorithm::RSA,
            KeyType::ECDH(_) => PublicKeyAlgorithm::ECDH,
            KeyType::EdDSALegacy => PublicKeyAlgorithm::EdDSALegacy,
            KeyType::ECDSA(_) => PublicKeyAlgorithm::ECDSA,
            KeyType::Dsa(_) => PublicKeyAlgorithm::DSA,
            KeyType::Ed25519 => PublicKeyAlgorithm::Ed25519,
            KeyType::X25519 => PublicKeyAlgorithm::X25519,
            #[cfg(feature = "unstable-curve448")]
            KeyType::X448 => PublicKeyAlgorithm::X448,
        }
    }

    pub fn generate<R: Rng + CryptoRng>(
        &self,
        rng: R,
    ) -> Result<(PublicParams, types::SecretParams)> {
        let (pub_params, plain) = match self {
            KeyType::Rsa(bit_size) => {
                let secret = rsa::SecretKey::generate_with_rng(rng, *bit_size as usize)?;
                let public_params = PublicParams::RSA((&secret).into());
                let secret_params = PlainSecretParams::RSA(secret);
                (public_params, secret_params)
            }
            KeyType::ECDH(curve) => {
                let secret = ecdh::SecretKey::generate_with_rng(rng, curve)?;
                let public_params = PublicParams::ECDH((&secret).into());
                let secret_params = PlainSecretParams::ECDH(secret);
                (public_params, secret_params)
            }
            KeyType::EdDSALegacy => {
                let secret = eddsa::SecretKey::generate_with_rng(rng);
                let public_params = PublicParams::EdDSALegacy((&secret).into());
                let secret_params = PlainSecretParams::EdDSALegacy(secret);
                (public_params, secret_params)
            }
            KeyType::ECDSA(curve) => {
                let secret = ecdsa::SecretKey::generate_with_rng(rng, curve)?;
                let public_params = PublicParams::ECDSA(
                    (&secret).try_into().expect("must not generate unuspported"),
                );
                let secret_params = PlainSecretParams::ECDSA(secret);
                (public_params, secret_params)
            }
            KeyType::Dsa(key_size) => {
                let secret = dsa::SecretKey::generate_with_rng(rng, (*key_size).into());
                let public_params = PublicParams::DSA((&secret).into());
                let secret_params = PlainSecretParams::DSA(secret);
                (public_params, secret_params)
            }
            KeyType::Ed25519 => {
                let secret = eddsa::SecretKey::generate_with_rng(rng);
                let public_params = PublicParams::Ed25519((&secret).into());
                let secret_params = PlainSecretParams::EdDSA(secret);
                (public_params, secret_params)
            }
            KeyType::X25519 => {
                let secret = x25519::SecretKey::generate_with_rng(rng);
                let public_params = PublicParams::X25519((&secret).into());
                let secret_params = PlainSecretParams::X25519(secret);
                (public_params, secret_params)
            }
            #[cfg(feature = "unstable-curve448")]
            KeyType::X448 => {
                let secret = crate::crypto::x448::SecretKey::generate_with_rng(rng);
                let public_params = PublicParams::X448((&secret).into());
                let secret_params = PlainSecretParams::X448(secret);
                (public_params, secret_params)
            }
        };

        Ok((pub_params, types::SecretParams::Plain(plain)))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;
    use smallvec::smallvec;

    use super::*;
    use crate::composed::{Deserializable, SignedPublicKey, SignedSecretKey};
    use crate::types::KeyVersion;

    #[test]
    #[ignore] // slow in debug mode
    fn test_key_gen_rsa_2048_v4() {
        let _ = pretty_env_logger::try_init();
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        for i in 0..5 {
            println!("round {i}");
            gen_rsa_2048(&mut rng, KeyVersion::V4);
        }
    }

    #[test]
    #[ignore] // slow in debug mode
    fn test_key_gen_rsa_2048_v6() {
        let _ = pretty_env_logger::try_init();
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        for i in 0..5 {
            println!("round {i}");
            gen_rsa_2048(&mut rng, KeyVersion::V6);
        }
    }

    fn gen_rsa_2048<R: Rng + CryptoRng>(mut rng: R, version: KeyVersion) {
        let mut key_params = SecretKeyParamsBuilder::default();
        key_params
            .version(version)
            .key_type(KeyType::Rsa(2048))
            .can_certify(true)
            .can_sign(true)
            .primary_user_id("Me <me@mail.com>".into())
            .preferred_symmetric_algorithms(smallvec![
                SymmetricKeyAlgorithm::AES256,
                SymmetricKeyAlgorithm::AES192,
                SymmetricKeyAlgorithm::AES128,
            ])
            .preferred_hash_algorithms(smallvec![
                HashAlgorithm::Sha256,
                HashAlgorithm::Sha384,
                HashAlgorithm::Sha512,
                HashAlgorithm::Sha224,
                HashAlgorithm::Sha1,
            ])
            .preferred_compression_algorithms(smallvec![
                CompressionAlgorithm::ZLIB,
                CompressionAlgorithm::ZIP,
            ]);

        let key_params_enc = key_params
            .clone()
            .passphrase(Some("hello".into()))
            .subkey(
                SubkeyParamsBuilder::default()
                    .version(version)
                    .key_type(KeyType::Rsa(2048))
                    .passphrase(Some("hello".into()))
                    .can_encrypt(true)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        let key_enc = key_params_enc
            .generate_with_rng(&mut rng)
            .expect("failed to generate secret key, encrypted");

        let key_params_plain = key_params
            .passphrase(None)
            .subkey(
                SubkeyParamsBuilder::default()
                    .version(version)
                    .key_type(KeyType::Rsa(2048))
                    .can_encrypt(true)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        let key_plain = key_params_plain
            .generate_with_rng(&mut rng)
            .expect("failed to generate secret key");

        let signed_key_enc = key_enc
            .sign_with_rng(&mut rng, &"hello".into())
            .expect("failed to sign key");
        let signed_key_plain = key_plain
            .sign_with_rng(&mut rng, &"".into())
            .expect("failed to sign key");

        let armor_enc = signed_key_enc
            .to_armored_string(None.into())
            .expect("failed to serialize key");
        let armor_plain = signed_key_plain
            .to_armored_string(None.into())
            .expect("failed to serialize key");

        // std::fs::write("sample-rsa-enc.sec.asc", &armor_enc).unwrap();
        // std::fs::write("sample-rsa.sec.asc", &armor_plain).unwrap();

        let (signed_key2_enc, _headers) =
            SignedSecretKey::from_string(&armor_enc).expect("failed to parse key (enc)");
        signed_key2_enc.verify().expect("invalid key (enc)");

        let (signed_key2_plain, _headers) =
            SignedSecretKey::from_string(&armor_plain).expect("failed to parse key (plain)");
        signed_key2_plain.verify().expect("invalid key (plain)");

        signed_key2_enc
            .unlock(&"hello".into(), |_, _| Ok(()))
            .expect("failed to unlock parsed key (enc)");
        signed_key2_plain
            .unlock(&"".into(), |_, _| Ok(()))
            .expect("failed to unlock parsed key (plain)");

        assert_eq!(signed_key_plain, signed_key2_plain);

        let public_key = signed_key_plain.public_key();

        let public_signed_key = public_key
            .sign(
                &mut rng,
                &*signed_key_plain,
                &*signed_key_plain.public_key(),
                &"".into(),
            )
            .expect("failed to sign public key");

        public_signed_key.verify().expect("invalid public key");

        let armor = public_signed_key
            .to_armored_string(None.into())
            .expect("failed to serialize public key");

        // std::fs::write("sample-rsa.pub.asc", &armor).unwrap();

        let (signed_key2, _headers) =
            SignedPublicKey::from_string(&armor).expect("failed to parse public key");
        signed_key2.verify().expect("invalid public key");
    }

    #[ignore]
    #[test]
    fn key_gen_25519_legacy_long() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        for i in 0..10_000 {
            println!("round {i}");
            gen_25519_legacy(&mut rng);
        }
    }

    #[test]
    fn key_gen_25519_legacy_short() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        for _ in 0..10 {
            gen_25519_legacy(&mut rng);
        }
    }

    fn gen_25519_legacy<R: Rng + CryptoRng>(mut rng: R) {
        // The v4-only key format variants based on Curve 25519 (EdDSALegacy/ECDH over 25519)

        let _ = pretty_env_logger::try_init();

        let key_params = SecretKeyParamsBuilder::default()
            .key_type(KeyType::EdDSALegacy)
            .can_certify(true)
            .can_sign(true)
            .primary_user_id("Me-X <me-25519-legacy@mail.com>".into())
            .passphrase(None)
            .preferred_symmetric_algorithms(smallvec![
                SymmetricKeyAlgorithm::AES256,
                SymmetricKeyAlgorithm::AES192,
                SymmetricKeyAlgorithm::AES128,
            ])
            .preferred_hash_algorithms(smallvec![
                HashAlgorithm::Sha256,
                HashAlgorithm::Sha384,
                HashAlgorithm::Sha512,
                HashAlgorithm::Sha224,
                HashAlgorithm::Sha1,
            ])
            .preferred_compression_algorithms(smallvec![
                CompressionAlgorithm::ZLIB,
                CompressionAlgorithm::ZIP,
            ])
            .subkey(
                SubkeyParamsBuilder::default()
                    .key_type(KeyType::ECDH(ECCCurve::Curve25519))
                    .can_encrypt(true)
                    .passphrase(None)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();

        let key = key_params
            .generate_with_rng(&mut rng)
            .expect("failed to generate secret key");

        let signed_key = key
            .sign_with_rng(&mut rng, &"".into())
            .expect("failed to sign key");

        let armor = signed_key
            .to_armored_string(None.into())
            .expect("failed to serialize key");

        // std::fs::write("sample-25519-legacy.sec.asc", &armor).unwrap();

        let (signed_key2, _headers) =
            SignedSecretKey::from_string(&armor).expect("failed to parse key");
        signed_key2.verify().expect("invalid key");

        assert_eq!(signed_key, signed_key2);

        let public_key = signed_key.public_key();

        let public_signed_key = public_key
            .sign(
                &mut rng,
                &*signed_key,
                &*signed_key.public_key(),
                &"".into(),
            )
            .expect("failed to sign public key");

        public_signed_key.verify().expect("invalid public key");

        let armor = public_signed_key
            .to_armored_string(None.into())
            .expect("failed to serialize public key");

        // std::fs::write("sample-25519-legacy.pub.asc", &armor).unwrap();

        let (signed_key2, _headers) =
            SignedPublicKey::from_string(&armor).expect("failed to parse public key");
        signed_key2.verify().expect("invalid public key");
    }

    #[ignore]
    #[test]
    fn key_gen_25519_rfc9580_long() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        for key_version in [KeyVersion::V4, KeyVersion::V6] {
            println!("key version {:?}", key_version);

            for i in 0..10_000 {
                println!("round {i}");
                gen_25519_rfc9580(&mut rng, key_version);
            }
        }
    }

    #[test]
    fn key_gen_25519_rfc9580_short() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        for key_version in [KeyVersion::V4, KeyVersion::V6] {
            println!("key version {:?}", key_version);

            for _ in 0..10 {
                gen_25519_rfc9580(&mut rng, key_version);
            }
        }
    }

    fn gen_25519_rfc9580<R: Rng + CryptoRng>(mut rng: R, version: KeyVersion) {
        // The RFC 9580 key format variants based on Curve 25519 (X25519/Ed25519)

        let _ = pretty_env_logger::try_init();

        let key_params = SecretKeyParamsBuilder::default()
            .version(version)
            .key_type(KeyType::Ed25519)
            .can_certify(true)
            .can_sign(true)
            .primary_user_id("Me-X <me-25519-rfc9580@mail.com>".into())
            .passphrase(None)
            .preferred_symmetric_algorithms(smallvec![
                SymmetricKeyAlgorithm::AES256,
                SymmetricKeyAlgorithm::AES192,
                SymmetricKeyAlgorithm::AES128,
            ])
            .preferred_hash_algorithms(smallvec![
                HashAlgorithm::Sha256,
                HashAlgorithm::Sha384,
                HashAlgorithm::Sha512,
                HashAlgorithm::Sha224,
                HashAlgorithm::Sha1,
            ])
            .preferred_compression_algorithms(smallvec![
                CompressionAlgorithm::ZLIB,
                CompressionAlgorithm::ZIP,
            ])
            .subkey(
                SubkeyParamsBuilder::default()
                    .version(version)
                    .key_type(KeyType::X25519)
                    .can_encrypt(true)
                    .passphrase(None)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();

        let key = key_params
            .generate_with_rng(&mut rng)
            .expect("failed to generate secret key");

        let signed_key = key
            .sign_with_rng(&mut rng, &"".into())
            .expect("failed to sign key");

        let armor = signed_key
            .to_armored_string(None.into())
            .expect("failed to serialize key");

        // std::fs::write("sample-25519-rfc9580.sec.asc", &armor).unwrap();

        let (signed_key2, _headers) =
            SignedSecretKey::from_string(&armor).expect("failed to parse key");
        signed_key2.verify().expect("invalid key");

        assert_eq!(signed_key, signed_key2);

        let public_key = signed_key.public_key();

        let public_signed_key = public_key
            .sign(
                &mut rng,
                &*signed_key,
                &*signed_key.public_key(),
                &"".into(),
            )
            .expect("failed to sign public key");

        public_signed_key.verify().expect("invalid public key");

        let armor = public_signed_key
            .to_armored_string(None.into())
            .expect("failed to serialize public key");

        // std::fs::write("sample-25519-rfc9580.pub.asc", &armor).unwrap();

        let (signed_key2, _headers) =
            SignedPublicKey::from_string(&armor).expect("failed to parse public key");
        signed_key2.verify().expect("invalid public key");
    }

    fn gen_ecdsa_ecdh<R: Rng + CryptoRng>(
        mut rng: R,
        ecdsa: ECCCurve,
        ecdh: ECCCurve,
        version: KeyVersion,
    ) {
        let _ = pretty_env_logger::try_init();

        let key_params = SecretKeyParamsBuilder::default()
            .version(version)
            .key_type(KeyType::ECDSA(ecdsa.clone()))
            .can_certify(true)
            .can_sign(true)
            .primary_user_id("Me-X <me-ecdsa@mail.com>".into())
            .passphrase(None)
            .preferred_symmetric_algorithms(smallvec![
                SymmetricKeyAlgorithm::AES256,
                SymmetricKeyAlgorithm::AES192,
                SymmetricKeyAlgorithm::AES128,
            ])
            .preferred_hash_algorithms(smallvec![
                HashAlgorithm::Sha256,
                HashAlgorithm::Sha384,
                HashAlgorithm::Sha512,
                HashAlgorithm::Sha224,
                HashAlgorithm::Sha1,
            ])
            .preferred_compression_algorithms(smallvec![
                CompressionAlgorithm::ZLIB,
                CompressionAlgorithm::ZIP,
            ])
            .subkey(
                SubkeyParamsBuilder::default()
                    .version(version)
                    .key_type(KeyType::ECDH(ecdh.clone()))
                    .can_encrypt(true)
                    .passphrase(None)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();

        let key = key_params
            .generate_with_rng(&mut rng)
            .expect("failed to generate secret key");

        let signed_key = key
            .sign_with_rng(&mut rng, &"".into())
            .expect("failed to sign key");

        let armor = signed_key
            .to_armored_string(None.into())
            .expect("failed to serialize key");

        // std::fs::write(
        //     format!("sample-ecdsa-{ecdsa:?}-ecdh-{ecdh:?}.pub.asc"),
        //     &armor,
        // )
        // .unwrap();

        let (signed_key2, _headers) =
            SignedSecretKey::from_string(&armor).expect("failed to parse key");
        signed_key2.verify().expect("invalid key");

        assert_eq!(signed_key, signed_key2);

        let public_key = signed_key.public_key();

        let public_signed_key = public_key
            .sign(
                &mut rng,
                &*signed_key,
                &*signed_key.public_key(),
                &"".into(),
            )
            .expect("failed to sign public key");

        public_signed_key.verify().expect("invalid public key");

        let armor = public_signed_key
            .to_armored_string(None.into())
            .expect("failed to serialize public key");

        // std::fs::write(
        //     format!("sample-ecdsa-{ecdsa:?}-ecdh-{ecdh:?}.pub.asc"),
        //     &armor,
        // )
        // .unwrap();

        let (signed_key2, _headers) =
            SignedPublicKey::from_string(&armor).expect("failed to parse public key");
        signed_key2.verify().expect("invalid public key");
    }

    #[test]
    fn key_gen_ecdsa_p256_v4() {
        let mut rng = &mut ChaCha8Rng::seed_from_u64(0);

        for _ in 0..=175 {
            gen_ecdsa_ecdh(&mut rng, ECCCurve::P256, ECCCurve::P256, KeyVersion::V4);
        }
    }
    #[test]
    fn key_gen_ecdsa_p256_v6() {
        let mut rng = &mut ChaCha8Rng::seed_from_u64(0);

        for _ in 0..=175 {
            gen_ecdsa_ecdh(&mut rng, ECCCurve::P256, ECCCurve::P256, KeyVersion::V6);
        }
    }

    #[test]
    #[ignore]
    fn key_gen_ecdsa_p384_v4() {
        let mut rng = &mut ChaCha8Rng::seed_from_u64(0);
        for _ in 0..100 {
            gen_ecdsa_ecdh(&mut rng, ECCCurve::P384, ECCCurve::P384, KeyVersion::V4);
        }
    }

    #[test]
    #[ignore]
    fn key_gen_ecdsa_p384_v6() {
        let mut rng = &mut ChaCha8Rng::seed_from_u64(0);
        for _ in 0..100 {
            gen_ecdsa_ecdh(&mut rng, ECCCurve::P384, ECCCurve::P384, KeyVersion::V6);
        }
    }

    #[test]
    #[ignore]
    fn key_gen_ecdsa_p521_v4() {
        let mut rng = &mut ChaCha8Rng::seed_from_u64(0);

        for _ in 0..100 {
            gen_ecdsa_ecdh(&mut rng, ECCCurve::P521, ECCCurve::P521, KeyVersion::V4);
        }
    }
    #[test]
    #[ignore]
    fn key_gen_ecdsa_p521_v6() {
        let mut rng = &mut ChaCha8Rng::seed_from_u64(0);

        for _ in 0..100 {
            gen_ecdsa_ecdh(&mut rng, ECCCurve::P521, ECCCurve::P521, KeyVersion::V6);
        }
    }

    #[test]
    fn key_gen_ecdsa_secp256k1() {
        let mut rng = &mut ChaCha8Rng::seed_from_u64(0);

        for _ in 0..100 {
            gen_ecdsa_ecdh(
                &mut rng,
                ECCCurve::Secp256k1,
                ECCCurve::Curve25519, // we don't currently support ECDH over Secp256k1
                KeyVersion::V4,       // use of secp256k1 isn't specified in RFC 9580
            );
        }
    }

    fn gen_dsa<R: Rng + CryptoRng>(mut rng: R, key_size: DsaKeySize) {
        let _ = pretty_env_logger::try_init();

        let key_params = SecretKeyParamsBuilder::default()
            .key_type(KeyType::Dsa(key_size))
            .can_certify(true)
            .can_sign(true)
            .primary_user_id("Me-X <me-dsa@mail.com>".into())
            .passphrase(None)
            .preferred_symmetric_algorithms(smallvec![
                SymmetricKeyAlgorithm::AES256,
                SymmetricKeyAlgorithm::AES192,
                SymmetricKeyAlgorithm::AES128,
            ])
            .preferred_hash_algorithms(smallvec![
                HashAlgorithm::Sha256,
                HashAlgorithm::Sha384,
                HashAlgorithm::Sha512,
                HashAlgorithm::Sha224,
                HashAlgorithm::Sha1,
            ])
            .preferred_compression_algorithms(smallvec![
                CompressionAlgorithm::ZLIB,
                CompressionAlgorithm::ZIP,
            ])
            .subkey(
                SubkeyParamsBuilder::default()
                    .key_type(KeyType::ECDH(ECCCurve::Curve25519))
                    .can_encrypt(true)
                    .passphrase(None)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();

        let key = key_params
            .generate_with_rng(&mut rng)
            .expect("failed to generate secret key");

        let signed_key = key
            .sign_with_rng(&mut rng, &"".into())
            .expect("failed to sign key");

        let armor = signed_key
            .to_armored_string(None.into())
            .expect("failed to serialize key");

        // std::fs::write("sample-dsa.sec.asc", &armor).unwrap();

        let (signed_key2, _headers) =
            SignedSecretKey::from_string(&armor).expect("failed to parse key");
        signed_key2.verify().expect("invalid key");

        assert_eq!(signed_key, signed_key2);

        let public_key = signed_key.public_key();

        let public_signed_key = public_key
            .sign(
                &mut rng,
                &*signed_key,
                &*signed_key.public_key(),
                &"".into(),
            )
            .expect("failed to sign public key");

        public_signed_key.verify().expect("invalid public key");

        let armor = public_signed_key
            .to_armored_string(None.into())
            .expect("failed to serialize public key");

        // std::fs::write(format!("sample-dsa-{key_size:?}.pub.asc"), &armor).unwrap();

        let (signed_key2, _headers) =
            SignedPublicKey::from_string(&armor).expect("failed to parse public key");
        signed_key2.verify().expect("invalid public key");
    }

    // Test is slow in debug mode
    #[test]
    #[ignore]
    fn key_gen_dsa_1024() {
        let mut rng = &mut ChaCha8Rng::seed_from_u64(0);

        for _ in 0..5 {
            gen_dsa(&mut rng, DsaKeySize::B1024);
        }
    }

    // Test is slow in debug mode
    #[test]
    #[ignore]
    fn key_gen_dsa_2048() {
        let mut rng = &mut ChaCha8Rng::seed_from_u64(0);

        for _ in 0..5 {
            gen_dsa(&mut rng, DsaKeySize::B2048);
        }
    }
    // Test is slow in debug mode
    #[test]
    #[ignore]
    fn key_gen_dsa_3072() {
        let mut rng = &mut ChaCha8Rng::seed_from_u64(0);

        gen_dsa(&mut rng, DsaKeySize::B3072);
    }
}

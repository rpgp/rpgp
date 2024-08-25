use std::io;

use chrono::{DateTime, Utc};
use log::warn;
use rand::{CryptoRng, Rng};

use crate::composed::key::{PublicKey, PublicSubkey};
use crate::composed::signed_key::{SignedKeyDetails, SignedPublicSubKey};
use crate::crypto::hash::HashAlgorithm;
use crate::crypto::public_key::PublicKeyAlgorithm;
use crate::errors::Result;
use crate::packet::{self, write_packet, Packet, SignatureType};
use crate::ser::Serialize;
use crate::types::{
    EskType, Fingerprint, KeyId, KeyVersion, PublicKeyTrait, PublicParams, SecretKeyRepr,
    SecretKeyTrait, SignatureBytes, Tag,
};
use crate::{armor, ArmorOptions, EskBytes, SignedPublicKey};

/// Represents a secret signed PGP key.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SignedSecretKey {
    pub primary_key: packet::SecretKey,
    pub details: SignedKeyDetails,
    pub public_subkeys: Vec<SignedPublicSubKey>,
    pub secret_subkeys: Vec<SignedSecretSubKey>,
}

/// Parse a transferable keys from the given packets.
/// Ref: <https://tools.ietf.org/html/rfc4880.html#section-11.1>
pub struct SignedSecretKeyParser<
    I: Sized + Iterator<Item = crate::errors::Result<crate::packet::Packet>>,
> {
    inner: std::iter::Peekable<I>,
}

impl<I: Sized + Iterator<Item = crate::errors::Result<crate::packet::Packet>>>
    SignedSecretKeyParser<I>
{
    pub fn into_inner(self) -> std::iter::Peekable<I> {
        self.inner
    }

    pub fn from_packets(packets: std::iter::Peekable<I>) -> Self {
        SignedSecretKeyParser { inner: packets }
    }
}

impl<I: Sized + Iterator<Item = Result<Packet>>> Iterator for SignedSecretKeyParser<I> {
    type Item = Result<SignedSecretKey>;

    fn next(&mut self) -> Option<Self::Item> {
        match super::key_parser::next::<I, packet::SecretKey>(&mut self.inner, Tag::SecretKey, true)
        {
            Some(Err(err)) => Some(Err(err)),
            None => None,
            Some(Ok((primary_key, details, public_subkeys, secret_subkeys))) => Some(Ok(
                SignedSecretKey::new(primary_key, details, public_subkeys, secret_subkeys),
            )),
        }
    }
}

impl crate::composed::Deserializable for SignedSecretKey {
    /// Parse a transferable key from packets.
    /// Ref: <https://tools.ietf.org/html/rfc4880.html#section-11.1>
    fn from_packets<'a, I: Iterator<Item = Result<Packet>> + 'a>(
        packets: std::iter::Peekable<I>,
    ) -> Box<dyn Iterator<Item = Result<Self>> + 'a> {
        Box::new(SignedSecretKeyParser::from_packets(packets))
    }

    fn matches_block_type(typ: armor::BlockType) -> bool {
        matches!(typ, armor::BlockType::PrivateKey | armor::BlockType::File)
    }
}

impl SignedSecretKey {
    pub fn new(
        primary_key: packet::SecretKey,
        details: SignedKeyDetails,
        mut public_subkeys: Vec<SignedPublicSubKey>,
        mut secret_subkeys: Vec<SignedSecretSubKey>,
    ) -> Self {
        public_subkeys.retain(|key| {
            if key.signatures.is_empty() {
                warn!("ignoring unsigned {:?}", key.key);
                false
            } else {
                true
            }
        });

        secret_subkeys.retain(|key| {
            if key.signatures.is_empty() {
                warn!("ignoring unsigned {:?}", key.key);
                false
            } else {
                true
            }
        });

        SignedSecretKey {
            primary_key,
            details,
            public_subkeys,
            secret_subkeys,
        }
    }

    /// Get the secret key expiration as a date.
    pub fn expires_at(&self) -> Option<DateTime<Utc>> {
        let expiration = self.details.key_expiration_time()?;
        Some(*self.primary_key.created_at() + expiration)
    }

    fn verify_public_subkeys(&self) -> Result<()> {
        for subkey in &self.public_subkeys {
            subkey.verify(&self.primary_key)?;
        }

        Ok(())
    }

    fn verify_secret_subkeys(&self) -> Result<()> {
        for subkey in &self.secret_subkeys {
            subkey.verify(&self.primary_key)?;
        }

        Ok(())
    }

    pub fn verify(&self) -> Result<()> {
        self.details.verify(&self.primary_key)?;
        self.verify_public_subkeys()?;
        self.verify_secret_subkeys()?;

        Ok(())
    }

    pub fn to_armored_writer(
        &self,
        writer: &mut impl io::Write,
        opts: ArmorOptions<'_>,
    ) -> Result<()> {
        armor::write(
            self,
            armor::BlockType::PrivateKey,
            writer,
            opts.headers,
            opts.include_checksum,
        )
    }

    pub fn to_armored_bytes(&self, opts: ArmorOptions<'_>) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        self.to_armored_writer(&mut buf, opts)?;

        Ok(buf)
    }

    pub fn to_armored_string(&self, opts: ArmorOptions<'_>) -> Result<String> {
        let res = String::from_utf8(self.to_armored_bytes(opts)?).map_err(|e| e.utf8_error())?;
        Ok(res)
    }
}

impl Serialize for SignedSecretKey {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        write_packet(writer, &self.primary_key)?;
        self.details.to_writer(writer)?;
        for ps in &self.public_subkeys {
            ps.to_writer(writer)?;
        }

        for ps in &self.secret_subkeys {
            ps.to_writer(writer)?;
        }

        Ok(())
    }
}

impl SecretKeyTrait for SignedSecretKey {
    type PublicKey = PublicKey;
    type Unlocked = SecretKeyRepr;

    fn unlock<F, G, T>(&self, pw: F, work: G) -> Result<T>
    where
        F: FnOnce() -> String,
        G: FnOnce(&Self::Unlocked) -> Result<T>,
    {
        self.primary_key.unlock(pw, work)
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
        self.primary_key.create_signature(key_pw, hash, data)
    }

    fn public_key(&self) -> Self::PublicKey {
        let mut subkeys: Vec<PublicSubkey> = self
            .public_subkeys
            .iter()
            .map(SignedPublicSubKey::as_unsigned)
            .collect();
        let sec_subkeys = self.secret_subkeys.iter().map(SecretKeyTrait::public_key);

        subkeys.extend(sec_subkeys);

        PublicKey::new(
            self.primary_key.public_key(),
            self.details.as_unsigned(),
            subkeys,
        )
    }
}

impl PublicKeyTrait for SignedSecretKey {
    fn verify_signature(
        &self,
        hash: HashAlgorithm,
        data: &[u8],
        sig: &SignatureBytes,
    ) -> Result<()> {
        self.primary_key.verify_signature(hash, data, sig)
    }

    fn encrypt<R: Rng + CryptoRng>(&self, rng: R, plain: &[u8], typ: EskType) -> Result<EskBytes> {
        self.primary_key.encrypt(rng, plain, typ)
    }

    fn serialize_for_hashing(&self, writer: &mut impl io::Write) -> Result<()> {
        self.primary_key.serialize_for_hashing(writer)
    }

    fn public_params(&self) -> &PublicParams {
        self.primary_key.public_params()
    }

    fn version(&self) -> KeyVersion {
        self.primary_key.version()
    }

    /// Returns the fingerprint of the associated primary key.
    fn fingerprint(&self) -> Fingerprint {
        self.primary_key.fingerprint()
    }

    /// Returns the Key ID of the associated primary key.
    fn key_id(&self) -> KeyId {
        self.primary_key.key_id()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.primary_key.algorithm()
    }

    fn created_at(&self) -> &chrono::DateTime<chrono::Utc> {
        self.primary_key.created_at()
    }

    fn expiration(&self) -> Option<u16> {
        self.primary_key.expiration()
    }
}

/// Represents a composed secret PGP SubKey.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SignedSecretSubKey {
    pub key: packet::SecretSubkey,
    pub signatures: Vec<packet::Signature>,
}

impl SignedSecretSubKey {
    pub fn new(key: packet::SecretSubkey, mut signatures: Vec<packet::Signature>) -> Self {
        signatures.retain(|sig| {
            if sig.typ() != SignatureType::SubkeyBinding
                && sig.typ() != SignatureType::SubkeyRevocation
            {
                warn!(
                    "ignoring unexpected signature {:?} after Subkey packet",
                    sig.typ()
                );
                false
            } else {
                true
            }
        });

        SignedSecretSubKey { key, signatures }
    }

    pub fn verify(&self, key: &impl PublicKeyTrait) -> Result<()> {
        ensure!(!self.signatures.is_empty(), "missing subkey bindings");

        for sig in &self.signatures {
            sig.verify_key_binding(key, &self.key)?;
        }

        Ok(())
    }
}

impl Serialize for SignedSecretSubKey {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        write_packet(writer, &self.key)?;
        for sig in &self.signatures {
            write_packet(writer, sig)?;
        }

        Ok(())
    }
}

impl SecretKeyTrait for SignedSecretSubKey {
    type PublicKey = PublicSubkey;
    type Unlocked = SecretKeyRepr;

    fn unlock<F, G, T>(&self, pw: F, work: G) -> Result<T>
    where
        F: FnOnce() -> String,
        G: FnOnce(&Self::Unlocked) -> Result<T>,
    {
        self.key.unlock(pw, work)
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
        self.key.create_signature(key_pw, hash, data)
    }

    fn public_key(&self) -> Self::PublicKey {
        let keyflags = self
            .signatures
            .first()
            .expect("invalid signed subkey")
            .key_flags();

        PublicSubkey::new(self.key.public_key(), keyflags)
    }
}

impl PublicKeyTrait for SignedSecretSubKey {
    fn verify_signature(
        &self,
        hash: HashAlgorithm,
        data: &[u8],
        sig: &SignatureBytes,
    ) -> Result<()> {
        self.key.verify_signature(hash, data, sig)
    }

    fn encrypt<R: Rng + CryptoRng>(&self, rng: R, plain: &[u8], typ: EskType) -> Result<EskBytes> {
        self.key.encrypt(rng, plain, typ)
    }

    fn serialize_for_hashing(&self, writer: &mut impl io::Write) -> Result<()> {
        self.key.serialize_for_hashing(writer)
    }

    fn public_params(&self) -> &PublicParams {
        self.key.public_params()
    }

    fn version(&self) -> KeyVersion {
        self.key.version()
    }

    fn fingerprint(&self) -> Fingerprint {
        self.key.fingerprint()
    }

    fn key_id(&self) -> KeyId {
        self.key.key_id()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.key.algorithm()
    }

    fn created_at(&self) -> &chrono::DateTime<chrono::Utc> {
        self.key.created_at()
    }

    fn expiration(&self) -> Option<u16> {
        self.key.expiration()
    }
}

impl From<SignedSecretKey> for SignedPublicKey {
    fn from(value: SignedSecretKey) -> Self {
        let primary = value.primary_key.public_key();
        let details = value.details;

        let mut subkeys = value.public_subkeys;

        value
            .secret_subkeys
            .into_iter()
            .for_each(|key| subkeys.push(key.into()));

        SignedPublicKey::new(primary, details, subkeys)
    }
}

impl From<SignedSecretSubKey> for SignedPublicSubKey {
    fn from(value: SignedSecretSubKey) -> Self {
        SignedPublicSubKey::new(value.key.public_key(), value.signatures)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use packet::LiteralData;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    use super::*;
    use crate::types::S2kParams;
    use crate::{composed::shared::Deserializable, Message};

    #[test]
    fn test_v6_annex_a_4() -> Result<()> {
        let _ = pretty_env_logger::try_init();

        // A.4. Sample v6 Secret Key (Transferable Secret Key)

        let tsk = "-----BEGIN PGP PRIVATE KEY BLOCK-----

xUsGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laMAGXKB
exK+cH6NX1hs5hNhIB00TrJmosgv3mg1ditlsLfCsQYfGwoAAABCBYJjh3/jAwsJ
BwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6
2azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lwgyU2kCcUmKfvBXbAf6rh
RYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaEQsiPlR4zxP/TP7mhfVEe
7XWPxtnMUMtf15OyA51YBMdLBmOHf+MZAAAAIIaTJINn+eUBXbki+PSAld2nhJh/
LVmFsS+60WyvXkQ1AE1gCk95TUR3XFeibg/u/tVY6a//1q0NWC1X+yui3O24wpsG
GBsKAAAALAWCY4d/4wKbDCIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6
2azJAAAAAAQBIKbpGG2dWTX8j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDE
M0g12vYxoWM8Y81W+bHBw805I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUr
k0mXubZvyl4GBg==
-----END PGP PRIVATE KEY BLOCK-----";

        let (ssk, _) = SignedSecretKey::from_armor_single(io::Cursor::new(tsk))?;

        eprintln!("ssk: {:#02x?}", ssk);

        ssk.verify()?;

        let lit = LiteralData::from_bytes("".into(), "Hello world".as_bytes());
        let msg = Message::Literal(lit);

        let pri = ssk.primary_key;

        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let signed = msg.sign(&mut rng, &pri, String::default, HashAlgorithm::SHA2_256)?;

        signed.verify(&pri)?;

        let mut sink = vec![];
        signed
            .to_armored_writer(&mut sink, ArmorOptions::default())
            .expect("FIXME");

        eprintln!("{}", String::from_utf8_lossy(&sink));

        Ok(())
    }

    // A.5. Sample locked v6 Secret Key (Transferable Secret Key)
    const ANNEX_A_5: &str = "-----BEGIN PGP PRIVATE KEY BLOCK-----

xYIGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laP9JgkC
FARdb9ccngltHraRe25uHuyuAQQVtKipJ0+r5jL4dacGWSAheCWPpITYiyfyIOPS
3gIDyg8f7strd1OB4+LZsUhcIjOMpVHgmiY/IutJkulneoBYwrEGHxsKAAAAQgWC
Y4d/4wMLCQcFFQoOCAwCFgACmwMCHgkiIQbLGGxPBgmml+TVLfpscisMHx4nwYpW
cI9lJewnutmsyQUnCQIHAgAAAACtKCAQPi19In7A5tfORHHbNr/JcIMlNpAnFJin
7wV2wH+q4UWFs7kDsBJ+xP2i8CMEWi7Ha8tPlXGpZR4UruETeh1mhELIj5UeM8T/
0z+5oX1RHu11j8bZzFDLX9eTsgOdWATHggZjh3/jGQAAACCGkySDZ/nlAV25Ivj0
gJXdp4SYfy1ZhbEvutFsr15ENf0mCQIUBA5hhGgp2oaavg6mFUXcFMwBBBUuE8qf
9Ock+xwusd+GAglBr5LVyr/lup3xxQvHXFSjjA2haXfoN6xUGRdDEHI6+uevKjVR
v5oAxgu7eJpaXNjCmwYYGwoAAAAsBYJjh3/jApsMIiEGyxhsTwYJppfk1S36bHIr
DB8eJ8GKVnCPZSXsJ7rZrMkAAAAABAEgpukYbZ1ZNfyP5WMUzbUnSGpaUSD5t2Ki
Nacp8DkBClZRa2c3AMQzSDXa9jGhYzxjzVb5scHDzTkjyRZWRdTq8U6L4da+/+Kt
ruh8m7Xo2ehSSFyWRSuTSZe5tm/KXgYG
-----END PGP PRIVATE KEY BLOCK-----";

    const ANNEX_A_5_PASSPHRASE: &str = "correct horse battery staple";

    #[test]
    #[ignore] // slow in debug mode (argon2)
    fn test_v6_annex_a_5() -> Result<()> {
        let _ = pretty_env_logger::try_init();

        let (ssk, _) = SignedSecretKey::from_armor_single(io::Cursor::new(ANNEX_A_5))?;
        ssk.verify()?;

        let lit = LiteralData::from_bytes("".into(), "Hello world".as_bytes());

        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let msg = Message::Literal(lit).sign(
            &mut rng,
            &ssk.primary_key,
            || ANNEX_A_5_PASSPHRASE.to_string(),
            HashAlgorithm::SHA2_256,
        )?;

        msg.verify(&ssk.primary_key)?;

        Ok(())
    }

    #[test]
    #[ignore] // slow in debug mode
    fn secret_key_protection_v6() -> Result<()> {
        let _ = pretty_env_logger::try_init();

        let lit = LiteralData::from_bytes("".into(), "Hello world".as_bytes());
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        let (ssk, _) = SignedSecretKey::from_armor_single(io::Cursor::new(ANNEX_A_5))?;
        ssk.verify()?;

        // we will test unlock/lock on the primary key
        let mut pri = ssk.primary_key;

        // remove passphrase
        pri.remove_password(|| ANNEX_A_5_PASSPHRASE.to_string())?;

        // try signing without pw
        let msg = Message::Literal(lit.clone()).sign(
            &mut rng,
            &pri,
            String::default,
            HashAlgorithm::SHA2_256,
        )?;
        msg.verify(&pri)?;

        // set passphrase with default s2k
        pri.set_password(&mut rng, || ANNEX_A_5_PASSPHRASE.to_string())?;

        // try signing with pw
        let msg = Message::Literal(lit.clone()).sign(
            &mut rng,
            &pri,
            || ANNEX_A_5_PASSPHRASE.to_string(),
            HashAlgorithm::SHA2_256,
        )?;
        msg.verify(&pri)?;

        // remove passphrase
        pri.remove_password(|| ANNEX_A_5_PASSPHRASE.to_string())?;

        // set passphrase with Cfb s2k (default for KeyVersion::V4)
        pri.set_password_with_s2k(
            || ANNEX_A_5_PASSPHRASE.to_string(),
            S2kParams::new_default(&mut rng, KeyVersion::V4),
        )?;

        // try signing with pw
        let msg = Message::Literal(lit).sign(
            &mut rng,
            &pri,
            || ANNEX_A_5_PASSPHRASE.to_string(),
            HashAlgorithm::SHA2_256,
        )?;
        msg.verify(&pri)?;

        Ok(())
    }
}

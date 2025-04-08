use std::{io, ops::Deref};

use chrono::{DateTime, Utc};
use log::{debug, warn};
use rand::{CryptoRng, Rng};

use crate::{
    armor,
    composed::{
        key::{PublicKey, PublicSubkey},
        signed_key::{SignedKeyDetails, SignedPublicSubKey},
        ArmorOptions, PlainSessionKey, SignedPublicKey,
    },
    errors::{ensure, Result},
    packet::{self, Packet, PacketTrait, SignatureType},
    ser::Serialize,
    types::{EskType, Password, PkeskBytes, PublicKeyTrait, Tag},
};

/// Represents a secret signed PGP key.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SignedSecretKey {
    pub primary_key: packet::SecretKey,
    pub details: SignedKeyDetails,
    pub public_subkeys: Vec<SignedPublicSubKey>,
    pub secret_subkeys: Vec<SignedSecretSubKey>,
}

/// Parse OpenPGP secret keys ("Transferable Secret Keys") from the given packets.
/// Ref: <https://www.rfc-editor.org/rfc/rfc9580.html#name-transferable-secret-keys>
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
        match super::key_parser::next::<_, packet::SecretKey>(&mut self.inner, Tag::SecretKey, true)
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
    /// Ref: <https://www.rfc-editor.org/rfc/rfc9580.html#name-transferable-secret-keys>
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
        Some(*self.primary_key.public_key().created_at() + expiration)
    }

    fn verify_public_subkeys(&self) -> Result<()> {
        for subkey in &self.public_subkeys {
            subkey.verify(self.primary_key.public_key())?;
        }

        Ok(())
    }

    fn verify_secret_subkeys(&self) -> Result<()> {
        for subkey in &self.secret_subkeys {
            subkey.verify(self.primary_key.public_key())?;
        }

        Ok(())
    }

    pub fn verify(&self) -> Result<()> {
        self.details.verify(self.primary_key.public_key())?;
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

    pub fn encrypt<R: Rng + CryptoRng>(
        &self,
        rng: R,
        plain: &[u8],
        typ: EskType,
    ) -> Result<PkeskBytes> {
        self.primary_key.encrypt(rng, plain, typ)
    }

    pub fn public_key(&self) -> PublicKey {
        let mut subkeys: Vec<PublicSubkey> = self
            .public_subkeys
            .iter()
            .map(SignedPublicSubKey::as_unsigned)
            .collect();
        let sec_subkeys = self.secret_subkeys.iter().map(|k| k.public_key());
        subkeys.extend(sec_subkeys);

        PublicKey::new(
            self.primary_key.public_key().clone(),
            self.details.as_unsigned(),
            subkeys,
        )
    }

    /// Decrypts session key using this key.
    pub fn decrypt_session_key(
        &self,
        key_pw: &Password,
        values: &PkeskBytes,
        typ: EskType,
    ) -> Result<Result<PlainSessionKey>> {
        debug!("decrypt session key");

        self.unlock(key_pw, |pub_params, priv_key| {
            priv_key.decrypt(pub_params, values, typ, self.primary_key.public_key())
        })
    }
}

impl Serialize for SignedSecretKey {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        self.primary_key.to_writer_with_header(writer)?;
        self.details.to_writer(writer)?;
        for ps in &self.public_subkeys {
            ps.to_writer(writer)?;
        }

        for ps in &self.secret_subkeys {
            ps.to_writer(writer)?;
        }

        Ok(())
    }

    fn write_len(&self) -> usize {
        let mut sum = self.primary_key.write_len_with_header();
        sum += self.details.write_len();
        sum += self.public_subkeys.write_len();
        sum += self.secret_subkeys.write_len();
        sum
    }
}

impl Deref for SignedSecretKey {
    type Target = packet::SecretKey;

    fn deref(&self) -> &Self::Target {
        &self.primary_key
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
            if sig.typ() != Some(SignatureType::SubkeyBinding)
                && sig.typ() != Some(SignatureType::SubkeyRevocation)
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

    pub fn verify<P>(&self, key: &P) -> Result<()>
    where
        P: PublicKeyTrait + Serialize,
    {
        ensure!(!self.signatures.is_empty(), "missing subkey bindings");

        for sig in &self.signatures {
            sig.verify_key_binding(key, self.key.public_key())?;
        }

        Ok(())
    }

    pub fn encrypt<R: Rng + CryptoRng>(
        &self,
        rng: R,
        plain: &[u8],
        typ: EskType,
    ) -> Result<PkeskBytes> {
        self.key.encrypt(rng, plain, typ)
    }

    pub fn public_key(&self) -> PublicSubkey {
        let keyflags = self
            .signatures
            .first()
            .expect("invalid signed subkey")
            .key_flags();

        PublicSubkey::new(self.key.public_key().clone(), keyflags)
    }

    /// Decrypts session key using this key.
    pub fn decrypt_session_key(
        &self,
        key_pw: &Password,
        values: &PkeskBytes,
        typ: EskType,
    ) -> Result<Result<PlainSessionKey>> {
        debug!("decrypt session key");

        self.unlock(key_pw, |pub_params, priv_key| {
            priv_key.decrypt(pub_params, values, typ, self.key.public_key())
        })
    }
}

impl Deref for SignedSecretSubKey {
    type Target = packet::SecretSubkey;

    fn deref(&self) -> &Self::Target {
        &self.key
    }
}

impl Serialize for SignedSecretSubKey {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        self.key.to_writer_with_header(writer)?;
        for sig in &self.signatures {
            sig.to_writer_with_header(writer)?;
        }

        Ok(())
    }

    fn write_len(&self) -> usize {
        let mut sum = self.key.write_len_with_header();
        for sig in &self.signatures {
            sum += sig.write_len_with_header()
        }
        sum
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

        SignedPublicKey::new(primary.clone(), details, subkeys)
    }
}

impl From<SignedSecretSubKey> for SignedPublicSubKey {
    fn from(value: SignedSecretSubKey) -> Self {
        SignedPublicSubKey::new(value.key.public_key().clone(), value.signatures)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    use super::*;
    use crate::{
        composed::{shared::Deserializable, Message, MessageBuilder},
        crypto::hash::HashAlgorithm,
        types::{KeyVersion, Password, S2kParams},
    };

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

        // eprintln!("ssk: {:#02x?}", ssk);

        ssk.verify()?;

        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let pri = &ssk.primary_key;

        let signed = crate::composed::MessageBuilder::from_bytes("", &b"Hello world"[..])
            .sign(pri, Password::empty(), HashAlgorithm::Sha256)
            .to_armored_string(&mut rng, ArmorOptions::default())?;

        eprintln!("{}", signed);

        let (mut message, _) = Message::from_armor(signed.as_bytes())?;
        message.verify_read(&pri.public_key())?;

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

        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let msg = MessageBuilder::from_bytes("", &b"Hello world"[..])
            .sign(
                &ssk.primary_key,
                ANNEX_A_5_PASSPHRASE.into(),
                HashAlgorithm::Sha256,
            )
            .to_vec(&mut rng)?;
        let mut msg = Message::from_bytes(&msg[..])?;
        msg.verify_read(&ssk.primary_key.public_key())?;
        Ok(())
    }

    #[test]
    #[ignore] // slow in debug mode
    fn secret_key_protection_v6() -> Result<()> {
        let _ = pretty_env_logger::try_init();

        let file_name = "";
        let text = b"Hello world";
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        let (ssk, _) = SignedSecretKey::from_armor_single(io::Cursor::new(ANNEX_A_5))?;
        ssk.verify()?;

        // we will test unlock/lock on the primary key
        let mut pri = ssk.primary_key;

        // remove passphrase
        pri.remove_password(&ANNEX_A_5_PASSPHRASE.into())?;

        // try signing without pw
        let msg = MessageBuilder::from_bytes(file_name, &text[..])
            .sign(&pri, Password::empty(), HashAlgorithm::Sha256)
            .to_vec(&mut rng)?;

        let mut msg = Message::from_bytes(&msg[..])?;
        msg.verify_read(pri.public_key())?;

        // set passphrase with default s2k
        pri.set_password(&mut rng, &ANNEX_A_5_PASSPHRASE.into())?;

        // try signing with pw
        let msg = MessageBuilder::from_bytes(file_name, &text[..])
            .sign(&pri, ANNEX_A_5_PASSPHRASE.into(), HashAlgorithm::Sha256)
            .to_vec(&mut rng)?;

        let mut msg = Message::from_bytes(&msg[..])?;
        msg.verify_read(pri.public_key())?;

        // remove passphrase
        pri.remove_password(&ANNEX_A_5_PASSPHRASE.into())?;

        // set passphrase with Cfb s2k (default for KeyVersion::V4)
        pri.set_password_with_s2k(
            &ANNEX_A_5_PASSPHRASE.into(),
            S2kParams::new_default(&mut rng, KeyVersion::V4),
        )?;

        // try signing with pw
        let msg = MessageBuilder::from_bytes(file_name, &text[..])
            .sign(&pri, ANNEX_A_5_PASSPHRASE.into(), HashAlgorithm::Sha256)
            .to_vec(&mut rng)?;

        let mut msg = Message::from_bytes(&msg[..])?;
        msg.verify_read(pri.public_key())?;
        Ok(())
    }
}

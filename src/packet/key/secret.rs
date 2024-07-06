use zeroize::Zeroize;

use crate::{
    crypto::{hash::HashAlgorithm, public_key::PublicKeyAlgorithm},
    errors::Result,
    packet::{
        PacketTrait, Signature, SignatureConfigBuilder, SignatureType, Subpacket, SubpacketData,
    },
    types::{
        KeyId, KeyTrait, KeyVersion, Mpi, PublicKeyTrait, PublicParams, SecretKeyRepr,
        SecretKeyTrait, SecretParams, Tag, Version,
    },
};

use super::{PublicKey, PublicSubkey};

#[derive(Debug, PartialEq, Eq, Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct SecretKey(SecretKeyInner<PublicKey>);

#[derive(Debug, PartialEq, Eq, Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct SecretSubkey(SecretKeyInner<PublicSubkey>);

#[derive(Debug, PartialEq, Eq, Clone)]
struct SecretKeyInner<D> {
    details: D,
    secret_params: SecretParams,
}

impl<D> zeroize::Zeroize for SecretKeyInner<D> {
    fn zeroize(&mut self) {
        // details are not zeroed as they are public knowledge.
        self.secret_params.zeroize();
    }
}

impl<D> Drop for SecretKeyInner<D> {
    fn drop(&mut self) {
        self.zeroize()
    }
}

impl SecretKey {
    pub fn new(details: PublicKey, secret_params: SecretParams) -> Self {
        Self(SecretKeyInner {
            details,
            secret_params,
        })
    }

    /// Parses a `SecretKey` packet from the given slice.
    pub fn from_slice(packet_version: Version, input: &[u8]) -> Result<Self> {
        let (_, details) = crate::packet::secret_key_parser::parse(input)?;
        let (version, algorithm, created_at, expiration, public_params, secret_params) = details;
        Ok(Self(SecretKeyInner {
            details: PublicKey::new(
                packet_version,
                version,
                algorithm,
                created_at,
                expiration,
                public_params,
            )?,
            secret_params,
        }))
    }

    pub fn created_at(&self) -> &chrono::DateTime<chrono::Utc> {
        self.0.details.created_at()
    }

    pub fn expiration(&self) -> Option<u16> {
        self.0.details.expiration()
    }

    pub fn secret_params(&self) -> &SecretParams {
        self.0.secret_params()
    }

    /// Checks if we should expect a SHA1 checksum in the encrypted part.
    pub fn has_sha1_checksum(&self) -> bool {
        self.0.has_sha1_checksum()
    }

    pub fn sign<F>(&self, key: &impl SecretKeyTrait, key_pw: F) -> Result<Signature>
    where
        F: FnOnce() -> String,
    {
        self.0.sign(key, key_pw, SignatureType::KeyBinding)
    }
}

impl SecretSubkey {
    pub fn new(details: PublicSubkey, secret_params: SecretParams) -> Self {
        Self(SecretKeyInner {
            details,
            secret_params,
        })
    }

    /// Parses a `SecretKey` packet from the given slice.
    pub fn from_slice(packet_version: Version, input: &[u8]) -> Result<Self> {
        let (_, details) = crate::packet::secret_key_parser::parse(input)?;
        let (version, algorithm, created_at, expiration, public_params, secret_params) = details;
        Ok(Self(SecretKeyInner {
            details: PublicSubkey::new(
                packet_version,
                version,
                algorithm,
                created_at,
                expiration,
                public_params,
            )?,
            secret_params,
        }))
    }

    pub fn created_at(&self) -> &chrono::DateTime<chrono::Utc> {
        self.0.details.created_at()
    }

    pub fn expiration(&self) -> Option<u16> {
        self.0.details.expiration()
    }

    pub fn secret_params(&self) -> &SecretParams {
        self.0.secret_params()
    }

    /// Checks if we should expect a SHA1 checksum in the encrypted part.
    pub fn has_sha1_checksum(&self) -> bool {
        self.0.has_sha1_checksum()
    }

    pub fn sign<F>(&self, key: &impl SecretKeyTrait, key_pw: F) -> Result<Signature>
    where
        F: FnOnce() -> String,
    {
        self.0.sign(key, key_pw, SignatureType::SubkeyBinding)
    }
}

impl<D: PublicKeyTrait + crate::ser::Serialize> SecretKeyInner<D> {
    fn secret_params(&self) -> &SecretParams {
        &self.secret_params
    }

    fn has_sha1_checksum(&self) -> bool {
        self.secret_params.string_to_key_id() == 254
    }

    fn sign<F>(
        &self,
        key: &impl SecretKeyTrait,
        key_pw: F,
        sig_typ: SignatureType,
    ) -> Result<Signature>
    where
        F: FnOnce() -> String,
    {
        use chrono::SubsecRound;
        let mut config = SignatureConfigBuilder::default();
        config
            .typ(sig_typ)
            .pub_alg(key.algorithm())
            .hash_alg(key.hash_alg())
            .hashed_subpackets(vec![Subpacket::regular(
                SubpacketData::SignatureCreationTime(chrono::Utc::now().trunc_subsecs(0)),
            )])
            .unhashed_subpackets(vec![Subpacket::regular(SubpacketData::Issuer(
                key.key_id(),
            ))])
            .build()?
            .sign_key(key, key_pw, &self)
    }
}

impl<D: PublicKeyTrait + Clone + crate::ser::Serialize> SecretKeyTrait for SecretKeyInner<D> {
    type PublicKey = D;
    type Unlocked = SecretKeyRepr;

    fn unlock<F, G, T>(&self, pw: F, work: G) -> Result<T>
    where
        F: FnOnce() -> String,
        G: FnOnce(&Self::Unlocked) -> Result<T>,
    {
        let decrypted = match self.secret_params {
            SecretParams::Plain(ref k) => k.as_ref().as_repr(self.public_params()),
            SecretParams::Encrypted(ref k) => {
                let plain = k.unlock(pw, self.details.algorithm(), self.public_params())?;
                plain.as_ref().as_repr(self.public_params())
            }
        }?;

        work(&decrypted)
    }

    fn create_signature<F>(&self, key_pw: F, hash: HashAlgorithm, data: &[u8]) -> Result<Vec<Mpi>>
    where
        F: FnOnce() -> String,
    {
        use crate::crypto::Signer;

        let mut signature: Option<Vec<Mpi>> = None;
        self.unlock(key_pw, |priv_key| {
            debug!("unlocked key");
            let sig = match *priv_key {
                SecretKeyRepr::RSA(ref priv_key) => priv_key.sign(hash, data, self.public_params()),
                SecretKeyRepr::ECDSA(ref priv_key) => {
                    priv_key.sign(hash, data, self.public_params())
                }
                SecretKeyRepr::DSA(ref priv_key) => priv_key.sign(hash, data, self.public_params()),
                SecretKeyRepr::ECDH(_) => {
                    bail!("ECDH can not be used to for signing operations")
                }
                SecretKeyRepr::EdDSA(ref priv_key) => {
                    priv_key.sign(hash, data, self.public_params())
                }
            }?;

            // strip leading zeros, to match parse results from MPIs
            signature = Some(
                sig.iter()
                    .map(|v| Mpi::from_raw_slice(&v[..]))
                    .collect::<Vec<_>>(),
            );
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
    type Unlocked = SecretKeyRepr;

    fn unlock<F, G, T>(&self, pw: F, work: G) -> Result<T>
    where
        F: FnOnce() -> String,
        G: FnOnce(&Self::Unlocked) -> Result<T>,
    {
        SecretKeyTrait::unlock(&self.0, pw, work)
    }

    fn create_signature<F>(&self, key_pw: F, hash: HashAlgorithm, data: &[u8]) -> Result<Vec<Mpi>>
    where
        F: FnOnce() -> String,
    {
        SecretKeyTrait::create_signature(&self.0, key_pw, hash, data)
    }

    fn public_key(&self) -> PublicKey {
        SecretKeyTrait::public_key(&self.0)
    }
}

impl SecretKeyTrait for SecretSubkey {
    type PublicKey = PublicSubkey;
    type Unlocked = SecretKeyRepr;

    fn unlock<F, G, T>(&self, pw: F, work: G) -> Result<T>
    where
        F: FnOnce() -> String,
        G: FnOnce(&Self::Unlocked) -> Result<T>,
    {
        SecretKeyTrait::unlock(&self.0, pw, work)
    }

    fn create_signature<F>(&self, key_pw: F, hash: HashAlgorithm, data: &[u8]) -> Result<Vec<Mpi>>
    where
        F: FnOnce() -> String,
    {
        SecretKeyTrait::create_signature(&self.0, key_pw, hash, data)
    }

    fn public_key(&self) -> PublicSubkey {
        SecretKeyTrait::public_key(&self.0)
    }
}

impl<D: PublicKeyTrait + crate::ser::Serialize> crate::ser::Serialize for SecretKeyInner<D> {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        // writes version and public part
        crate::ser::Serialize::to_writer(&self.details, writer)?;
        self.secret_params.to_writer(writer)?;
        Ok(())
    }
}

impl crate::ser::Serialize for SecretKey {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        crate::ser::Serialize::to_writer(&self.0, writer)
    }
}

impl crate::ser::Serialize for SecretSubkey {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        crate::ser::Serialize::to_writer(&self.0, writer)
    }
}

impl PacketTrait for SecretKey {
    fn packet_version(&self) -> Version {
        self.0.details.packet_version()
    }

    fn tag(&self) -> Tag {
        Tag::SecretKey
    }
}

impl PacketTrait for SecretSubkey {
    fn packet_version(&self) -> Version {
        self.0.details.packet_version()
    }

    fn tag(&self) -> Tag {
        Tag::SecretSubkey
    }
}

impl<D: PublicKeyTrait> KeyTrait for SecretKeyInner<D> {
    fn version(&self) -> KeyVersion {
        self.details.version()
    }

    fn fingerprint(&self) -> Vec<u8> {
        self.details.fingerprint()
    }

    fn key_id(&self) -> KeyId {
        self.details.key_id()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.details.algorithm()
    }
}

impl KeyTrait for SecretKey {
    fn version(&self) -> KeyVersion {
        KeyTrait::version(&self.0)
    }

    fn fingerprint(&self) -> Vec<u8> {
        KeyTrait::fingerprint(&self.0)
    }

    fn key_id(&self) -> KeyId {
        KeyTrait::key_id(&self.0)
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        KeyTrait::algorithm(&self.0)
    }
}

impl KeyTrait for SecretSubkey {
    fn version(&self) -> KeyVersion {
        KeyTrait::version(&self.0)
    }

    fn fingerprint(&self) -> Vec<u8> {
        KeyTrait::fingerprint(&self.0)
    }

    fn key_id(&self) -> KeyId {
        KeyTrait::key_id(&self.0)
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        KeyTrait::algorithm(&self.0)
    }
}

impl PublicKeyTrait for SecretKey {
    fn verify_signature(&self, hash: HashAlgorithm, hashed: &[u8], sig: &[Mpi]) -> Result<()> {
        PublicKeyTrait::verify_signature(&self.0, hash, hashed, sig)
    }

    fn encrypt<R: rand::Rng + rand::CryptoRng>(
        &self,
        rng: &mut R,
        plain: &[u8],
    ) -> Result<Vec<Mpi>> {
        PublicKeyTrait::encrypt(&self.0, rng, plain)
    }

    fn to_writer_old(&self, writer: &mut impl std::io::Write) -> Result<()> {
        PublicKeyTrait::to_writer_old(&self.0, writer)
    }

    fn public_params(&self) -> &PublicParams {
        PublicKeyTrait::public_params(&self.0)
    }
}

impl PublicKeyTrait for SecretSubkey {
    fn verify_signature(&self, hash: HashAlgorithm, hashed: &[u8], sig: &[Mpi]) -> Result<()> {
        PublicKeyTrait::verify_signature(&self.0, hash, hashed, sig)
    }

    fn encrypt<R: rand::Rng + rand::CryptoRng>(
        &self,
        rng: &mut R,
        plain: &[u8],
    ) -> Result<Vec<Mpi>> {
        PublicKeyTrait::encrypt(&self.0, rng, plain)
    }

    fn to_writer_old(&self, writer: &mut impl std::io::Write) -> Result<()> {
        PublicKeyTrait::to_writer_old(&self.0, writer)
    }

    fn public_params(&self) -> &PublicParams {
        PublicKeyTrait::public_params(&self.0)
    }
}

impl<D: PublicKeyTrait + crate::ser::Serialize> PublicKeyTrait for SecretKeyInner<D> {
    fn verify_signature(&self, hash: HashAlgorithm, hashed: &[u8], sig: &[Mpi]) -> Result<()> {
        self.details.verify_signature(hash, hashed, sig)
    }

    fn encrypt<R: rand::Rng + rand::CryptoRng>(
        &self,
        rng: &mut R,
        plain: &[u8],
    ) -> Result<Vec<Mpi>> {
        self.details.encrypt(rng, plain)
    }

    fn to_writer_old(&self, writer: &mut impl std::io::Write) -> Result<()> {
        let mut key_buf = Vec::new();
        self.details.to_writer(&mut key_buf)?;

        // old style packet header for the key
        writer.write_all(&[0x99, (key_buf.len() >> 8) as u8, key_buf.len() as u8])?;
        writer.write_all(&key_buf)?;

        Ok(())
    }
    fn public_params(&self) -> &PublicParams {
        self.details.public_params()
    }
}

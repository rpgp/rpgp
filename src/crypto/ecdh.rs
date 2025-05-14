use cipher::array::Array;
use elliptic_curve::Generate;
use log::debug;
use rand::{CryptoRng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use super::hash::HashAlgorithm;
use crate::{
    crypto::{
        aes_kw, ecc_curve::ECCCurve, public_key::PublicKeyAlgorithm, sym::SymmetricKeyAlgorithm,
        Decryptor,
    },
    errors::{ensure, ensure_eq, unsupported_err, Error, Result},
    ser::Serialize,
    types::{ecdh::EcdhKdfType, pad_key, EcdhPublicParams, Mpi, PkeskBytes},
};

/// 20 octets representing "Anonymous Sender    ".
const ANON_SENDER: [u8; 20] = [
    0x41, 0x6E, 0x6F, 0x6E, 0x79, 0x6D, 0x6F, 0x75, 0x73, 0x20, 0x53, 0x65, 0x6E, 0x64, 0x65, 0x72,
    0x20, 0x20, 0x20, 0x20,
];

/// ECDH Curve25519 secret key
#[derive(Clone, ZeroizeOnDrop, derive_more::Debug)]
pub struct Curve25519(#[debug("..")] StaticSecret);

impl From<StaticSecret> for Curve25519 {
    fn from(value: StaticSecret) -> Self {
        Self(value)
    }
}

impl PartialEq for Curve25519 {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_bytes().eq(other.0.as_bytes())
    }
}

impl Eq for Curve25519 {}

impl Curve25519 {
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let mut secret_key_bytes = Zeroizing::new([0u8; ECCCurve::Curve25519.secret_key_length()]);
        rng.fill_bytes(&mut *secret_key_bytes);

        // Clamp, as `to_bytes` does not clamp.
        let q_raw = curve25519_dalek::scalar::clamp_integer(*secret_key_bytes);
        let secret = StaticSecret::from(q_raw);

        Self(secret)
    }

    /// Reads the value in the reverse order (little endian), because..PGP screwed up
    pub fn try_from_bytes_rev(bytes: &[u8]) -> Result<Self> {
        let rev: Vec<u8> = bytes.iter().rev().copied().collect();
        let secret_raw = pad_key::<32>(&rev)?;
        let secret = x25519_dalek::StaticSecret::from(secret_raw);
        Ok(Self(secret))
    }

    /// Returns the raw key in reverse order (little endian)
    pub fn to_bytes_rev(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (byte, o) in self.0.as_bytes().iter().rev().zip(out.iter_mut()) {
            *o = *byte;
        }
        out
    }

    /// Returns the raw key in big endian
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

/// Secret key for ECDH
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop, derive_more::Debug)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub enum SecretKey {
    /// ECDH with Curve25519
    Curve25519(Curve25519),
    /// ECDH with Nist P256
    P256 {
        /// The secret point.
        #[debug("..")]
        #[cfg_attr(test, proptest(strategy = "tests::key_p256_gen()"))]
        secret: p256::SecretKey,
    },

    /// ECDH with Nist P384
    P384 {
        /// The secret point.
        #[debug("..")]
        #[cfg_attr(test, proptest(strategy = "tests::key_p384_gen()"))]
        secret: p384::SecretKey,
    },

    /// ECDH with Nist P521
    P521 {
        /// The secret point.
        #[debug("..")]
        #[cfg_attr(test, proptest(strategy = "tests::key_p521_gen()"))]
        secret: p521::SecretKey,
    },
}

impl From<&SecretKey> for EcdhPublicParams {
    fn from(value: &SecretKey) -> Self {
        let curve = value.curve();
        let hash = curve.hash_algo().expect("known algo");
        let alg_sym = curve.sym_algo().expect("known algo");
        match value {
            SecretKey::Curve25519(key) => Self::Curve25519 {
                p: PublicKey::from(&key.0),
                hash,
                alg_sym,
                ecdh_kdf_type: EcdhKdfType::Native,
            },
            SecretKey::P256 { ref secret } => Self::P256 {
                p: secret.public_key(),
                hash,
                alg_sym,
            },
            SecretKey::P384 { ref secret } => Self::P384 {
                p: secret.public_key(),
                hash,
                alg_sym,
            },
            SecretKey::P521 { ref secret } => Self::P521 {
                p: secret.public_key(),
                hash,
                alg_sym,
            },
        }
    }
}

impl SecretKey {
    /// Generate an ECDH KeyPair.
    pub fn generate<R: RngCore + CryptoRng + ?Sized>(
        rng: &mut R,
        curve: &ECCCurve,
    ) -> Result<Self> {
        match curve {
            ECCCurve::Curve25519 => {
                let key = Curve25519::generate(rng);
                Ok(Self::Curve25519(key))
            }
            ECCCurve::P256 => {
                let secret = p256::SecretKey::random(rng);
                Ok(SecretKey::P256 { secret })
            }
            ECCCurve::P384 => {
                let secret = p384::SecretKey::random(rng);
                Ok(SecretKey::P384 { secret })
            }
            ECCCurve::P521 => {
                let secret = p521::SecretKey::random(rng);
                Ok(SecretKey::P521 { secret })
            }
            _ => unsupported_err!("curve {:?} for ECDH", curve),
        }
    }

    pub(crate) fn try_from_mpi(pub_params: &EcdhPublicParams, d: Mpi) -> Result<Self> {
        match pub_params {
            EcdhPublicParams::Curve25519 { .. } => {
                let key = Curve25519::try_from_bytes_rev(d.as_ref())?;
                Ok(SecretKey::Curve25519(key))
            }
            EcdhPublicParams::P256 { .. } => {
                const SIZE: usize = ECCCurve::P256.secret_key_length();
                let raw = pad_key::<SIZE>(d.as_ref())?;
                let secret = elliptic_curve::SecretKey::<p256::NistP256>::from_bytes(&raw.into())?;

                Ok(SecretKey::P256 { secret })
            }
            EcdhPublicParams::P384 { .. } => {
                const SIZE: usize = ECCCurve::P384.secret_key_length();
                let raw = pad_key::<SIZE>(d.as_ref())?;
                let secret = elliptic_curve::SecretKey::<p384::NistP384>::from_bytes(&raw.into())?;

                Ok(SecretKey::P384 { secret })
            }
            EcdhPublicParams::P521 { .. } => {
                const SIZE: usize = ECCCurve::P521.secret_key_length();
                let raw = pad_key::<SIZE>(d.as_ref())?;
                let arr = Array::<u8, cipher::typenum::U66>::from_slice(&raw[..]);
                let secret = elliptic_curve::SecretKey::<p521::NistP521>::from_bytes(arr)?;

                Ok(SecretKey::P521 { secret })
            }
            EcdhPublicParams::Brainpool256 { .. }
            | EcdhPublicParams::Brainpool384 { .. }
            | EcdhPublicParams::Brainpool512 { .. } => {
                unsupported_err!("brainpool curve {:?} for ECDH")
            }
            EcdhPublicParams::Unsupported { ref curve, .. } => {
                unsupported_err!("curve {:?} for ECDH", curve)
            }
        }
    }

    fn to_mpi(&self) -> Mpi {
        match self {
            Self::Curve25519(key) => {
                let bytes = key.to_bytes_rev();

                // create scalar and reverse to little endian
                // https://www.rfc-editor.org/rfc/rfc9580.html#name-curve25519legacy-ecdh-secre
                Mpi::from_raw(bytes.to_vec().into())
            }
            Self::P256 { secret, .. } => Mpi::from_slice(&secret.to_bytes()),
            Self::P384 { secret, .. } => Mpi::from_slice(&secret.to_bytes()),
            Self::P521 { secret, .. } => Mpi::from_slice(&secret.to_bytes()),
        }
    }

    pub fn curve(&self) -> ECCCurve {
        match self {
            Self::Curve25519 { .. } => ECCCurve::Curve25519,
            Self::P256 { .. } => ECCCurve::P256,
            Self::P384 { .. } => ECCCurve::P384,
            Self::P521 { .. } => ECCCurve::P521,
        }
    }

    /// Returns the secret material as raw bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Curve25519(key) => key.as_bytes().to_vec(),
            Self::P256 { secret, .. } => secret.to_bytes().to_vec(),
            Self::P384 { secret, .. } => secret.to_bytes().to_vec(),
            Self::P521 { secret, .. } => secret.to_bytes().to_vec(),
        }
    }
}

impl Serialize for SecretKey {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        let x = self.to_mpi();
        x.to_writer(writer)
    }

    fn write_len(&self) -> usize {
        let x = self.to_mpi();
        x.write_len()
    }
}

pub struct EncryptionFields<'a> {
    pub public_point: &'a Mpi,

    /// Encrypted and wrapped value, derived from the session key
    pub encrypted_session_key: &'a [u8],

    /// NOTE: The fingerprint isn't part of the "Algorithm-Specific Fields", but it is needed for session key derivation
    pub fingerprint: &'a [u8],

    pub curve: ECCCurve,
    pub hash: HashAlgorithm,
    pub alg_sym: SymmetricKeyAlgorithm,
}

impl Decryptor for SecretKey {
    type EncryptionFields<'a> = EncryptionFields<'a>;

    fn decrypt(&self, data: Self::EncryptionFields<'_>) -> Result<Zeroizing<Vec<u8>>> {
        debug!("ECDH decrypt");

        let encrypted_key_len: usize = data.encrypted_session_key.len();
        let curve = data.curve;
        let alg_sym = data.alg_sym;
        let hash = data.hash;

        let shared_secret = match self {
            SecretKey::Curve25519(key) => {
                ensure_eq!(data.public_point.len(), 33, "invalid public point"); // prefix "0x40" + 32 bytes = 33 bytes

                let their_public = {
                    // public part of the ephemeral key (removes 0x40 prefix)
                    let ephemeral_public_key = &data.public_point.as_ref()[1..];

                    // create montgomery point
                    let mut ephemeral_public_key_arr = [0u8; 32];
                    ephemeral_public_key_arr[..].copy_from_slice(ephemeral_public_key);

                    x25519_dalek::PublicKey::from(ephemeral_public_key_arr)
                };

                // derive shared secret
                let shared_secret = key.0.diffie_hellman(&their_public);

                shared_secret.to_bytes().to_vec()
            }
            SecretKey::P256 { secret, .. } => {
                derive_shared_secret_decryption::<p256::NistP256>(data.public_point, secret, 65)?
            }
            SecretKey::P384 { secret, .. } => {
                derive_shared_secret_decryption::<p384::NistP384>(data.public_point, secret, 97)?
            }
            SecretKey::P521 { secret, .. } => {
                derive_shared_secret_decryption::<p521::NistP521>(data.public_point, secret, 133)?
            }
        };

        // obtain the session key from the shared secret
        let res = derive_session_key(
            &shared_secret,
            data.encrypted_session_key,
            encrypted_key_len,
            curve.clone(),
            hash,
            alg_sym,
            data.fingerprint,
        );

        if res.is_ok() {
            return res;
        }

        #[cfg(feature = "malformed-artifact-compat")]
        {
            log::debug!("Attempting to decrypt erroneous ECDH encryption");

            // Attempt alternative decryption variations for mal-encrypted ECDH ESKs.
            //
            // Context: Erroneous ESKs have been produced by historical versions of both
            // OpenPGP.js and GopenPGP.
            //
            // This special handling code can decrypt technically "broken" messages by attempting
            // to compensate for these two classes of encryption mistake to see if this yields
            // successful decryption.
            //
            // Note that this class of problem should only occur with historical/archived messages!
            // Encryption in both libraries was fixed in 2019:
            //
            // https://github.com/openpgpjs/openpgpjs/commit/1dd168e7a2ce6f9ba0fddf5d198e21baca9c042d
            // https://github.com/openpgpjs/openpgpjs/commit/a9599fea4243f38f01a218a2948b26509a7a3587

            // 1. Try with stripped leading zeroes (-> work around old go crypto bug)
            let mut strip_leading = shared_secret.as_slice();
            while strip_leading.starts_with(&[0]) {
                strip_leading = &strip_leading[1..];
            }

            if let Ok(sk) = derive_session_key(
                strip_leading,
                data.encrypted_session_key,
                encrypted_key_len,
                curve.clone(),
                hash,
                alg_sym,
                data.fingerprint,
            ) {
                log::info!("Decrypted erroneous ECDH session key by go crypto");

                return Ok(sk);
            }

            // 2. Try with stripped trailing zeroes (-> work around old OpenPGP.js bug)
            let mut strip_trailing = shared_secret.as_slice();
            while strip_trailing.ends_with(&[0]) {
                strip_trailing = &strip_trailing[..shared_secret.len() - 1];
            }

            if let Ok(sk) = derive_session_key(
                strip_trailing,
                data.encrypted_session_key,
                encrypted_key_len,
                curve,
                hash,
                alg_sym,
                data.fingerprint,
            ) {
                log::info!("Decrypted erroneous ECDH session key by OpenPGP.js");

                return Ok(sk);
            }
        }

        res
    }
}

/// Derive a shared secret in decryption, for a Rust Crypto curve
fn derive_shared_secret_decryption<C>(
    public_point: &Mpi,
    our_secret: &elliptic_curve::SecretKey<C>,
    pub_bytes: usize,
) -> Result<Vec<u8>>
where
    C: elliptic_curve::CurveArithmetic,
    elliptic_curve::FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
    elliptic_curve::AffinePoint<C>:
        elliptic_curve::sec1::FromEncodedPoint<C> + elliptic_curve::sec1::ToEncodedPoint<C>,
{
    ensure_eq!(public_point.len(), pub_bytes, "invalid public point");

    let ephemeral_public_key =
        elliptic_curve::PublicKey::<C>::from_sec1_bytes(public_point.as_ref())?;

    // derive shared secret
    let shared_secret = elliptic_curve::ecdh::diffie_hellman(
        our_secret.to_nonzero_scalar(),
        ephemeral_public_key.as_affine(),
    );

    Ok(shared_secret.raw_secret_bytes().to_vec())
}

/// Obtain the OpenPGP session key for a DH shared secret.
///
/// This helper function performs the key derivation and unwrapping steps
/// described in <https://www.rfc-editor.org/rfc/rfc9580.html#name-ecdh-algorithm>
pub fn derive_session_key(
    shared_secret: &[u8],
    encrypted_session_key: &[u8],
    encrypted_key_len: usize,
    curve: ECCCurve,
    hash: HashAlgorithm,
    alg_sym: SymmetricKeyAlgorithm,
    fingerprint: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let param = build_ecdh_param(&curve.oid(), alg_sym, hash, fingerprint);

    // Perform key derivation
    let z = kdf(hash, shared_secret, alg_sym.key_size(), &param)?;

    // Perform AES Key Unwrap
    let mut encrypted_session_key_vec = vec![0; encrypted_key_len];
    encrypted_session_key_vec[(encrypted_key_len - encrypted_session_key.len())..]
        .copy_from_slice(encrypted_session_key);

    let mut decrypted_key_padded = aes_kw::unwrap(&z, &encrypted_session_key_vec)?;
    // PKCS5-style unpadding (PKCS5 is PKCS7 with a blocksize of 8).
    //
    // RFC 9580 describes the padding:
    // a) "Then, the above values are padded to an 8-octet granularity using the method described in [RFC8018]."
    // b) "For example, assuming that an AES algorithm is used for the session key, the sender MAY
    // use 21, 13, and 5 octets of padding for AES-128, AES-192, and AES-256, respectively, to
    // provide the same number of octets, 40 total, as an input to the key wrapping method."
    //
    // So while the padding ensures that the length of the padded message is a multiple of 8, the
    // padding may exceed 8 bytes in size.
    {
        let len = decrypted_key_padded.len();
        let block_size = 8;
        ensure!(len % block_size == 0, "invalid key length {}", len);
        ensure!(!decrypted_key_padded.is_empty(), "empty key is not valid");

        // The last byte should contain the padding symbol, which is also the padding length
        let pad = decrypted_key_padded.last().expect("is not empty");

        // Padding length seems to exceed size of the padded message
        if *pad as usize > len {
            return Err(Error::UnpadError);
        }

        // Expected length of the unpadded message
        let unpadded_len = len - *pad as usize;

        // All bytes that constitute the padding must have the value of `pad`
        if decrypted_key_padded[unpadded_len..]
            .iter()
            .any(|byte| byte != pad)
        {
            return Err(Error::UnpadError);
        }

        decrypted_key_padded.truncate(unpadded_len);
    }

    // the key is now unpadded
    let decrypted_key = decrypted_key_padded;
    ensure!(!decrypted_key.is_empty(), "empty unpadded key is not valid");

    Ok(decrypted_key)
}

/// Build param for ECDH algorithm (as defined in RFC 9580)
/// <https://www.rfc-editor.org/rfc/rfc9580.html#name-ecdh-algorithm>
pub fn build_ecdh_param(
    oid: &[u8],
    alg_sym: SymmetricKeyAlgorithm,
    hash: HashAlgorithm,
    fingerprint: &[u8],
) -> Vec<u8> {
    let kdf_params = vec![
        0x03, // length of the following fields
        0x01, // reserved for future extensions
        hash.into(),
        u8::from(alg_sym),
    ];

    let oid_len = [oid.len() as u8];

    let pkalgo = [u8::from(PublicKeyAlgorithm::ECDH)];

    let values: Vec<&[u8]> = vec![
        &oid_len,
        oid,
        &pkalgo,
        &kdf_params,
        &ANON_SENDER[..],
        fingerprint,
    ];

    values.concat()
}

/// Key Derivation Function for ECDH (as defined in RFC 9580).
/// <https://www.rfc-editor.org/rfc/rfc9580.html#name-ecdh-algorithm>
pub fn kdf(hash: HashAlgorithm, x: &[u8], length: usize, param: &[u8]) -> Result<Vec<u8>> {
    let prefix = vec![0, 0, 0, 1];

    let values: Vec<&[u8]> = vec![&prefix, x, param];
    let data = values.concat();

    let mut digest = hash.digest(&data)?;
    digest.truncate(length);

    Ok(digest)
}

/// PKCS5-style padding, with a block-size of 8.
/// However, the padding may exceed the length of one block, to obfuscate key size.
fn pad(plain: &[u8]) -> Vec<u8> {
    let len = plain.len();

    // We produce "short padding" (between 1 and 8 bytes)
    let remainder = len % 8; // (e.g. 3 for len==19)
    let padded_len = len + 8 - remainder; // (e.g. "8 + 8 - 0 => 16", or "19 + 8 - 3 => 24")
    debug_assert!(
        padded_len.is_multiple_of(8),
        "Unexpected padded_len {padded_len}"
    );

    // The value we'll use for padding (must not be zero, and fit into a u8)
    let padding = padded_len - len;
    debug_assert!(
        padding > 0 && u8::try_from(padding).is_ok(),
        "Unexpected padding value {padding}"
    );
    let padding = padding as u8;

    // Extend length of plain_padded, fill with `padding` value
    let mut plain_padded = plain.to_vec();
    plain_padded.resize(padded_len, padding);

    plain_padded
}

/// ECDH encryption.
pub fn encrypt<R: CryptoRng + RngCore + ?Sized>(
    rng: &mut R,
    params: &EcdhPublicParams,
    fingerprint: &[u8],
    plain: &[u8],
) -> Result<PkeskBytes> {
    debug!("ECDH encrypt");

    // Maximum length for `plain`:
    // - padding increases the length (at least) to a length of the next multiple of 8.
    // - aes keywrap adds another 8 bytes
    // - the maximum length value this function can return is u8 (limited to 255)
    const MAX_SIZE: usize = 239;
    ensure!(
        plain.len() <= MAX_SIZE,
        "unable to encrypt larger than {} bytes",
        MAX_SIZE
    );

    let (encoded_public, shared_secret, hash, alg_sym) = match params {
        EcdhPublicParams::Curve25519 {
            p,
            hash,
            alg_sym,
            ecdh_kdf_type,
        } => {
            ensure_eq!(
                ecdh_kdf_type,
                &EcdhKdfType::Native,
                "ecdh_kdf_type must be Native"
            );

            let their_public = p;
            let mut our_secret_key_bytes =
                Zeroizing::new([0u8; ECCCurve::Curve25519.secret_key_length()]);
            rng.fill_bytes(&mut *our_secret_key_bytes);
            let our_secret = StaticSecret::from(*our_secret_key_bytes);

            // derive shared secret
            let shared_secret = our_secret.diffie_hellman(their_public);

            // Encode public point: prefix with 0x40
            let mut encoded_public = Vec::with_capacity(33);
            encoded_public.push(0x40);
            encoded_public.extend(x25519_dalek::PublicKey::from(&our_secret).as_bytes().iter());

            (
                encoded_public,
                shared_secret.as_bytes().to_vec(),
                hash,
                alg_sym,
            )
        }
        EcdhPublicParams::P256 { p, hash, alg_sym } => {
            let (public, secret) = derive_shared_secret_encryption::<p256::NistP256, R>(rng, p)?;
            (public, secret, hash, alg_sym)
        }
        EcdhPublicParams::P384 { p, hash, alg_sym } => {
            let (public, secret) = derive_shared_secret_encryption::<p384::NistP384, R>(rng, p)?;
            (public, secret, hash, alg_sym)
        }
        EcdhPublicParams::P521 { p, hash, alg_sym } => {
            let (public, secret) = derive_shared_secret_encryption::<p521::NistP521, R>(rng, p)?;
            (public, secret, hash, alg_sym)
        }
        _ => unsupported_err!("{:?} for ECDH", params),
    };

    // Implementations MUST NOT use MD5, SHA-1, or RIPEMD-160 as a hash function in an ECDH KDF.
    // (See https://www.rfc-editor.org/rfc/rfc9580.html#section-9.5-3)
    ensure!(
        *hash != HashAlgorithm::Md5
            && *hash != HashAlgorithm::Sha1
            && *hash != HashAlgorithm::Ripemd160,
        "{:?} is not a legal hash function for ECDH KDF",
        hash
    );

    let param = build_ecdh_param(&params.curve().oid(), *alg_sym, *hash, fingerprint);

    // Perform key derivation
    let z = kdf(*hash, &shared_secret, alg_sym.key_size(), &param)?;

    // Pad plaintext
    let plain_padded = pad(plain);

    // Perform AES Key Wrap
    let encrypted_session_key = aes_kw::wrap(&z, &plain_padded)?;

    Ok(PkeskBytes::Ecdh {
        public_point: Mpi::from_slice(&encoded_public),
        encrypted_session_key: encrypted_session_key.into(),
    })
}

/// Derive a shared secret in encryption, for a Rust Crypto curve.
/// Returns a pair of `(our_public key, shared_secret)`.
fn derive_shared_secret_encryption<C, R: CryptoRng + RngCore + ?Sized>(
    rng: &mut R,
    their_public: &elliptic_curve::PublicKey<C>,
) -> Result<(Vec<u8>, Vec<u8>)>
where
    C: elliptic_curve::CurveArithmetic + elliptic_curve::point::PointCompression,
    elliptic_curve::FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
    elliptic_curve::AffinePoint<C>:
        elliptic_curve::sec1::FromEncodedPoint<C> + elliptic_curve::sec1::ToEncodedPoint<C>,
{
    let our_secret = elliptic_curve::ecdh::EphemeralSecret::<C>::generate_from_rng(rng);

    // derive shared secret
    let shared_secret = our_secret.diffie_hellman(their_public);

    // encode our public key
    let our_public = elliptic_curve::PublicKey::<C>::from(&our_secret);
    let our_public = elliptic_curve::sec1::EncodedPoint::<C>::from(our_public);

    Ok((
        our_public.as_bytes().to_vec(),
        shared_secret.raw_secret_bytes().to_vec(),
    ))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use chacha20::ChaCha20Rng;
    use proptest::prelude::*;
    use rand::{RngCore, SeedableRng};

    use super::*;
    use crate::{
        composed::{Deserializable, Message, SignedSecretKey},
        types::Password,
    };

    #[test]
    #[ignore]
    fn test_encrypt_decrypt() {
        for curve in [
            ECCCurve::Curve25519,
            ECCCurve::P256,
            ECCCurve::P384,
            ECCCurve::P521,
        ] {
            let mut rng = ChaCha20Rng::from_seed([0u8; 32]);

            let skey = SecretKey::generate(&mut rng, &curve).unwrap();
            let pub_params: EcdhPublicParams = (&skey).into();

            for text_size in 1..=239 {
                for _i in 0..10 {
                    let mut fingerprint = vec![0u8; 20];
                    rng.fill_bytes(&mut fingerprint);

                    let mut plain = vec![0u8; text_size];
                    rng.fill_bytes(&mut plain);

                    let values = encrypt(&mut rng, &pub_params, &fingerprint, &plain[..]).unwrap();

                    let decrypted = match values {
                        PkeskBytes::Ecdh {
                            public_point,
                            encrypted_session_key,
                        } => skey
                            .decrypt(EncryptionFields {
                                public_point: &public_point.to_owned(),
                                encrypted_session_key: &encrypted_session_key,
                                fingerprint: &fingerprint,
                                curve: curve.clone(),
                                hash: curve.hash_algo().unwrap(),
                                alg_sym: curve.sym_algo().unwrap(),
                            })
                            .unwrap(),
                        _ => panic!("invalid key generated"),
                    };

                    assert_eq!(&plain[..], &decrypted[..]);
                }
            }
        }
    }

    #[test]
    fn test_decrypt_padding() {
        let _ = pretty_env_logger::try_init();

        let (decrypt_key, _headers) = SignedSecretKey::from_armor_single(
            fs::File::open("./tests/unit-tests/padding/alice.key").unwrap(),
        )
        .expect("failed to read decryption key");

        for msg_file in [
            "./tests/unit-tests/padding/msg-short-padding.pgp",
            "./tests/unit-tests/padding/msg-long-padding.pgp",
        ] {
            let (message, _headers) =
                Message::from_armor_file(msg_file).expect("failed to parse message");

            let mut msg = message
                .decrypt(&Password::empty(), &decrypt_key)
                .expect("failed to init decryption");

            let data = msg.as_data_vec().unwrap();

            assert_eq!(data, "hello\n".as_bytes());
        }
    }

    #[test]
    #[cfg(feature = "malformed-artifact-compat")]
    /// Test custom decryption of incorrectly formed ECDH messages
    /// "broken ECC message from old OpenPGP.js"
    ///
    /// From: https://github.com/openpgpjs/openpgpjs/blob/448418a6f56ece88dfb28c26a85107b887061d9d/test/general/openpgp.js#L337-L405
    fn test_decrypt_bad_ecdh_openpgp_js() {
        let _ = pretty_env_logger::try_init();

        const PASSPHRASE: &str = "12345";

        const MSG_OPENPGP_JS_PLAIN: &str = "\r\n";

        let (decrypt_key, _headers) =
            SignedSecretKey::from_armor_file("tests/bad_ecdh/openpgp_js.key")
                .expect("failed to read decryption key");

        let (message, _headers) = Message::from_armor_file("tests/bad_ecdh/openpgp_js.msg")
            .expect("failed to parse message");

        let mut dec = message
            .decrypt(&Password::from(PASSPHRASE), &decrypt_key)
            .expect("failed to decrypt")
            .decompress()
            .expect("failed to decompress");

        let data = dec.as_data_vec().unwrap();

        assert_eq!(data, MSG_OPENPGP_JS_PLAIN.as_bytes());
    }

    #[test]
    #[cfg(feature = "malformed-artifact-compat")]
    /// Test custom decryption of incorrectly formed ECDH messages
    /// "broken ECC message from old go crypto"
    ///
    /// From: https://github.com/openpgpjs/openpgpjs/blob/448418a6f56ece88dfb28c26a85107b887061d9d/test/general/openpgp.js#L337-L405
    fn test_decrypt_bad_ecdh_go_crypto() {
        use std::io::Read;

        use crate::{
            composed::{Esk, PlainSessionKey},
            types::{DecryptionKey, EskType},
        };

        let _ = pretty_env_logger::try_init();

        const PASSPHRASE: &str = "12345";

        const MSG_GO_CRYPTO_PLAIN: &str =
            "Tesssst<br><br><br>Sent from ProtonMail mobile<br><br><br>";

        let (decrypt_key, _headers) =
            SignedSecretKey::from_armor_file("tests/bad_ecdh/gocrypto.key")
                .expect("failed to read decryption key");

        let (message, _headers) = Message::from_armor_file("tests/bad_ecdh/gocrypto.msg")
            .expect("failed to parse message");

        {
            // Note: The content of the Edata is technically malformed
            // ("Illegal first partial body length 2 (shorter than 512 bytes)"), and thus rPGP
            // refuses to handle it without setting handling of partial body encoding to lenient.
            //
            // As a first step (that should always work), we decrypt just the PKESK itself.

            let Message::Encrypted { ref esk, .. } = &message else {
                panic!("expect encrypted message")
            };

            assert_eq!(esk.len(), 1);

            let Esk::PublicKeyEncryptedSessionKey(pkesk) = &esk[0] else {
                panic!("expect PKESK")
            };

            let psk = decrypt_key.secret_subkeys[0]
                .decrypt(
                    &Password::from(PASSPHRASE),
                    pkesk.values().unwrap(),
                    EskType::V3_4,
                )
                .expect("failed to decrypt session key")
                .expect("failed to unlock the key");

            let PlainSessionKey::V3_4 { ref key, .. } = &psk else {
                panic!("expect v3/4 session key")
            };

            // Having found the session key is good enough to show that decryption worked
            assert_eq!(
                key.as_ref(),
                &[
                    0xb6, 0xe1, 0xc2, 0xeb, 0x51, 0xad, 0xdd, 0xf3, 0x9a, 0x69, 0x6e, 0xbf, 0x0d,
                    0xbb, 0x6b, 0x83, 0x87, 0xeb, 0x39, 0x81, 0x4f, 0x80, 0xf6, 0xaa, 0x97, 0xe6,
                    0x88, 0xb6, 0x1d, 0xaa, 0x3e, 0xc4
                ]
            );
        }

        let Ok(mut dec) = message.decrypt(&Password::from(PASSPHRASE), &decrypt_key) else {
            panic!("could not decrypt message")
        };

        let mut data = Vec::new();
        dec.read_to_end(&mut data).unwrap();

        assert_eq!(&data, MSG_GO_CRYPTO_PLAIN.as_bytes());
    }

    prop_compose! {
        pub fn key_p256_gen()(seed: u64) -> p256::SecretKey {
            let mut rng = chacha20::ChaCha8Rng::seed_from_u64(seed);
             p256::SecretKey::random(&mut rng)
        }
    }

    prop_compose! {
        pub fn key_p384_gen()(seed: u64) -> p384::SecretKey {
            let mut rng = chacha20::ChaCha8Rng::seed_from_u64(seed);
            p384::SecretKey::random(&mut rng)
        }
    }

    prop_compose! {
        pub fn key_p521_gen()(seed: u64) -> p521::SecretKey {
            let mut rng = chacha20::ChaCha8Rng::seed_from_u64(seed);
            p521::SecretKey::random(&mut rng)
        }
    }

    prop_compose! {
        pub fn key_k256_gen()(seed: u64) -> k256::SecretKey {
            let mut rng = chacha20::ChaCha8Rng::seed_from_u64(seed);
            k256::SecretKey::random(&mut rng)
        }
    }

    impl Arbitrary for Curve25519 {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            any::<u64>()
                .prop_map(|seed| {
                    let mut rng = chacha20::ChaCha8Rng::seed_from_u64(seed);
                    Curve25519::generate(&mut rng)
                })
                .boxed()
        }
    }
}

use std::hash::Hasher;
use std::io;

use ::rsa::traits::PrivateKeyParts;
use byteorder::{BigEndian, ByteOrder};
use bytes::Buf;
use hkdf::Hkdf;
use num_bigint::ModInverse;
use sha2::Sha256;
use zeroize::ZeroizeOnDrop;

use crate::crypto::aead::AeadAlgorithm;
use crate::crypto::ecc_curve::ECCCurve;
use crate::crypto::public_key::PublicKeyAlgorithm;
use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::crypto::{checksum, dsa, ecdh, ecdsa, eddsa, rsa, x25519, Decryptor};
use crate::errors::Result;
use crate::parsing::BufParsing;
use crate::ser::Serialize;
use crate::types::PkeskBytes;
use crate::types::*;
use crate::types::{EskType, PublicKeyTrait, PublicParams};
use crate::util::TeeWriter;
use crate::PlainSessionKey;

#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop, derive_more::Debug)]
#[allow(clippy::large_enum_variant)] // FIXME
pub enum PlainSecretParams {
    RSA(rsa::SecretKey),
    DSA(dsa::SecretKey),
    ECDSA(ecdsa::SecretKey),
    ECDH(ecdh::SecretKey),
    EdDSA(eddsa::SecretKey),
    EdDSALegacy(eddsa::SecretKey),
    X25519(x25519::SecretKey),
    #[cfg(feature = "unstable-curve448")]
    X448(crate::crypto::x448::SecretKey),
}

pub(crate) fn pad_key<const SIZE: usize>(val: &[u8]) -> Result<[u8; SIZE]> {
    ensure!(val.len() <= SIZE, "invalid secret key size");

    let mut key = [0u8; SIZE];
    key[SIZE - val.len()..].copy_from_slice(val);
    Ok(key)
}

impl PlainSecretParams {
    /// Skips the checksum, because it already has been checked.
    pub fn try_from_buf_no_checksum<B: Buf>(
        mut i: B,
        _version: KeyVersion,
        alg: PublicKeyAlgorithm,
        public_params: &PublicParams,
    ) -> Result<Self> {
        let params = Self::try_from_buf_inner(&mut i, alg, public_params)?;
        ensure!(
            !i.has_remaining(),
            "failed to process full secret key material"
        );
        Ok(params)
    }

    fn try_from_buf_inner<B: Buf>(
        mut i: B,
        alg: PublicKeyAlgorithm,
        public_params: &PublicParams,
    ) -> Result<Self> {
        let params = match (alg, public_params) {
            (
                PublicKeyAlgorithm::RSA
                | PublicKeyAlgorithm::RSAEncrypt
                | PublicKeyAlgorithm::RSASign,
                PublicParams::RSA(pub_params),
            ) => {
                let d = MpiBytes::from_buf(&mut i)?;
                let p = MpiBytes::from_buf(&mut i)?;
                let q = MpiBytes::from_buf(&mut i)?;
                let u = MpiBytes::from_buf(&mut i)?;

                let key = crate::crypto::rsa::SecretKey::try_from_mpi(pub_params, d, p, q, u)?;
                Self::RSA(key)
            }
            (PublicKeyAlgorithm::DSA, PublicParams::DSA(pub_params)) => {
                let secret = MpiBytes::from_buf(i)?;

                let key = crate::crypto::dsa::SecretKey::try_from_mpi(pub_params, secret)?;
                Self::DSA(key)
            }
            (PublicKeyAlgorithm::Elgamal, PublicParams::Elgamal(_)) => {
                // map(mpi, PlainSecretParamsRef::Elgamal)(i)
                unsupported_err!("elgamal secret key material");
            }
            (PublicKeyAlgorithm::ECDH, PublicParams::ECDH(pub_params)) => {
                let secret = MpiBytes::from_buf(i)?;

                let key = crate::crypto::ecdh::SecretKey::try_from_mpi(pub_params, secret)?;
                Self::ECDH(key)
            }
            (PublicKeyAlgorithm::ECDSA, PublicParams::ECDSA(pub_params)) => {
                let secret = MpiBytes::from_buf(i)?;

                let key = crate::crypto::ecdsa::SecretKey::try_from_mpi(pub_params, secret)?;
                Self::ECDSA(key)
            }
            (PublicKeyAlgorithm::EdDSALegacy, PublicParams::EdDSALegacy(_pub_params)) => {
                let secret = MpiBytes::from_buf(i)?;

                const SIZE: usize = ECCCurve::Ed25519.secret_key_length();
                let secret = pad_key::<SIZE>(secret.as_ref())?;
                let key = crate::crypto::eddsa::SecretKey::try_from_bytes(secret)?;
                Self::EdDSALegacy(key)
            }
            (PublicKeyAlgorithm::Ed25519, PublicParams::Ed25519(_pub_params)) => {
                let secret = i.read_array::<32>()?;
                let key = crate::crypto::eddsa::SecretKey::try_from_bytes(secret)?;
                Self::EdDSA(key)
            }
            (PublicKeyAlgorithm::X25519, PublicParams::X25519(pub_params)) => {
                let secret = i.read_array::<32>()?;
                let key = crate::crypto::x25519::SecretKey::try_from_array(pub_params, secret)?;
                Self::X25519(key)
            }
            #[cfg(feature = "unstable-curve448")]
            (PublicKeyAlgorithm::X448, PublicParams::X448 { .. }) => {
                let s = i.read_array::<56>()?;
                let key = crate::crypto::x448::SecretKey::try_from_bytes(s)?;
                Self::X448(key)
            }
            _ => {
                bail!("inconsistent key state");
            }
        };

        Ok(params)
    }

    pub fn try_from_buf<B: Buf>(
        mut i: B,
        version: KeyVersion,
        alg: PublicKeyAlgorithm,
        public_params: &PublicParams,
    ) -> Result<Self> {
        let params = Self::try_from_buf_inner(&mut i, alg, public_params)?;
        if version == KeyVersion::V3 || version == KeyVersion::V4 {
            let checksum = i.read_array::<2>()?;
            params.compare_checksum_simple(&checksum)?;
            ensure!(
                !i.has_remaining(),
                "failed to process full secret key material"
            );
        }

        Ok(params)
    }

    pub fn string_to_key_id(&self) -> u8 {
        0
    }

    pub fn checksum_simple(&self) -> Vec<u8> {
        let mut hasher = checksum::SimpleChecksum::default();
        self.to_writer_raw(&mut hasher).expect("known write target");
        hasher.finalize().to_vec()
    }

    /// Uses sha1_checked
    pub fn checksum_sha1(&self) -> Result<[u8; 20]> {
        let mut buf = Vec::with_capacity(self.write_len_raw());
        self.to_writer_raw(&mut buf).expect("known write target");
        checksum::calculate_sha1([&buf])
    }

    pub fn encrypt(
        &self,
        passphrase: &str,
        s2k_params: S2kParams,
        pub_key: &(impl PublicKeyTrait + Serialize),
        secret_tag: Option<Tag>,
    ) -> Result<EncryptedSecretParams> {
        let version = pub_key.version();

        // forbid weak hash algo in s2k

        match &s2k_params {
            S2kParams::Cfb { s2k, .. }
            | S2kParams::Aead { s2k, .. }
            | S2kParams::MalleableCfb { s2k, .. } => {
                // Implementations MUST NOT generate packets using MD5, SHA-1, or RIPEMD-160 as a hash function in an S2K KDF.
                // (See https://www.rfc-editor.org/rfc/rfc9580.html#section-9.5-3)
                ensure!(
                    !s2k.known_weak_hash_algo(),
                    "Weak hash algorithm in S2K not allowed for v6 {:?}",
                    s2k
                )
            }
            _ => {}
        }

        match &s2k_params {
            S2kParams::Unprotected => bail!("cannot encrypt to unprotected"),
            S2kParams::Cfb { sym_alg, s2k, iv } => {
                // An implementation MUST NOT create [..] any Secret Key packet where the S2K usage
                // octet is not AEAD (253) and the S2K Specifier Type is Argon2.
                ensure!(
                    !matches!(s2k, StringToKey::Argon2 { .. }),
                    "Argon2 not allowed with Cfb"
                );

                let key = s2k.derive_key(passphrase, sym_alg.key_size())?;
                let enc_data = match version {
                    KeyVersion::V2 | KeyVersion::V3 => {
                        unimplemented_err!("Encryption for V2/V3 keys is not available")
                    }
                    KeyVersion::V4 | KeyVersion::V6 => {
                        let mut data = Vec::with_capacity(self.write_len_raw());
                        self.to_writer_raw(&mut data).expect("preallocated vector");

                        data.extend_from_slice(&self.checksum_sha1()?[..]);
                        sym_alg.encrypt_with_iv_regular(&key, iv, &mut data)?;

                        data
                    }
                    KeyVersion::V5 => unimplemented_err!("v5 encryption"),
                    KeyVersion::Other(v) => unimplemented_err!("encryption for key version {}", v),
                };

                Ok(EncryptedSecretParams::new(enc_data.into(), s2k_params))
            }
            S2kParams::Aead {
                sym_alg,
                aead_mode,
                s2k,
                nonce,
            } => {
                let key = s2k.derive_key(passphrase, sym_alg.key_size())?;

                let enc_data = match version {
                    KeyVersion::V2 | KeyVersion::V3 => {
                        unimplemented_err!("Encryption for V2/V3 keys is not available")
                    }
                    KeyVersion::V4 | KeyVersion::V6 => {
                        let mut data = Vec::with_capacity(self.write_len_raw());
                        self.to_writer_raw(&mut data).expect("preallocated vector");

                        let Some(secret_tag) = secret_tag else {
                            bail!("no secret_tag provided");
                        };

                        let (okm, ad) =
                            s2k_usage_aead(&key, secret_tag, pub_key, *sym_alg, *aead_mode)?;

                        // AEAD encrypt
                        let tag =
                            aead_mode.encrypt_in_place(sym_alg, &okm, nonce, &ad, &mut data)?;

                        // append tag to now encrypted secret params
                        data.extend_from_slice(&tag);

                        data
                    }
                    KeyVersion::V5 => unimplemented_err!("v5 encryption"),
                    KeyVersion::Other(v) => unimplemented_err!("encryption for key version {}", v),
                };

                Ok(EncryptedSecretParams::new(enc_data.into(), s2k_params))
            }
            _ => unimplemented_err!("{:?} not implemented yet", s2k_params),
        }
    }

    pub fn decrypt<P>(
        &self,
        pub_params: &PublicParams,
        values: &PkeskBytes,
        typ: EskType,
        recipient: &P,
    ) -> Result<PlainSessionKey>
    where
        P: PublicKeyTrait,
    {
        let decrypted_key = match (self, values) {
            (PlainSecretParams::RSA(ref priv_key), PkeskBytes::Rsa { mpi }) => {
                priv_key.decrypt(&mpi.to_owned())?
            }
            (PlainSecretParams::DSA(_), _) => bail!("DSA is only used for signing"),
            (PlainSecretParams::ECDSA(_), _) => bail!("ECDSA is only used for signing"),
            (
                PlainSecretParams::ECDH(ref priv_key),
                PkeskBytes::Ecdh {
                    public_point,
                    encrypted_session_key,
                },
            ) => {
                let PublicParams::ECDH(params) = pub_params else {
                    bail!("inconsistent key state");
                };

                let (hash, alg_sym) = match params {
                    EcdhPublicParams::Curve25519 { hash, alg_sym, .. } => (hash, alg_sym),
                    EcdhPublicParams::P256 { hash, alg_sym, .. } => (hash, alg_sym),
                    EcdhPublicParams::P384 { hash, alg_sym, .. } => (hash, alg_sym),
                    EcdhPublicParams::P521 { hash, alg_sym, .. } => (hash, alg_sym),
                    EcdhPublicParams::Unsupported { curve, .. } => {
                        unsupported_err!("curve {} is not supported", curve);
                    }
                };

                priv_key.decrypt(ecdh::EncryptionFields {
                    public_point: &public_point.to_owned(),
                    encrypted_session_key,
                    fingerprint: recipient.fingerprint().as_bytes(),
                    curve: params.curve(),
                    hash: *hash,
                    alg_sym: *alg_sym,
                })?
            }

            (
                PlainSecretParams::X25519(ref priv_key),
                PkeskBytes::X25519 {
                    ephemeral,
                    session_key,
                    sym_alg,
                },
            ) => {
                // Recipient public key (32 bytes)
                let PublicParams::X25519(params) = recipient.public_params() else {
                    bail!(
                        "Unexpected recipient public_params {:?} for X25519",
                        recipient.public_params()
                    );
                };

                let data = x25519::EncryptionFields {
                    ephemeral_public_point: ephemeral.to_owned(),
                    recipient_public: params.key.to_bytes(),
                    encrypted_session_key: session_key,
                };

                let key = priv_key.decrypt(data)?;

                return match (&typ, *sym_alg) {
                    // We expect `sym_alg` to be set for v3 PKESK, and unset for v6 PKESK
                    (EskType::V3_4, Some(sym_alg)) => Ok(PlainSessionKey::V3_4 { key, sym_alg }),
                    (EskType::V6, None) => Ok(PlainSessionKey::V6 { key }),
                    _ => bail!("unexpected: sym_alg {:?} for {:?}", sym_alg, typ),
                };
            }

            #[cfg(feature = "unstable-curve448")]
            (
                PlainSecretParams::X448(ref priv_key),
                PkeskBytes::X448 {
                    ephemeral,
                    session_key,
                    sym_alg,
                },
            ) => {
                // Recipient public key (56 bytes)
                let PublicParams::X448(ref params) = recipient.public_params() else {
                    bail!(
                        "Unexpected recipient public_params {:?} for X448",
                        recipient.public_params()
                    );
                };

                let data = crate::crypto::x448::EncryptionFields {
                    ephemeral_public_point: ephemeral.to_owned(),
                    recipient_public: params.key,
                    encrypted_session_key: session_key,
                };

                let key = priv_key.decrypt(data)?;

                // We expect `algo` to be set for v3 PKESK, and unset for v6 PKESK
                return if let Some(sym_alg) = *sym_alg {
                    Ok(PlainSessionKey::V3_4 { key, sym_alg })
                } else {
                    Ok(PlainSessionKey::V6 { key })
                };
            }

            (PlainSecretParams::EdDSA(_), _) => bail!("EdDSA is only used for signing"),
            _ => unimplemented_err!(
                "Unsupported: PlainSecretParams {:?}, PkeskBytes {:?}",
                self,
                values
            ),
        };

        match typ {
            EskType::V3_4 => {
                let sym_alg = SymmetricKeyAlgorithm::from(decrypted_key[0]);
                ensure!(
                    sym_alg != SymmetricKeyAlgorithm::Plaintext,
                    "session key algorithm cannot be plaintext"
                );

                debug!("sym_alg: {:?}", sym_alg);

                let key_size = sym_alg.key_size();
                ensure_eq!(
                    decrypted_key.len(),
                    key_size + 3,
                    "unexpected decrypted_key length ({}) for sym_alg {:?}",
                    decrypted_key.len(),
                    sym_alg
                );

                let key = decrypted_key[1..=key_size].to_vec();
                let checksum = &decrypted_key[key_size + 1..key_size + 3];

                checksum::simple(checksum, &key)?;

                Ok(PlainSessionKey::V3_4 { key, sym_alg })
            }

            EskType::V6 => {
                let len = decrypted_key.len();

                // ensure minimal length so that we don't panic in the slice splitting, below
                ensure!(
                    len >= 2,
                    "unexpected decrypted_key length ({}) for V6 ESK",
                    len,
                );

                let key = decrypted_key[0..len - 2].to_vec();
                let checksum = &decrypted_key[len - 2..];

                checksum::simple(checksum, &key)?;

                Ok(PlainSessionKey::V6 { key })
            }
        }
    }

    pub fn to_writer<W: io::Write>(&self, writer: &mut W, version: KeyVersion) -> Result<()> {
        let mut hasher = checksum::SimpleChecksum::default();
        {
            let mut tee = TeeWriter::new(&mut hasher, writer);
            self.to_writer_raw(&mut tee)?;
        }

        if version == KeyVersion::V3 || version == KeyVersion::V4 {
            // Only for a version 3 or 4 packet where the string-to-key usage octet is zero, a
            // two-octet checksum of the algorithm-specific portion (sum of all octets, mod 65536).
            //
            // https://www.rfc-editor.org/rfc/rfc9580.html#section-5.5.3-3.6.1
            hasher.to_writer(writer)?;
        }

        Ok(())
    }

    pub fn write_len(&self, version: KeyVersion) -> usize {
        let mut sum = self.write_len_raw();
        if version == KeyVersion::V3 || version == KeyVersion::V4 {
            // checksum
            sum += 2;
        }
        sum
    }

    fn compare_checksum_simple(&self, other: &[u8]) -> Result<()> {
        let mut hasher = checksum::SimpleChecksum::default();
        self.to_writer_raw(&mut hasher)?;
        ensure_eq!(
            BigEndian::read_u16(other),
            hasher.finish() as u16,
            "Invalid checksum"
        );
        Ok(())
    }

    fn to_writer_raw<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            PlainSecretParams::RSA(key) => {
                let d = key.d();
                let p = &key.primes()[0];
                let q = &key.primes()[1];
                let u = p
                    .clone()
                    .mod_inverse(q)
                    .expect("invalid prime")
                    .to_biguint()
                    .expect("invalid prime");

                MpiBytes::from(d).to_writer(writer)?;
                MpiBytes::from(p).to_writer(writer)?;
                MpiBytes::from(q).to_writer(writer)?;
                MpiBytes::from(u).to_writer(writer)?;
            }
            PlainSecretParams::DSA(key) => {
                let x = key.x();
                MpiBytes::from(x).to_writer(writer)?;
            }
            PlainSecretParams::ECDSA(key) => {
                let x = key.as_mpi();
                x.to_writer(writer)?;
            }
            PlainSecretParams::ECDH(key) => {
                let x = key.as_mpi();
                x.to_writer(writer)?;
            }
            PlainSecretParams::X25519(key) => {
                let q = key.secret.to_bytes();
                writer.write_all(&q)?;
            }
            PlainSecretParams::EdDSA(key) => {
                writer.write_all(key.secret.as_bytes().as_ref())?;
            }
            PlainSecretParams::EdDSALegacy(key) => {
                let x = key.as_mpi();
                x.to_writer(writer)?;
            }
            #[cfg(feature = "unstable-curve448")]
            PlainSecretParams::X448(key) => {
                writer.write_all(&key.secret)?;
            }
        }

        Ok(())
    }

    fn write_len_raw(&self) -> usize {
        match self {
            PlainSecretParams::RSA(key) => {
                let d = key.d();
                let p = &key.primes()[0];
                let q = &key.primes()[1];
                let u = p
                    .clone()
                    .mod_inverse(q)
                    .expect("invalid prime")
                    .to_biguint()
                    .expect("invalid prime");

                let mut sum = 0;
                sum += MpiBytes::from(d).write_len();
                sum += MpiBytes::from(p).write_len();
                sum += MpiBytes::from(q).write_len();
                sum += MpiBytes::from(u).write_len();
                sum
            }
            PlainSecretParams::DSA(key) => {
                let x = key.x();
                MpiBytes::from(x).write_len()
            }
            PlainSecretParams::ECDSA(key) => {
                let x = key.as_mpi();
                x.write_len()
            }
            PlainSecretParams::ECDH(key) => {
                let x = key.as_mpi();
                x.write_len()
            }
            PlainSecretParams::EdDSA(_key) => 32,
            PlainSecretParams::EdDSALegacy(key) => {
                let x = key.as_mpi();
                x.write_len()
            }
            PlainSecretParams::X25519(_key) => 32,
            #[cfg(feature = "unstable-curve448")]
            PlainSecretParams::X448(_key) => 56,
        }
    }
}

/// Derive output keying material and associated data for the s2k usage method AEAD.
///
/// https://www.rfc-editor.org/rfc/rfc9580.html#name-secret-key-packet-formats
pub(crate) fn s2k_usage_aead(
    derived: &[u8],
    secret_tag: Tag,
    pub_key: &(impl PublicKeyTrait + Serialize),
    sym_alg: SymmetricKeyAlgorithm,
    aead_mode: AeadAlgorithm,
) -> Result<([u8; 32], Vec<u8>)> {
    // HKDF to derive output keying material
    let hk = Hkdf::<Sha256>::new(None, derived);
    let mut okm = [0u8; 32];

    let type_id = u8::from(secret_tag) | 0xc0;

    // HKDF info parameter
    let info = [
        type_id,
        pub_key.version().into(),
        sym_alg.into(),
        aead_mode.into(),
    ];

    hk.expand(&info, &mut okm)
        .expect("32 is a valid length for Sha256 to output");

    // Additional data:
    // - the Packet Type ID in OpenPGP format encoding
    // - followed by the public key packet fields, starting with the packet version number
    let mut ad = vec![type_id];
    pub_key.to_writer(&mut ad)?;

    Ok((okm, ad))
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;

    use crate::crypto::public_key::PublicKeyAlgorithm;

    impl Arbitrary for PlainSecretParams {
        type Parameters = PublicKeyAlgorithm;
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary() -> Self::Strategy {
            any::<PublicKeyAlgorithm>()
                .prop_flat_map(Self::arbitrary_with)
                .boxed()
        }

        fn arbitrary_with(alg: Self::Parameters) -> Self::Strategy {
            match alg {
                PublicKeyAlgorithm::RSA
                | PublicKeyAlgorithm::RSAEncrypt
                | PublicKeyAlgorithm::RSASign => any::<rsa::SecretKey>()
                    .prop_map(PlainSecretParams::RSA)
                    .boxed(),
                PublicKeyAlgorithm::DSA => any::<dsa::SecretKey>()
                    .prop_map(PlainSecretParams::DSA)
                    .boxed(),
                PublicKeyAlgorithm::ECDSA => any::<ecdsa::SecretKey>()
                    .prop_map(PlainSecretParams::ECDSA)
                    .boxed(),
                PublicKeyAlgorithm::ECDH => any::<ecdh::SecretKey>()
                    .prop_map(PlainSecretParams::ECDH)
                    .boxed(),
                PublicKeyAlgorithm::EdDSALegacy => any::<eddsa::SecretKey>()
                    .prop_map(PlainSecretParams::EdDSALegacy)
                    .boxed(),
                PublicKeyAlgorithm::Ed25519 => any::<eddsa::SecretKey>()
                    .prop_map(PlainSecretParams::EdDSA)
                    .boxed(),
                PublicKeyAlgorithm::X25519 => any::<x25519::SecretKey>()
                    .prop_map(PlainSecretParams::X25519)
                    .boxed(),
                #[cfg(feature = "unstable-curve448")]
                PublicKeyAlgorithm::X448 => any::<crate::crypto::x448::SecretKey>()
                    .prop_map(PlainSecretParams::X448)
                    .boxed(),
                _ => {
                    unimplemented!("{:?}", alg)
                }
            }
        }
    }

    proptest! {
        #[test]
        #[ignore]
        fn params_write_len_v3(params: PlainSecretParams) {
            let mut buf = Vec::new();
            params.to_writer(&mut buf, KeyVersion::V3)?;
            prop_assert_eq!(buf.len(), params.write_len(KeyVersion::V3));
        }

        #[test]
        #[ignore]
        fn params_write_len_v4(params: PlainSecretParams) {
            let mut buf = Vec::new();
            params.to_writer(&mut buf, KeyVersion::V4)?;
            prop_assert_eq!(buf.len(), params.write_len(KeyVersion::V4));
        }

        #[test]
        #[ignore]
        fn params_write_len_v6(params: PlainSecretParams) {
            let mut buf = Vec::new();
            params.to_writer(&mut buf, KeyVersion::V6)?;
            prop_assert_eq!(buf.len(), params.write_len(KeyVersion::V6));
        }

        #[test]
        #[ignore]
        fn params_roundtrip_v3(
            (alg, secret_params) in any::<PublicKeyAlgorithm>().prop_flat_map(|alg| (Just(alg), any_with::<PlainSecretParams>(alg)))
        ) {
            let mut buf = Vec::new();
            secret_params.to_writer(&mut buf, KeyVersion::V3)?;
            let public_params = PublicParams::try_from(&secret_params)?;
            let new_params = PlainSecretParams::try_from_buf(&mut &buf[..], KeyVersion::V3, alg, &public_params)?;
            prop_assert_eq!(secret_params, new_params);
        }
        #[test]
        #[ignore]
        fn params_roundtrip_v4(
            (alg, secret_params) in any::<PublicKeyAlgorithm>().prop_flat_map(|alg| (Just(alg), any_with::<PlainSecretParams>(alg)))
        ) {
            let mut buf = Vec::new();
            secret_params.to_writer(&mut buf, KeyVersion::V4)?;
            let public_params = PublicParams::try_from(&secret_params)?;
            let new_params = PlainSecretParams::try_from_buf(&mut &buf[..], KeyVersion::V4, alg, &public_params)?;
            prop_assert_eq!(secret_params, new_params);
        }

        #[test]
        #[ignore]
        fn params_roundtrip_v6(
            (alg, secret_params) in any::<PublicKeyAlgorithm>().prop_flat_map(|alg| (Just(alg), any_with::<PlainSecretParams>(alg)))
        ) {
            let mut buf = Vec::new();
            secret_params.to_writer(&mut buf, KeyVersion::V6)?;
            let public_params = PublicParams::try_from(&secret_params)?;
            let new_params = PlainSecretParams::try_from_buf(&mut &buf[..], KeyVersion::V6, alg, &public_params)?;
            prop_assert_eq!(secret_params, new_params);
        }
    }
}

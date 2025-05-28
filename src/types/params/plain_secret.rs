use std::{
    hash::Hasher,
    io::{self, BufRead},
};

use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, Bytes, BytesMut};
use hkdf::Hkdf;
use log::debug;
use sha2::Sha256;
use zeroize::{ZeroizeOnDrop, Zeroizing};

#[cfg(feature = "draft-pqc")]
use crate::crypto::{
    ml_dsa65_ed25519, ml_dsa87_ed448, ml_kem1024_x448, ml_kem768_x25519, slh_dsa_shake128f,
    slh_dsa_shake128s, slh_dsa_shake256s,
};
use crate::{
    composed::PlainSessionKey,
    crypto::{
        aead::AeadAlgorithm, checksum, dsa, ecc_curve::ECCCurve, ecdh, ecdsa, ed25519, ed448,
        elgamal, public_key::PublicKeyAlgorithm, rsa, sym::SymmetricKeyAlgorithm, x25519, x448,
        Decryptor,
    },
    errors::{bail, ensure, ensure_eq, unimplemented_err, unsupported_err, Result},
    parsing_reader::BufReadParsing,
    ser::Serialize,
    types::{EskType, PkeskBytes, PublicKeyTrait, PublicParams, *},
    util::TeeWriter,
};

#[derive(Clone, PartialEq, Eq, derive_more::Debug, ZeroizeOnDrop)]
pub enum PlainSecretParams {
    RSA(rsa::SecretKey),
    DSA(dsa::SecretKey),
    ECDSA(ecdsa::SecretKey),
    ECDH(ecdh::SecretKey),
    Ed25519(ed25519::SecretKey),
    Ed25519Legacy(ed25519::SecretKey),
    X25519(x25519::SecretKey),
    #[cfg(feature = "draft-pqc")]
    MlKem768X25519(ml_kem768_x25519::SecretKey),
    #[cfg(feature = "draft-pqc")]
    MlKem1024X448(ml_kem1024_x448::SecretKey),
    #[cfg(feature = "draft-pqc")]
    MlDsa65Ed25519(ml_dsa65_ed25519::SecretKey),
    #[cfg(feature = "draft-pqc")]
    MlDsa87Ed448(ml_dsa87_ed448::SecretKey),
    Elgamal(elgamal::SecretKey),
    X448(x448::SecretKey),
    Ed448(ed448::SecretKey),
    #[cfg(feature = "draft-pqc")]
    SlhDsaShake128s(slh_dsa_shake128s::SecretKey),
    #[cfg(feature = "draft-pqc")]
    SlhDsaShake128f(slh_dsa_shake128f::SecretKey),
    #[cfg(feature = "draft-pqc")]
    SlhDsaShake256s(slh_dsa_shake256s::SecretKey),
    Unknown {
        #[zeroize(skip)]
        alg: PublicKeyAlgorithm,
        #[debug("{}", hex::encode(data))]
        data: Zeroizing<Vec<u8>>,
        #[zeroize(skip)]
        #[debug("{}", hex::encode(pub_params))]
        pub_params: Bytes,
    },
}

pub(crate) fn pad_key<const SIZE: usize>(val: &[u8]) -> Result<[u8; SIZE]> {
    ensure!(val.len() <= SIZE, "invalid secret key size");

    let mut key = [0u8; SIZE];
    key[SIZE - val.len()..].copy_from_slice(val);
    Ok(key)
}

impl PlainSecretParams {
    /// Skips the checksum, because it already has been checked.
    pub fn try_from_reader_no_checksum<B: BufRead>(
        mut i: B,
        _version: KeyVersion,
        alg: PublicKeyAlgorithm,
        public_params: &PublicParams,
    ) -> Result<Self> {
        let params = Self::try_from_reader_inner(&mut i, alg, public_params)?;
        ensure!(
            !i.has_remaining()?,
            "failed to process full secret key material"
        );
        Ok(params)
    }

    fn try_from_reader_inner<B: BufRead>(
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
                let d = Mpi::try_from_reader(&mut i)?;
                let p = Mpi::try_from_reader(&mut i)?;
                let q = Mpi::try_from_reader(&mut i)?;
                let u = Mpi::try_from_reader(&mut i)?;

                let key = crate::crypto::rsa::SecretKey::try_from_mpi(pub_params, d, p, q, u)?;
                Self::RSA(key)
            }
            (PublicKeyAlgorithm::DSA, PublicParams::DSA(pub_params)) => {
                let secret = Mpi::try_from_reader(i)?;

                let key = crate::crypto::dsa::SecretKey::try_from_mpi(pub_params, secret)?;
                Self::DSA(key)
            }
            (PublicKeyAlgorithm::Elgamal, PublicParams::Elgamal(pub_params)) => {
                let x = Mpi::try_from_reader(i)?;
                ensure!(!pub_params.is_encrypt_only(), "inconsistent key state");
                let key = crate::crypto::elgamal::SecretKey::try_from_mpi(pub_params.clone(), x);
                Self::Elgamal(key)
            }
            (PublicKeyAlgorithm::ElgamalEncrypt, PublicParams::Elgamal(pub_params)) => {
                let x = Mpi::try_from_reader(i)?;
                ensure!(pub_params.is_encrypt_only(), "inconsistent key state");
                let key = crate::crypto::elgamal::SecretKey::try_from_mpi(pub_params.clone(), x);
                Self::Elgamal(key)
            }
            (PublicKeyAlgorithm::ECDH, PublicParams::ECDH(pub_params)) => {
                let secret = Mpi::try_from_reader(i)?;

                let key = crate::crypto::ecdh::SecretKey::try_from_mpi(pub_params, secret)?;
                Self::ECDH(key)
            }
            (PublicKeyAlgorithm::ECDSA, PublicParams::ECDSA(pub_params)) => {
                let secret = Mpi::try_from_reader(i)?;

                let key = crate::crypto::ecdsa::SecretKey::try_from_mpi(pub_params, secret)?;
                Self::ECDSA(key)
            }
            (PublicKeyAlgorithm::EdDSALegacy, PublicParams::EdDSALegacy(_pub_params)) => {
                let secret = Mpi::try_from_reader(i)?;

                const SIZE: usize = ECCCurve::Ed25519.secret_key_length();
                let secret = pad_key::<SIZE>(secret.as_ref())?;
                let key = crate::crypto::ed25519::SecretKey::try_from_bytes(
                    secret,
                    crate::crypto::ed25519::Mode::EdDSALegacy,
                )?;
                Self::Ed25519Legacy(key)
            }
            (PublicKeyAlgorithm::Ed25519, PublicParams::Ed25519(_pub_params)) => {
                let secret = i.read_array::<32>()?;
                let key = crate::crypto::ed25519::SecretKey::try_from_bytes(
                    secret,
                    crate::crypto::ed25519::Mode::Ed25519,
                )?;
                Self::Ed25519(key)
            }
            (PublicKeyAlgorithm::Ed448, PublicParams::Ed448(_pub_params)) => {
                let secret = i.read_array::<57>()?;
                let key = crate::crypto::ed448::SecretKey::try_from_bytes(secret)?;
                Self::Ed448(key)
            }
            (PublicKeyAlgorithm::X25519, PublicParams::X25519(_)) => {
                let secret = i.read_array::<32>()?;
                let key = crate::crypto::x25519::SecretKey::try_from_bytes(secret)?;
                Self::X25519(key)
            }
            (PublicKeyAlgorithm::X448, PublicParams::X448 { .. }) => {
                let s = i.read_array::<56>()?;
                let key = crate::crypto::x448::SecretKey::try_from_bytes(s)?;
                Self::X448(key)
            }
            #[cfg(feature = "draft-pqc")]
            (PublicKeyAlgorithm::MlKem768X25519, PublicParams::MlKem768X25519(_)) => {
                // X25519
                let x = i.read_array::<32>()?;

                // ML KEM
                let ml_kem = i.read_array::<64>()?;
                let key = crate::crypto::ml_kem768_x25519::SecretKey::try_from_bytes(x, ml_kem)?;
                Self::MlKem768X25519(key)
            }
            #[cfg(feature = "draft-pqc")]
            (PublicKeyAlgorithm::MlKem1024X448, PublicParams::MlKem1024X448(_)) => {
                // X448
                let x = i.read_array::<56>()?;

                // ML KEM
                let ml_kem = i.read_array::<64>()?;
                let key = crate::crypto::ml_kem1024_x448::SecretKey::try_from_bytes(x, ml_kem)?;
                Self::MlKem1024X448(key)
            }
            (
                alg,
                PublicParams::Unknown {
                    data: pub_params, ..
                },
            ) => {
                let data = Zeroizing::new(i.rest()?.to_vec());
                Self::Unknown {
                    alg,
                    data,
                    pub_params: pub_params.clone(),
                }
            }
            #[cfg(feature = "draft-pqc")]
            (PublicKeyAlgorithm::MlDsa65Ed25519, PublicParams::MlDsa65Ed25519(_)) => {
                // ed25519
                let ed = i.read_array::<32>()?;

                // ML DSA
                let ml_dsa = i.read_array::<32>()?;
                let key = crate::crypto::ml_dsa65_ed25519::SecretKey::try_from_bytes(ed, ml_dsa)?;
                Self::MlDsa65Ed25519(key)
            }
            #[cfg(feature = "draft-pqc")]
            (PublicKeyAlgorithm::MlDsa87Ed448, PublicParams::MlDsa87Ed448(_)) => {
                // ed448
                let ed = i.read_array::<57>()?;

                // ML DSA
                let ml_dsa_seed = i.read_array::<32>()?;
                let key =
                    crate::crypto::ml_dsa87_ed448::SecretKey::try_from_bytes(ed, ml_dsa_seed)?;
                Self::MlDsa87Ed448(key)
            }
            #[cfg(feature = "draft-pqc")]
            (PublicKeyAlgorithm::SlhDsaShake128s, PublicParams::SlhDsaShake128s(_)) => {
                let secret = i.read_array::<64>()?;
                let key = crate::crypto::slh_dsa_shake128s::SecretKey::try_from_bytes(secret)?;
                Self::SlhDsaShake128s(key)
            }
            #[cfg(feature = "draft-pqc")]
            (PublicKeyAlgorithm::SlhDsaShake128f, PublicParams::SlhDsaShake128f(_)) => {
                let secret = i.read_array::<64>()?;
                let key = crate::crypto::slh_dsa_shake128f::SecretKey::try_from_bytes(secret)?;
                Self::SlhDsaShake128f(key)
            }
            #[cfg(feature = "draft-pqc")]
            (PublicKeyAlgorithm::SlhDsaShake256s, PublicParams::SlhDsaShake256s(_)) => {
                let secret = i.read_array::<128>()?;
                let key = crate::crypto::slh_dsa_shake256s::SecretKey::try_from_bytes(secret)?;
                Self::SlhDsaShake256s(key)
            }

            (_, _) => {
                bail!("invalid combination {:?} - {:?}", alg, public_params);
            }
        };

        Ok(params)
    }

    pub fn try_from_reader<B: BufRead>(
        mut i: B,
        version: KeyVersion,
        alg: PublicKeyAlgorithm,
        public_params: &PublicParams,
    ) -> Result<Self> {
        let params = Self::try_from_reader_inner(&mut i, alg, public_params)?;
        if version == KeyVersion::V3 || version == KeyVersion::V4 {
            let checksum = i.read_array::<2>()?;
            params.compare_checksum_simple(&checksum)?;
            ensure!(
                !i.has_remaining()?,
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
        let checksum = checksum::calculate_sha1([&buf])?;
        Ok(checksum)
    }

    pub fn encrypt(
        &self,
        passphrase: &[u8],
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
                        let data = BytesMut::with_capacity(self.write_len_raw());
                        let mut writer = data.writer();
                        self.to_writer_raw(&mut writer)
                            .expect("preallocated vector");
                        let mut data = writer.into_inner();

                        let Some(secret_tag) = secret_tag else {
                            bail!("no secret_tag provided");
                        };

                        let (okm, ad) =
                            s2k_usage_aead(&key, secret_tag, pub_key, *sym_alg, *aead_mode)?;

                        // AEAD encrypt
                        aead_mode.encrypt_in_place(sym_alg, &okm, nonce, &ad, &mut data)?;

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
                    EcdhPublicParams::Brainpool256 { .. }
                    | EcdhPublicParams::Brainpool384 { .. }
                    | EcdhPublicParams::Brainpool512 { .. } => {
                        unsupported_err!("brainpool is not supported");
                    }
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
            #[cfg(feature = "draft-pqc")]
            (
                PlainSecretParams::MlKem768X25519(ref priv_key),
                PkeskBytes::MlKem768X25519 {
                    ecdh_ciphertext: ephemeral,
                    ml_kem_ciphertext,
                    session_key,
                    sym_alg,
                },
            ) => {
                // Recipient public key (32 bytes)
                let PublicParams::MlKem768X25519(params) = recipient.public_params() else {
                    bail!(
                        "Unexpected recipient public_params {:?} for ML KEM 768 X25519",
                        recipient.public_params()
                    );
                };

                let data = ml_kem768_x25519::EncryptionFields {
                    ecdh_ciphertext: ephemeral.to_owned(),
                    ml_kem_ciphertext,
                    ecdh_pub_key: &params.x25519_key,
                    ml_kem_pub_key: &params.ml_kem_key,
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
            #[cfg(feature = "draft-pqc")]
            (
                PlainSecretParams::MlKem1024X448(ref priv_key),
                PkeskBytes::MlKem1024X448 {
                    ecdh_ciphertext: ephemeral,
                    ml_kem_ciphertext,
                    session_key,
                    sym_alg,
                },
            ) => {
                // Recipient public key
                let PublicParams::MlKem1024X448(params) = recipient.public_params() else {
                    bail!(
                        "Unexpected recipient public_params {:?} for ML KEM 1024 X448",
                        recipient.public_params()
                    );
                };

                let data = ml_kem1024_x448::EncryptionFields {
                    ecdh_ciphertext: ephemeral,
                    ml_kem_ciphertext,
                    ecdh_pub_key: &params.x448_key,
                    ml_kem_pub_key: &params.ml_kem_key,
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
                    recipient_public: &params.key,
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
            (PlainSecretParams::Ed25519(_), _) => bail!("Ed25519 is only used for signing"),
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
                let checksum = decrypted_key[key_size + 1..key_size + 3]
                    .try_into()
                    .expect("fixed size");

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
                let checksum = decrypted_key[len - 2..].try_into().expect("fixed size");

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
                key.to_writer(writer)?;
            }
            PlainSecretParams::DSA(key) => {
                key.to_writer(writer)?;
            }
            PlainSecretParams::Elgamal(key) => {
                key.to_writer(writer)?;
            }
            PlainSecretParams::ECDSA(key) => {
                key.to_writer(writer)?;
            }
            PlainSecretParams::ECDH(key) => {
                key.to_writer(writer)?;
            }
            PlainSecretParams::X25519(key) => key.to_writer(writer)?,
            PlainSecretParams::Ed25519(key) => {
                key.to_writer(writer)?;
            }
            #[cfg(feature = "draft-pqc")]
            PlainSecretParams::MlKem768X25519(key) => {
                key.to_writer(writer)?;
            }
            #[cfg(feature = "draft-pqc")]
            PlainSecretParams::MlKem1024X448(key) => {
                key.to_writer(writer)?;
            }
            PlainSecretParams::Ed448(key) => {
                key.to_writer(writer)?;
            }
            PlainSecretParams::Ed25519Legacy(key) => {
                key.to_writer(writer)?;
            }
            PlainSecretParams::X448(key) => {
                key.to_writer(writer)?;
            }
            #[cfg(feature = "draft-pqc")]
            PlainSecretParams::MlDsa65Ed25519(key) => {
                key.to_writer(writer)?;
            }
            #[cfg(feature = "draft-pqc")]
            PlainSecretParams::MlDsa87Ed448(key) => {
                key.to_writer(writer)?;
            }
            #[cfg(feature = "draft-pqc")]
            PlainSecretParams::SlhDsaShake128s(key) => {
                key.to_writer(writer)?;
            }
            #[cfg(feature = "draft-pqc")]
            PlainSecretParams::SlhDsaShake128f(key) => {
                key.to_writer(writer)?;
            }
            #[cfg(feature = "draft-pqc")]
            PlainSecretParams::SlhDsaShake256s(key) => {
                key.to_writer(writer)?;
            }
            PlainSecretParams::Unknown { data, .. } => {
                writer.write_all(data)?;
            }
        }

        Ok(())
    }

    fn write_len_raw(&self) -> usize {
        match self {
            PlainSecretParams::RSA(key) => key.write_len(),
            PlainSecretParams::DSA(key) => key.write_len(),
            PlainSecretParams::Elgamal(key) => key.write_len(),
            PlainSecretParams::ECDSA(key) => key.write_len(),
            PlainSecretParams::ECDH(key) => key.write_len(),
            PlainSecretParams::Ed25519(key) => key.write_len(),
            PlainSecretParams::Ed25519Legacy(key) => key.write_len(),
            PlainSecretParams::X25519(key) => key.write_len(),
            PlainSecretParams::Ed448(key) => key.write_len(),
            PlainSecretParams::X448(key) => key.write_len(),
            #[cfg(feature = "draft-pqc")]
            PlainSecretParams::MlKem768X25519(key) => key.write_len(),
            #[cfg(feature = "draft-pqc")]
            PlainSecretParams::MlKem1024X448(key) => key.write_len(),
            #[cfg(feature = "draft-pqc")]
            PlainSecretParams::MlDsa65Ed25519(key) => key.write_len(),
            #[cfg(feature = "draft-pqc")]
            PlainSecretParams::MlDsa87Ed448(key) => key.write_len(),
            #[cfg(feature = "draft-pqc")]
            PlainSecretParams::SlhDsaShake128s(key) => key.write_len(),
            #[cfg(feature = "draft-pqc")]
            PlainSecretParams::SlhDsaShake128f(key) => key.write_len(),
            #[cfg(feature = "draft-pqc")]
            PlainSecretParams::SlhDsaShake256s(key) => key.write_len(),
            PlainSecretParams::Unknown { data, .. } => data.len(),
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
    use proptest::prelude::*;

    use super::*;
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
                PublicKeyAlgorithm::EdDSALegacy => any::<ed25519::SecretKey>()
                    .prop_map(|mut key| {
                        key.mode = ed25519::Mode::EdDSALegacy;
                        PlainSecretParams::Ed25519Legacy(key)
                    })
                    .boxed(),
                PublicKeyAlgorithm::Ed25519 => any::<ed25519::SecretKey>()
                    .prop_map(|mut key| {
                        key.mode = ed25519::Mode::Ed25519;
                        PlainSecretParams::Ed25519(key)
                    })
                    .boxed(),
                PublicKeyAlgorithm::X25519 => any::<x25519::SecretKey>()
                    .prop_map(PlainSecretParams::X25519)
                    .boxed(),
                PublicKeyAlgorithm::X448 => any::<crate::crypto::x448::SecretKey>()
                    .prop_map(PlainSecretParams::X448)
                    .boxed(),
                PublicKeyAlgorithm::Ed448 => any::<crate::crypto::ed448::SecretKey>()
                    .prop_map(PlainSecretParams::Ed448)
                    .boxed(),
                #[cfg(feature = "draft-pqc")]
                PublicKeyAlgorithm::MlKem768X25519 => {
                    any::<crate::crypto::ml_kem768_x25519::SecretKey>()
                        .prop_map(PlainSecretParams::MlKem768X25519)
                        .boxed()
                }
                #[cfg(feature = "draft-pqc")]
                PublicKeyAlgorithm::MlKem1024X448 => {
                    any::<crate::crypto::ml_kem1024_x448::SecretKey>()
                        .prop_map(PlainSecretParams::MlKem1024X448)
                        .boxed()
                }
                #[cfg(feature = "draft-pqc")]
                PublicKeyAlgorithm::MlDsa65Ed25519 => {
                    any::<crate::crypto::ml_dsa65_ed25519::SecretKey>()
                        .prop_map(PlainSecretParams::MlDsa65Ed25519)
                        .boxed()
                }
                #[cfg(feature = "draft-pqc")]
                PublicKeyAlgorithm::MlDsa87Ed448 => {
                    any::<crate::crypto::ml_dsa87_ed448::SecretKey>()
                        .prop_map(PlainSecretParams::MlDsa87Ed448)
                        .boxed()
                }
                #[cfg(feature = "draft-pqc")]
                PublicKeyAlgorithm::SlhDsaShake128s => {
                    any::<crate::crypto::slh_dsa_shake128s::SecretKey>()
                        .prop_map(PlainSecretParams::SlhDsaShake128s)
                        .boxed()
                }
                #[cfg(feature = "draft-pqc")]
                PublicKeyAlgorithm::SlhDsaShake128f => {
                    any::<crate::crypto::slh_dsa_shake128f::SecretKey>()
                        .prop_map(PlainSecretParams::SlhDsaShake128f)
                        .boxed()
                }
                #[cfg(feature = "draft-pqc")]
                PublicKeyAlgorithm::SlhDsaShake256s => {
                    any::<crate::crypto::slh_dsa_shake256s::SecretKey>()
                        .prop_map(PlainSecretParams::SlhDsaShake256s)
                        .boxed()
                }
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
            let new_params = PlainSecretParams::try_from_reader(&mut &buf[..], KeyVersion::V3, alg, &public_params)?;
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
            let new_params = PlainSecretParams::try_from_reader(&mut &buf[..], KeyVersion::V4, alg, &public_params)?;
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
            let new_params = PlainSecretParams::try_from_reader(&mut &buf[..], KeyVersion::V6, alg, &public_params)?;
            prop_assert_eq!(secret_params, new_params);
        }
    }
}

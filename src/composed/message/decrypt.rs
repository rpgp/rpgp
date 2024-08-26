use log::debug;

use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::errors::Result;
use crate::packet::SymKeyEncryptedSessionKey;
use crate::types::{EskType, Mpi, SecretKeyRepr, SecretKeyTrait};

/// Decrypts session key using secret key.
pub fn decrypt_session_key<F, L>(
    locked_key: &L,
    key_pw: F,
    values: &EskBytes,
    typ: EskType,
) -> Result<PlainSessionKey>
where
    F: FnOnce() -> String,
    L: SecretKeyTrait<Unlocked = SecretKeyRepr>,
{
    debug!("decrypt session key");

    locked_key.unlock(key_pw, |priv_key| priv_key.decrypt(values, typ, locked_key))
}

/// Values comprising the encrypted session key
///
/// FIXME: extend for algorithm specific values? (and/or v3 vs. v6)
/// FIXME: naming?
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EskBytes {
    Rsa {
        mpi: Mpi,
    },
    Elgamal {
        first: Mpi,
        second: Mpi,
    },
    Ecdh {
        public_point: Mpi,
        encrypted_session_key: Vec<u8>,
    },
    X25519 {
        // Ephemeral X25519 public key (32 bytes).
        ephemeral: [u8; 32],

        // Encrypted and wrapped session key.
        session_key: Vec<u8>,

        // Set for v3 only (the sym_algo is not encrypted with the session key for X25519)
        sym_alg: Option<SymmetricKeyAlgorithm>,
    },
    X448 {
        // Ephemeral X448 public key (56 bytes).
        ephemeral: [u8; 56],

        // Encrypted and wrapped session key.
        session_key: Vec<u8>,

        // Set for v3 only (the sym_algo is not encrypted with the session key for X448)
        sym_alg: Option<SymmetricKeyAlgorithm>,
    },
    Other,
}

/// Decrypted session key.
///
/// A v3/v4 session key can be used with a SED, or a v1 SEIPD.
/// A v6 session key can only be used with a v2 SEIPD.
///
/// https://www.rfc-editor.org/rfc/rfc9580.html#name-packet-versions-in-encrypte
#[derive(derive_more::Debug, Clone, PartialEq, Eq)]
pub enum PlainSessionKey {
    /// A session key from a v3 PKESK or a v4 SKESK
    ///
    /// (Note: for historical reasons, the OpenPGP format doesn't specify a v4 PKESK or a V3 SKESK)
    V3_4 {
        sym_alg: SymmetricKeyAlgorithm,
        #[debug("..")]
        key: Vec<u8>,
    },

    V5 {
        #[debug("..")]
        key: Vec<u8>,
    },

    /// A session key from a v6 PKESK or a v6 SKESK
    V6 {
        #[debug("..")]
        key: Vec<u8>,
    },
}

/// Decrypts session key from SKESK packet.
///
/// Returns decrypted or derived session key
/// and symmetric algorithm of the key.
pub fn decrypt_session_key_with_password<F>(
    packet: &SymKeyEncryptedSessionKey,
    msg_pw: F,
) -> Result<PlainSessionKey>
where
    F: FnOnce() -> String,
{
    debug!("decrypt session key with password");

    let packet_algorithm = packet.sym_algorithm();
    ensure!(
        packet_algorithm != SymmetricKeyAlgorithm::Plaintext,
        "SKESK packet encryption algorithm cannot be plaintext"
    );

    let key = packet
        .s2k()
        .derive_key(&msg_pw(), packet_algorithm.key_size())?;

    debug!("derived key: {}", hex::encode(&key));
    if packet.encrypted_key().is_none() {
        // There is no encrypted session key.
        //
        // S2K-derived key is the session key.
        return Ok(PlainSessionKey::V3_4 {
            key,
            sym_alg: packet_algorithm,
        });
    }

    let decrypted_key = packet.decrypt(&key)?;

    Ok(decrypted_key)
}

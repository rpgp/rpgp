use log::debug;

use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::errors::Result;
use crate::packet::SymKeyEncryptedSessionKey;
use crate::types::{EskType, PkeskBytes, SecretKeyRepr, SecretKeyTrait};

/// Decrypts session key using secret key.
pub fn decrypt_session_key<F, L>(
    locked_key: &L,
    key_pw: F,
    values: &PkeskBytes,
    typ: EskType,
) -> Result<PlainSessionKey>
where
    F: FnOnce() -> String,
    L: SecretKeyTrait<Unlocked = SecretKeyRepr>,
{
    debug!("decrypt session key");

    locked_key.unlock(key_pw, |priv_key| priv_key.decrypt(values, typ, locked_key))
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

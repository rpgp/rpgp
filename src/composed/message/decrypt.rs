use log::debug;

use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::errors::Result;
use crate::packet::SymKeyEncryptedSessionKey;
use crate::types::{Mpi, SecretKeyRepr, SecretKeyTrait};

/// Decrypts session key using secret key.
pub fn decrypt_session_key<F, L>(locked_key: &L, key_pw: F, mpis: &[Mpi]) -> Result<PlainSessionKey>
where
    F: FnOnce() -> String,
    L: SecretKeyTrait<Unlocked = SecretKeyRepr>,
{
    debug!("decrypt session key");

    locked_key.unlock(key_pw, |priv_key| {
        let (key, sym_alg) = priv_key.decrypt(mpis, &locked_key.fingerprint())?;
        // TODO: handle other versions
        Ok(PlainSessionKey::V4 { key, sym_alg })
    })
}

/// Decrypted session key.
#[derive(derive_more::Debug, Clone, PartialEq, Eq)]
pub enum PlainSessionKey {
    V4 {
        sym_alg: SymmetricKeyAlgorithm,
        #[debug("{}", hex::encode(key))]
        key: Vec<u8>,
    },
    V5 {
        #[debug("{}", hex::encode(key))]
        key: Vec<u8>,
    },
    V6 {
        #[debug("{}", hex::encode(key))]
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
        return Ok(PlainSessionKey::V4 {
            key,
            sym_alg: packet_algorithm,
        });
    }

    let decrypted_key = packet.decrypt(&key)?;

    Ok(decrypted_key)
}

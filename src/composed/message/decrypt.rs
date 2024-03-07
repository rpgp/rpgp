use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::crypto::{checksum, ecdh, rsa};
use crate::errors::Result;
use crate::packet::SymKeyEncryptedSessionKey;
use crate::types::{KeyTrait, Mpi, SecretKeyRepr, SecretKeyTrait};

/// Decrypts session key using secret key.
pub fn decrypt_session_key<F>(
    locked_key: &(impl SecretKeyTrait + KeyTrait),
    key_pw: F,
    mpis: &[Mpi],
) -> Result<(Vec<u8>, SymmetricKeyAlgorithm)>
where
    F: FnOnce() -> String,
{
    debug!("decrypting session key");

    let mut key: Vec<u8> = Vec::new();
    let mut alg: Option<SymmetricKeyAlgorithm> = None;
    locked_key.unlock(key_pw, |priv_key| {
        let decrypted_key = match *priv_key {
            SecretKeyRepr::RSA(ref priv_key) => {
                rsa::decrypt(priv_key, mpis, &locked_key.fingerprint())?
            }
            SecretKeyRepr::DSA(_) => bail!("DSA is only used for signing"),
            SecretKeyRepr::ECDSA(_) => bail!("ECDSA is only used for signing"),
            SecretKeyRepr::ECDH(ref priv_key) => {
                ecdh::decrypt(priv_key, mpis, &locked_key.fingerprint())?
            }
            SecretKeyRepr::EdDSA(_) => unimplemented_err!("EdDSA"),
        };

        let session_key_algorithm = SymmetricKeyAlgorithm::from(decrypted_key[0]);
        ensure!(
            session_key_algorithm != SymmetricKeyAlgorithm::Plaintext,
            "session key algorithm cannot be plaintext"
        );
        alg = Some(session_key_algorithm);
        debug!("alg: {:?}", alg);

        let (k, checksum) = match *priv_key {
            SecretKeyRepr::ECDH(_) => {
                let dec_len = decrypted_key.len();
                (
                    &decrypted_key[1..dec_len - 2],
                    &decrypted_key[dec_len - 2..],
                )
            }
            _ => {
                let key_size = session_key_algorithm.key_size();
                (
                    &decrypted_key[1..=key_size],
                    &decrypted_key[key_size + 1..key_size + 3],
                )
            }
        };

        key = k.to_vec();
        checksum::simple(checksum, k)?;

        Ok(())
    })?;

    Ok((key, alg.expect("failed to unlock")))
}

/// Decrypts session key from SKESK packet.
///
/// Returns decrypted or derived session key
/// and symmetric algorithm of the key.
pub fn decrypt_session_key_with_password<F>(
    packet: &SymKeyEncryptedSessionKey,
    msg_pw: F,
) -> Result<(Vec<u8>, SymmetricKeyAlgorithm)>
where
    F: FnOnce() -> String,
{
    debug!("decrypting session key");

    let packet_algorithm = packet.sym_algorithm();
    ensure!(
        packet_algorithm != SymmetricKeyAlgorithm::Plaintext,
        "SKESK packet encryption algorithm cannot be plaintext"
    );

    let key = packet
        .s2k()
        .derive_key(&msg_pw(), packet_algorithm.key_size())?;

    let Some(ref encrypted_key) = packet.encrypted_key() else {
        // There is no encrypted session key.
        //
        // S2K-derived key is the session key.
        return Ok((key, packet_algorithm));
    };

    let mut decrypted_key = encrypted_key.to_vec();
    // packet.sym_algorithm().decrypt(&key, &mut decrypted_key)?;
    let iv = vec![0u8; packet.sym_algorithm().block_size()];
    packet_algorithm.decrypt_with_iv_regular(&key, &iv, &mut decrypted_key)?;

    let session_key_algorithm = SymmetricKeyAlgorithm::from(decrypted_key[0]);
    ensure!(
        session_key_algorithm != SymmetricKeyAlgorithm::Plaintext,
        "session key algorithm cannot be plaintext"
    );

    Ok((decrypted_key[1..].to_vec(), session_key_algorithm))
}

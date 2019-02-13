use block_padding::{Padding, Pkcs7};
use hex;
use x25519_dalek::x25519;

use crypto::aes_kw;
use crypto::hash::HashAlgorithm;
use crypto::kdf::kdf;
use crypto::public_key::PublicKeyAlgorithm;
use crypto::sym::SymmetricKeyAlgorithm;
use errors::Result;
use types::ECDHSecretKey;

// 20 octets representing "Anonymous Sender    ".
const ANON_SENDER: [u8; 20] = [
    0x41, 0x6E, 0x6F, 0x6E, 0x79, 0x6D, 0x6F, 0x75, 0x73, 0x20, 0x53, 0x65, 0x6E, 0x64, 0x65, 0x72,
    0x20, 0x20, 0x20, 0x20,
];

/// Build param for ECDH algorithm (as defined in RFC 6637)
/// https://tools.ietf.org/html/rfc6637#section-8
pub fn build_ecdh_param(
    oid: &[u8],
    alg_sym: SymmetricKeyAlgorithm,
    hash: HashAlgorithm,
    fingerprint: &[u8],
) -> Vec<u8> {
    let kdf_params = vec![
        0x03, // length of the following fields
        0x01, // reserved for future extensions
        hash as u8,
        alg_sym as u8,
    ];

    info!("kdf params: {}", hex::encode(&kdf_params));
    let oid_len = [oid.len() as u8];

    let values: Vec<&[u8]> = vec![
        &oid_len,
        oid,
        &[PublicKeyAlgorithm::ECDH as u8],
        &kdf_params,
        &ANON_SENDER[..],
        fingerprint,
    ];

    values.concat()
}

pub fn decrypt_ecdh(
    priv_key: &ECDHSecretKey,
    mpis: &[Vec<u8>],
    fingerprint: &[u8],
) -> Result<Vec<u8>> {
    info!("ECDH decrypt");
    info!("oid {}", hex::encode(&priv_key.oid));
    info!("cipher {}", priv_key.alg_sym as u8);
    info!("hash: {}", priv_key.hash as u8);
    info!("fingerprint: {}", hex::encode(fingerprint));

    let param = build_ecdh_param(&priv_key.oid, priv_key.alg_sym, priv_key.hash, fingerprint);
    info!("ecdh kdf param: {}", hex::encode(&param));

    // 33 = 0x40 + 32bits
    ensure_eq!(mpis[0].len(), 33, "invalid public point");

    // public part of the ephemeral key (removes 0x40 prefix)
    let ephemeral_public_key = &mpis[0][1..];

    // encrypted and wrapped value derived from the session key
    let encrypted_session_key = &mpis[1];

    // private key of the recipient.
    let private_key = &priv_key.secret[..];

    // create montgomery point
    let mut ephemeral_public_key_arr = [0u8; 32];
    ephemeral_public_key_arr[..].copy_from_slice(ephemeral_public_key);

    // create scalar and reverse to little endian
    let private_key_le = private_key.iter().rev().cloned().collect::<Vec<u8>>();
    let mut private_key_arr = [0u8; 32];
    private_key_arr[..].copy_from_slice(&private_key_le);

    // derive shared secret
    // let shared_secret =
    // EphemeralSecret::diffie_hellman(&private_key_arr, &ephemeral_public_key_arr);
    let shared_secret = x25519(private_key_arr, ephemeral_public_key_arr);

    // Perform key derivation
    let z = kdf(
        priv_key.hash,
        &shared_secret,
        priv_key.alg_sym.key_size(),
        &param,
    )?;

    // Peform AES Key Unwrap
    let decrypted_key_padded = aes_kw::unwrap(&z, encrypted_session_key)?;

    // PKCS5 unpadding (PKCS5 is PKCS7 with a blocksize of 8)
    let decrypted_key = Pkcs7::unpad(&decrypted_key_padded)?;

    Ok(decrypted_key.to_vec())
}

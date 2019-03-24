use std::ffi::{CStr, CString};
use std::io::Cursor;
use std::slice;

use libc::c_char;
use pgp::composed::{
    Deserializable, KeyType, SecretKeyParamsBuilder, SignedSecretKey, SubkeyParamsBuilder,
};
use pgp::crypto::{HashAlgorithm, SymmetricKeyAlgorithm};
use pgp::errors::Result;
use pgp::ser::Serialize;
use pgp::types::{CompressionAlgorithm, KeyTrait, SecretKeyTrait};
use smallvec::smallvec;

use crate::cvec::cvec;
use crate::signed_public_key;

pub type signed_secret_key = SignedSecretKey;

/// Generates a new RSA key.
#[no_mangle]
pub unsafe extern "C" fn rpgp_create_rsa_skey(
    bits: u32,
    user_id: *const c_char,
) -> *mut signed_secret_key {
    assert!(!user_id.is_null());

    let user_id = CStr::from_ptr(user_id);
    let user_id_str = try_ffi!(user_id.to_str(), "invalid user id");

    let key = try_ffi!(
        create_key(KeyType::Rsa(bits), KeyType::Rsa(bits), user_id_str),
        "failed to generate key"
    );

    Box::into_raw(Box::new(key))
}

/// Generates a new x25519 key.
#[no_mangle]
pub unsafe extern "C" fn rpgp_create_x25519_skey(user_id: *const c_char) -> *mut signed_secret_key {
    assert!(!user_id.is_null());

    let user_id = CStr::from_ptr(user_id);
    let user_id_str = try_ffi!(user_id.to_str(), "invalid user id");
    let key = try_ffi!(
        create_key(KeyType::EdDSA, KeyType::ECDH, user_id_str),
        "failed to generate key"
    );

    Box::into_raw(Box::new(key))
}

/// Serialize a secret key into its byte representation.
#[no_mangle]
pub unsafe extern "C" fn rpgp_skey_to_bytes(skey_ptr: *mut signed_secret_key) -> *mut cvec {
    assert!(!skey_ptr.is_null());

    let skey = &*skey_ptr;

    let mut res = Vec::new();
    try_ffi!(skey.to_writer(&mut res), "failed to serialize key");

    Box::into_raw(Box::new(res.into()))
}

/// Get the signed public key matching the given private key. Only works for non password protected keys.
#[no_mangle]
pub unsafe extern "C" fn rpgp_skey_public_key(
    skey_ptr: *mut signed_secret_key,
) -> *mut signed_public_key {
    assert!(!skey_ptr.is_null());

    let skey = &*skey_ptr;

    let pkey = skey.public_key();
    let signed_pkey = try_ffi!(pkey.sign(&skey, || "".into()), "failed to sign key");

    Box::into_raw(Box::new(signed_pkey))
}

/// Returns the KeyID for the passed in key.
#[no_mangle]
pub unsafe extern "C" fn rpgp_skey_key_id(skey_ptr: *mut signed_secret_key) -> *mut c_char {
    assert!(!skey_ptr.is_null());

    let key = &*skey_ptr;
    let id = try_ffi!(
        CString::new(hex::encode(&key.key_id())),
        "failed to allocate string"
    );

    id.into_raw()
}

/// Free the memory of a secret key.
#[no_mangle]
pub unsafe extern "C" fn rpgp_skey_drop(skey_ptr: *mut signed_secret_key) {
    assert!(!skey_ptr.is_null());

    let _skey = &*skey_ptr;
    // Drop
}

/// Creates an in-memory representation of a Secret PGP key, based on the serialized bytes given.
#[no_mangle]
pub unsafe extern "C" fn rpgp_skey_from_bytes(
    raw: *const u8,
    len: libc::size_t,
) -> *mut signed_secret_key {
    assert!(!raw.is_null());
    assert!(len > 0);

    let bytes = slice::from_raw_parts(raw, len);
    let key = try_ffi!(
        SignedSecretKey::from_bytes(Cursor::new(bytes)),
        "invalid secret key"
    );
    try_ffi!(key.verify(), "failed to verify key");

    Box::into_raw(Box::new(key))
}

fn create_key(typ: KeyType, sub_typ: KeyType, user_id: &str) -> Result<SignedSecretKey> {
    let key_params = SecretKeyParamsBuilder::default()
        .key_type(typ)
        .can_create_certificates(true)
        .can_sign(true)
        .primary_user_id(user_id.into())
        .passphrase(None)
        .preferred_symmetric_algorithms(smallvec![
            SymmetricKeyAlgorithm::AES256,
            SymmetricKeyAlgorithm::AES192,
            SymmetricKeyAlgorithm::AES128,
        ])
        .preferred_hash_algorithms(smallvec![
            HashAlgorithm::SHA2_256,
            HashAlgorithm::SHA2_384,
            HashAlgorithm::SHA2_512,
            HashAlgorithm::SHA2_224,
            HashAlgorithm::SHA1,
        ])
        .preferred_compression_algorithms(smallvec![
            CompressionAlgorithm::ZLIB,
            CompressionAlgorithm::ZIP,
        ])
        .subkey(
            SubkeyParamsBuilder::default()
                .key_type(sub_typ)
                .can_encrypt(true)
                .passphrase(None)
                .build()
                .unwrap(),
        )
        .build()?;

    let key = key_params.generate()?;

    key.sign(|| "".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;
    use std::ffi::CStr;
    use std::slice;

    use pgp::composed::{Deserializable, SignedPublicKey, SignedSecretKey};

    #[test]
    fn test_keygen_rsa() {
        let user_id = CStr::from_bytes_with_nul(b"<hello@world.com>\0").unwrap();

        unsafe {
            /* Create the actual key */
            let skey = rpgp_create_rsa_skey(2048, user_id.as_ptr());

            /* Serialize secret key into bytes */
            let skey_bytes = rpgp_skey_to_bytes(skey);

            /* Get the public key */
            let pkey = rpgp_skey_public_key(skey);

            /* Serialize public key into bytes */
            let pkey_bytes = rpgp_pkey_to_bytes(pkey);

            let skey_bytes_vec =
                slice::from_raw_parts(rpgp_cvec_data(skey_bytes), rpgp_cvec_len(skey_bytes));
            let skey_back =
                SignedSecretKey::from_bytes(skey_bytes_vec).expect("invalid secret key");
            assert_eq!(&*skey, &skey_back);

            let pkey_bytes_vec =
                slice::from_raw_parts(rpgp_cvec_data(pkey_bytes), rpgp_cvec_len(pkey_bytes));
            let pkey_back =
                SignedPublicKey::from_bytes(pkey_bytes_vec).expect("invalid public key");
            assert_eq!(&*pkey, &pkey_back);

            /* cleanup */
            rpgp_skey_drop(skey);
            rpgp_cvec_drop(skey_bytes);
            rpgp_pkey_drop(pkey);
            rpgp_cvec_drop(pkey_bytes);
        }
    }
}

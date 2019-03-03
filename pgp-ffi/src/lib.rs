#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

extern crate hex;
extern crate libc;
#[macro_use]
extern crate pgp;
extern crate failure;

use std::ffi::{CStr, CString};
use std::io::Cursor;
use std::mem::transmute;
use std::os::raw::c_char;
use std::slice::from_raw_parts;

use pgp::composed::{
    from_armor_many, from_bytes_many, Deserializable, KeyType, Message, PublicOrSecret,
    SecretKeyParamsBuilder, SignedPublicKey, SignedSecretKey, SubkeyParamsBuilder,
};
use pgp::crypto::{HashAlgorithm, SymmetricKeyAlgorithm};
use pgp::errors::Result;
use pgp::ser::Serialize;
use pgp::types::{CompressionAlgorithm, KeyTrait, SecretKeyTrait};

pub type signed_secret_key = SignedSecretKey;
pub type signed_public_key = SignedPublicKey;
pub type public_or_secret_key = PublicOrSecret;
pub type message = Message;

mod errors;
pub use errors::*;

macro_rules! try_ffi {
    ($e:expr, $fmt:expr) => {
        match $e {
            Ok(v) => v,
            Err(err) => {
                update_last_error(err.into());
                return std::ptr::null_mut();
            }
        }
    };
}

/// Generates a new RSA key.
#[no_mangle]
pub unsafe extern "C" fn rpgp_create_rsa_skey(
    bits: u32,
    user_id: *const c_char,
) -> *mut signed_secret_key {
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
    let skey = &*skey_ptr;

    let pkey = skey.public_key();
    let signed_pkey = try_ffi!(pkey.sign(&skey, || "".into()), "failed to sign key");

    Box::into_raw(Box::new(signed_pkey))
}

/// Returns the KeyID for the passed in key.
#[no_mangle]
pub unsafe extern "C" fn rpgp_skey_key_id(ptr: *mut signed_secret_key) -> *mut c_char {
    let key = &*ptr;
    let id = try_ffi!(
        CString::new(hex::encode(&key.key_id())),
        "failed to allocate string"
    );

    id.into_raw()
}

/// Free the memory of a secret key.
#[no_mangle]
pub unsafe extern "C" fn rpgp_skey_drop(skey_ptr: *mut signed_secret_key) {
    let _skey: Box<signed_secret_key> = transmute(skey_ptr);
    // Drop
}

/// Creates an in-memory representation of a Secret PGP key, based on the serialized bytes given.
#[no_mangle]
pub unsafe extern "C" fn rpgp_skey_from_bytes(
    raw: *const u8,
    len: libc::size_t,
) -> *mut signed_secret_key {
    let bytes = from_raw_parts(raw, len);
    let key = try_ffi!(
        SignedSecretKey::from_bytes(Cursor::new(bytes)),
        "invalid secret key"
    );
    try_ffi!(key.verify(), "failed to verify key");

    Box::into_raw(Box::new(key))
}

/// Creates an in-memory representation of a Public PGP key, based on the serialized bytes given.
#[no_mangle]
pub unsafe extern "C" fn rpgp_pkey_from_bytes(
    raw: *const u8,
    len: libc::size_t,
) -> *mut signed_public_key {
    let bytes = from_raw_parts(raw, len);
    let key = try_ffi!(
        SignedPublicKey::from_bytes(Cursor::new(bytes)),
        "invalid public key"
    );

    try_ffi!(key.verify(), "failed to verify key");

    Box::into_raw(Box::new(key))
}

#[no_mangle]
pub unsafe extern "C" fn rpgp_pkey_to_bytes(pkey_ptr: *mut signed_public_key) -> *mut cvec {
    let pkey = &*pkey_ptr;

    let mut res = Vec::new();
    try_ffi!(pkey.to_writer(&mut res), "failed to serialize key");

    Box::into_raw(Box::new(res.into()))
}

/// Returns the KeyID for the passed in key.
#[no_mangle]
pub unsafe extern "C" fn rpgp_pkey_key_id(ptr: *mut signed_public_key) -> *mut c_char {
    let key = &*ptr;
    let id = try_ffi!(
        CString::new(hex::encode(&key.key_id())),
        "failed to allocate string"
    );

    id.into_raw()
}

#[no_mangle]
pub unsafe extern "C" fn rpgp_pkey_drop(pkey_ptr: *mut signed_public_key) {
    let _pkey: Box<signed_public_key> = transmute(pkey_ptr);
    // Drop
}

/// Represents a vector.
/// Has to deallocated using [rpgp_cvec_drop], otherwise leaks memory.
#[repr(C)]
#[derive(Debug)]
pub struct cvec {
    data: *mut u8,
    len: libc::size_t,
}

impl PartialEq for cvec {
    fn eq(&self, other: &cvec) -> bool {
        if self.len != other.len {
            return false;
        }

        unsafe { from_raw_parts(self.data, self.len) == from_raw_parts(other.data, other.len) }
    }
}

impl Eq for cvec {}

impl Into<cvec> for Vec<u8> {
    fn into(mut self) -> cvec {
        self.shrink_to_fit();
        assert!(self.len() == self.capacity());

        let res = cvec {
            data: self.as_mut_ptr(),
            len: self.len() as libc::size_t,
        };

        // prevent deallocation in Rust
        std::mem::forget(self);
        res
    }
}

impl Into<Vec<u8>> for cvec {
    fn into(self) -> Vec<u8> {
        unsafe { Vec::from_raw_parts(self.data, self.len, self.len) }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rpgp_cvec_len(cvec_ptr: *mut cvec) -> libc::size_t {
    let cvec = &*cvec_ptr;
    cvec.len
}

#[no_mangle]
pub unsafe extern "C" fn rpgp_cvec_data(cvec_ptr: *mut cvec) -> *const u8 {
    let cvec = &*cvec_ptr;
    cvec.data
}

#[no_mangle]
pub unsafe extern "C" fn rpgp_cvec_drop(cvec_ptr: *mut cvec) {
    let v = &*cvec_ptr;
    let _ = Vec::from_raw_parts(v.data, v.len, v.len);
    // Drop
}

fn create_key(typ: KeyType, sub_typ: KeyType, user_id: &str) -> Result<SignedSecretKey> {
    let key_params = SecretKeyParamsBuilder::default()
        .key_type(typ)
        .can_create_certificates(true)
        .can_sign(true)
        .primary_user_id(user_id.into())
        .passphrase(None)
        .preferred_symmetric_algorithms(vec![
            SymmetricKeyAlgorithm::AES256,
            SymmetricKeyAlgorithm::AES192,
            SymmetricKeyAlgorithm::AES128,
        ])
        .preferred_hash_algorithms(vec![
            HashAlgorithm::SHA2_256,
            HashAlgorithm::SHA2_384,
            HashAlgorithm::SHA2_512,
            HashAlgorithm::SHA2_224,
            HashAlgorithm::SHA1,
        ])
        .preferred_compression_algorithms(vec![
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

/// Creates an in-memory representation of a PGP key, based on the armor file given.
/// The returned pointer should be stored, and reused when calling methods "on" this key.
/// When done with it [rpgp_key_drop] should be called, to free the memory.
#[no_mangle]
pub unsafe extern "C" fn rpgp_key_from_armor(
    raw: *const u8,
    len: libc::size_t,
) -> *mut public_or_secret_key {
    let bytes = from_raw_parts(raw, len);
    let mut keys = try_ffi!(from_armor_many(Cursor::new(bytes)), "failed to parse");

    let key = try_ffi!(
        try_ffi!(
            keys.nth(0).ok_or_else(|| format_err!("no valid key found")),
            "failed to parse key"
        ),
        "failed to parse key"
    );

    try_ffi!(key.verify(), "failed to verify key");

    Box::into_raw(Box::new(key))
}

/// Creates an in-memory representation of a PGP key, based on the serialized bytes given.
#[no_mangle]
pub unsafe extern "C" fn rpgp_key_from_bytes(
    raw: *const u8,
    len: libc::size_t,
) -> *mut public_or_secret_key {
    let bytes = from_raw_parts(raw, len);
    let mut keys = from_bytes_many(Cursor::new(bytes));

    let key = try_ffi!(
        try_ffi!(
            keys.nth(0).ok_or_else(|| format_err!("no valid key found")),
            "failed to parse key"
        ),
        "failed to parse key"
    );

    try_ffi!(key.verify(), "failed to verify key");

    Box::into_raw(Box::new(key))
}

/// Returns the KeyID for the passed in key. The caller is responsible to call [rpgp_string_drop] with the returned memory, to free it.
#[no_mangle]
pub unsafe extern "C" fn rpgp_key_id(ptr: *mut public_or_secret_key) -> *mut c_char {
    let key = &*ptr;
    let id = try_ffi!(
        CString::new(hex::encode(&key.key_id())),
        "failed to allocate string"
    );

    id.into_raw()
}

/// Returns the Fingerprint for the passed in key. The caller is responsible to call [rpgp_cvec_drop] with the returned memory, to free it.
#[no_mangle]
pub unsafe extern "C" fn rpgp_key_fingerprint(ptr: *mut public_or_secret_key) -> *mut cvec {
    let key = &*ptr;
    let fingerprint = key.fingerprint();

    Box::into_raw(Box::new(fingerprint.into()))
}

/// Returns `true` if this key is a public key, false otherwise.
#[no_mangle]
pub unsafe extern "C" fn rpgp_key_is_public(ptr: *mut public_or_secret_key) -> bool {
    let key = &*ptr;

    key.is_public()
}

/// Returns `true` if this key is a secret key, false otherwise.
#[no_mangle]
pub unsafe extern "C" fn rpgp_key_is_secret(ptr: *mut public_or_secret_key) -> bool {
    let key = &*ptr;

    key.is_secret()
}

/// Frees the memory of the passed in key, making the pointer invalid after this method was called.
#[no_mangle]
pub unsafe extern "C" fn rpgp_key_drop(ptr: *mut public_or_secret_key) {
    let _key: Box<PublicOrSecret> = transmute(ptr);
    // Drop
}

/// Free string, that was created by rpgp.
#[no_mangle]
pub unsafe extern "C" fn rpgp_string_drop(p: *mut c_char) {
    let _ = CString::from_raw(p);
    // Drop
}

#[no_mangle]
pub unsafe extern "C" fn rpgp_msg_from_armor(
    msg_ptr: *const u8,
    msg_len: libc::size_t,
) -> *mut message {
    let enc_msg = from_raw_parts(msg_ptr, msg_len);

    let msg = try_ffi!(
        Message::from_armor_single(Cursor::new(enc_msg)),
        "invalid message"
    );

    Box::into_raw(Box::new(msg))
}

#[no_mangle]
pub unsafe extern "C" fn rpgp_msg_decrypt_no_pw(
    msg_ptr: *const message,
    skeys_ptr: *const *const signed_secret_key,
    skeys_len: libc::size_t,
    pkeys_ptr: *const *const signed_public_key,
    pkeys_len: libc::size_t,
) -> *mut message_decrypt_result {
    let msg = &*msg_ptr;
    let skeys_raw = from_raw_parts(skeys_ptr, skeys_len);
    let skeys = skeys_raw
        .iter()
        .map(|k| {
            let v: &SignedSecretKey = &**k;
            v
        })
        .collect::<Vec<_>>();

    let pkeys = if pkeys_ptr.is_null() {
        None
    } else {
        Some(from_raw_parts(pkeys_ptr, pkeys_len))
    };

    let (mut decryptor, _) = try_ffi!(
        msg.decrypt(|| "".into(), || "".into(), &skeys[..]),
        "failed to decrypt message"
    );

    // TODO: multiple messages
    let dec_msg = try_ffi!(
        try_ffi!(
            decryptor.next().ok_or_else(|| format_err!("no message")),
            "no message found"
        ),
        "failed to decrypt message"
    );

    let (valid_ids_ptr, valid_ids_len) = if let Some(pkeys) = pkeys {
        let mut valid_ids = pkeys
            .iter()
            .filter_map(|pkey| match dec_msg.verify(&(**pkey).primary_key) {
                Ok(_) => Some(
                    CString::new(hex::encode(&(&**pkey).key_id()))
                        .expect("failed to allocate")
                        .into_raw(),
                ),
                Err(_) => None,
            })
            .collect::<Vec<_>>();

        valid_ids.shrink_to_fit();
        let res = (valid_ids.as_mut_ptr(), valid_ids.len());
        std::mem::forget(valid_ids);
        res
    } else {
        (std::ptr::null_mut(), 0)
    };

    Box::into_raw(Box::new(message_decrypt_result {
        message_ptr: Box::into_raw(Box::new(dec_msg)),
        valid_ids_ptr,
        valid_ids_len,
    }))
}

#[repr(C)]
pub struct message_decrypt_result {
    pub message_ptr: *mut message,
    pub valid_ids_ptr: *mut *mut c_char,
    pub valid_ids_len: libc::size_t,
}

#[no_mangle]
pub unsafe extern "C" fn rpgp_message_decrypt_result_drop(res_ptr: *mut message_decrypt_result) {
    let res = &*res_ptr;
    let _msg = &*res.message_ptr;
    let _ids = Vec::from_raw_parts(res.valid_ids_ptr, res.valid_ids_len, res.valid_ids_len);
    // Drop
}

/// Returns the underlying data of the given message.
/// Fails when the message is encrypted. Decompresses compressed messages.
#[no_mangle]
pub unsafe extern "C" fn rpgp_msg_to_bytes(msg_ptr: *const message) -> *mut cvec {
    let msg = &*msg_ptr;

    let result = try_ffi!(msg.get_content(), "failed to extract content");
    match result {
        Some(data) => Box::into_raw(Box::new(data.into())),
        None => {
            update_last_error(format_err!("called on encrypted message").into());
            std::ptr::null_mut()
        }
    }
}

/// Free a message, that was created by rpgp.
#[no_mangle]
pub unsafe extern "C" fn rpgp_msg_drop(msg: *mut message) {
    let _ = &*msg;
    // Drop
}

/// Get the number of fingerprints of a given encrypted message.
#[no_mangle]
pub unsafe extern "C" fn rpgp_msg_recipients_len(msg_ptr: *mut message) -> u32 {
    let msg = &*msg_ptr;

    let list = msg.get_recipients();

    list.len() as u32
}

/// Get the fingerprint of a given encrypted message, by index, in hexformat.
#[no_mangle]
pub unsafe extern "C" fn rpgp_msg_recipients_get(msg_ptr: *mut message, i: u32) -> *mut c_char {
    let msg = &*msg_ptr;

    let list = msg.get_recipients();
    if (i as usize) < list.len() {
        CString::new(hex::encode(&list[i as usize]))
            .expect("allocation failure")
            .into_raw()
    } else {
        std::ptr::null_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use pgp::composed::Deserializable;

    #[test]
    fn test_cvec() {
        for i in 0..100 {
            let a = vec![i as u8; i * 10];
            let b: cvec = a.clone().into();
            let c: Vec<u8> = b.into();
            assert_eq!(a, c);
        }
    }

    #[test]
    fn test_fingerprint() {
        let user_id = CStr::from_bytes_with_nul(b"<hello@world.com>\0").unwrap();

        unsafe {
            // Create the actual key
            let skey = rpgp_create_x25519_skey(user_id.as_ptr());

            // Serialize secret key into bytes
            let skey_bytes = rpgp_skey_to_bytes(skey);

            let key = rpgp_key_from_bytes(rpgp_cvec_data(skey_bytes), rpgp_cvec_len(skey_bytes));
            assert!(rpgp_key_is_secret(key));

            let fingerprint1 = rpgp_key_fingerprint(key);

            // get fingerprint directly
            let mut fingerprint2: cvec = (&*skey).fingerprint().into();

            assert_eq!(*fingerprint1, fingerprint2);

            // cleanup
            rpgp_cvec_drop(skey_bytes);
            rpgp_cvec_drop(fingerprint1);
            rpgp_cvec_drop(&mut fingerprint2);
        }
    }

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
                from_raw_parts(rpgp_cvec_data(skey_bytes), rpgp_cvec_len(skey_bytes));
            let skey_back =
                SignedSecretKey::from_bytes(skey_bytes_vec).expect("invalid secret key");
            assert_eq!(&*skey, &skey_back);

            let pkey_bytes_vec =
                from_raw_parts(rpgp_cvec_data(pkey_bytes), rpgp_cvec_len(pkey_bytes));
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

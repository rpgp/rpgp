use std::ffi::CString;
use std::io::Cursor;
use std::slice;

use libc::c_char;
use pgp::composed::{from_armor_many, from_bytes_many, PublicOrSecret};
use pgp::types::KeyTrait;

use crate::cvec::cvec;

pub type public_or_secret_key = PublicOrSecret;

/// Creates an in-memory representation of a PGP key, based on the armor file given.
/// The returned pointer should be stored, and reused when calling methods "on" this key.
/// When done with it [rpgp_key_drop] should be called, to free the memory.
#[no_mangle]
pub unsafe extern "C" fn rpgp_key_from_armor(
    raw: *const u8,
    len: libc::size_t,
) -> *mut public_or_secret_key {
    assert!(!raw.is_null());
    assert!(len > 0);

    let bytes = slice::from_raw_parts(raw, len);
    let (mut keys, _headers) = try_ffi!(from_armor_many(Cursor::new(bytes)), "failed to parse");

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
    assert!(!raw.is_null());
    assert!(len > 0);

    let bytes = slice::from_raw_parts(raw, len);
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
pub unsafe extern "C" fn rpgp_key_id(key_ptr: *mut public_or_secret_key) -> *mut c_char {
    assert!(!key_ptr.is_null());

    let key = &*key_ptr;
    let id = try_ffi!(
        CString::new(hex::encode(&key.key_id())),
        "failed to allocate string"
    );

    id.into_raw()
}

/// Returns the Fingerprint for the passed in key. The caller is responsible to call [rpgp_cvec_drop] with the returned memory, to free it.
#[no_mangle]
pub unsafe extern "C" fn rpgp_key_fingerprint(key_ptr: *mut public_or_secret_key) -> *mut cvec {
    assert!(!key_ptr.is_null());

    let key = &*key_ptr;
    let fingerprint = key.fingerprint();

    Box::into_raw(Box::new(fingerprint.into()))
}

/// Returns `true` if this key is a public key, false otherwise.
#[no_mangle]
pub unsafe extern "C" fn rpgp_key_is_public(key_ptr: *mut public_or_secret_key) -> bool {
    assert!(!key_ptr.is_null());

    (&*key_ptr).is_public()
}

/// Returns `true` if this key is a secret key, false otherwise.
#[no_mangle]
pub unsafe extern "C" fn rpgp_key_is_secret(key_ptr: *mut public_or_secret_key) -> bool {
    assert!(!key_ptr.is_null());

    (&*key_ptr).is_secret()
}

/// Frees the memory of the passed in key, making the pointer invalid after this method was called.
#[no_mangle]
pub unsafe extern "C" fn rpgp_key_drop(key_ptr: *mut public_or_secret_key) {
    assert!(!key_ptr.is_null());

    let _key = &*key_ptr;
    // Drop
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    use crate::{
        rpgp_create_x25519_skey, rpgp_cvec_data, rpgp_cvec_drop, rpgp_cvec_len, rpgp_skey_to_bytes,
    };

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
}

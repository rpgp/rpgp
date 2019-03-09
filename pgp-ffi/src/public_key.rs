use std::ffi::CString;
use std::io::Cursor;
use std::slice;

use crate::cvec::cvec;
use libc::c_char;
use pgp::composed::{Deserializable, SignedPublicKey};
use pgp::ser::Serialize;
use pgp::types::KeyTrait;

pub type signed_public_key = SignedPublicKey;

/// Parse a serialized public key, into the native rPGP memory representation.
#[no_mangle]
pub unsafe extern "C" fn rpgp_pkey_from_bytes(
    raw: *const u8,
    len: libc::size_t,
) -> *mut signed_public_key {
    assert!(!raw.is_null());
    assert!(len > 0);

    let bytes = slice::from_raw_parts(raw, len);
    let key = try_ffi!(
        SignedPublicKey::from_bytes(Cursor::new(bytes)),
        "invalid public key"
    );

    try_ffi!(key.verify(), "failed to verify key");

    Box::into_raw(Box::new(key))
}

/// Serialize the [signed_public_key] to bytes.
#[no_mangle]
pub unsafe extern "C" fn rpgp_pkey_to_bytes(pkey_ptr: *mut signed_public_key) -> *mut cvec {
    assert!(!pkey_ptr.is_null());

    let pkey = &*pkey_ptr;

    let mut res = Vec::new();
    try_ffi!(pkey.to_writer(&mut res), "failed to serialize key");

    Box::into_raw(Box::new(res.into()))
}

/// Get the key id of the given [signed_public_key].
#[no_mangle]
pub unsafe extern "C" fn rpgp_pkey_key_id(pkey_ptr: *mut signed_public_key) -> *mut c_char {
    assert!(!pkey_ptr.is_null());

    let pkey = &*pkey_ptr;
    let id = try_ffi!(
        CString::new(hex::encode(&pkey.key_id())),
        "failed to allocate string"
    );

    id.into_raw()
}

/// Free the given [signed_public_key].
#[no_mangle]
pub unsafe extern "C" fn rpgp_pkey_drop(pkey_ptr: *mut signed_public_key) {
    assert!(!pkey_ptr.is_null());

    let _pkey = &*pkey_ptr;
    // Drop
}

extern crate hex;
extern crate libc;
extern crate pgp;

use std::ffi::CString;
use std::io::Cursor;
use std::mem::transmute;
use std::os::raw::c_char;
use std::slice::from_raw_parts;

use pgp::composed::{from_armor_many, PublicOrSecret};
use pgp::types::KeyTrait;

/// Creates an in-memory representation of a PGP key, based on the armor file given.
/// The returned pointer should be stored, and reused when calling methods "on" this key.
/// When done with it [rpgp_key_drop] should be called, to free the memory.
#[no_mangle]
pub extern "C" fn key_from_armor(raw: *const u8, len: libc::size_t) -> *mut PublicOrSecret {
    let bytes = unsafe { from_raw_parts(raw, len) };
    let mut keys = from_armor_many(Cursor::new(bytes)).expect("failed to parse");

    let key = keys.nth(0).unwrap().expect("failed to parse key");

    let _key = unsafe { transmute(Box::new(key)) };
    _key
}

/// Returns the KeyID for the passed in key. The caller is responsible to call [free_string] with the returned memory, to free it.
#[no_mangle]
pub extern "C" fn key_id(ptr: *mut PublicOrSecret) -> *mut c_char {
    let key = unsafe { &mut *ptr };
    let id = CString::new(hex::encode(key.key_id().unwrap())).unwrap();

    id.into_raw()
}

/// Frees the memory of the passed in key, making the pointer invalid after this method was called.
#[no_mangle]
pub extern "C" fn key_drop(ptr: *mut PublicOrSecret) {
    let key: Box<PublicOrSecret> = unsafe { transmute(ptr) };
    // Drop
}

/// Free string, that was created by rpgp.
#[no_mangle]
pub extern "C" fn free_string(p: *mut c_char) {
    let _ = unsafe { CString::from_raw(p) };
    // Drop
}

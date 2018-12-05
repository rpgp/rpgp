use std::ffi::CString;
use std::io::Cursor;
use std::mem::transmute;
use std::os::raw::c_char;
use std::slice::from_raw_parts;

use hex;
use libc;

use composed::key::{from_armor_many, PublicOrSecret};
use types::KeyTrait;

/// Creates an in-memory representation of a PGP key, based on the armor file given.
/// The returned pointer should be stored, and reused when calling methods "on" this key.
/// When done with it [rpgp_key_drop] should be called, to free the memory.
#[no_mangle]
pub extern "C" fn rpgp_key_from_armor(raw: *const u8, len: libc::size_t) -> *mut PublicOrSecret {
    let bytes = unsafe { from_raw_parts(raw, len) };
    let mut keys = from_armor_many(Cursor::new(bytes)).expect("failed to parse");

    let key = keys.nth(0).unwrap().expect("failed to parse key");
    println!("got key with id {}", hex::encode(key.key_id().unwrap()));

    let _key = unsafe { transmute(Box::new(key)) };
    _key
}

/// Returns the KeyID for the passed in key. The caller is responsible to `free` the returned
/// memory.
#[no_mangle]
pub extern "C" fn rpgp_key_id(ptr: *mut PublicOrSecret) -> *mut c_char {
    let key = unsafe { &mut *ptr };
    let id = CString::new(hex::encode(key.key_id().unwrap())).unwrap();

    id.into_raw()
}

/// Frees the memory of the passed in key, making the pointer invalid after this method was called.
#[no_mangle]
pub extern "C" fn rpgp_key_drop(ptr: *mut PublicOrSecret) {
    let key: Box<PublicOrSecret> = unsafe { transmute(ptr) };
    // Drop
}

use sha2::{Digest, Sha256};
use std::slice;

use crate::cvec::cvec;

/// Calculate the SHA256 hash of the given bytes.
#[no_mangle]
pub unsafe extern "C" fn rpgp_hash_sha256(
    bytes_ptr: *const u8,
    bytes_len: libc::size_t,
) -> *mut cvec {
    assert!(!bytes_ptr.is_null());
    assert!(bytes_len > 0);

    let bytes = slice::from_raw_parts(bytes_ptr, bytes_len);
    let result = Sha256::digest(bytes);

    Box::into_raw(Box::new(result.to_vec().into()))
}
